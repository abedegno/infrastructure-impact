# Schedule Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make website-health results independent of cadence/storage failures, while retaining honest scheduled-service evidence and actionable failure details.

**Architecture:** Keep the pinned, standard-library public-health checker in `monitor.yaml`. Move cadence and metadata-only storage review into a separate read-only default-branch workflow. Extend the existing operational report additively; do not change collection, publication or recovery behavior.

**Tech Stack:** Python >=3.11 standard library, Bash, GitHub Actions, pytest, existing frozen build/hosted tooling. No new dependency or account.

**Spec:** `docs/superpowers/specs/2026-11-02-schedule-reliability-design.md` — explicitly approved on 2 November 2026.

## Global Constraints

- Preserve the two-hour cadence grace, 36-hour publication age limit, daily collection at 12:43 UTC and health cron `23 */6 * * *`.
- Preserve the original service and cadence anchors, existing history limits, storage budgets and old failed conclusions. Manual runs never become scheduled observations.
- Keep nonzero operational exits for overdue successful-run observations or exceeded storage budgets. Successful website health cannot clear these findings.
- Keep the collector runtime pin deliberate. This change needs no collector upgrade, reparse, package version bump, migration or private-vault access.
- Both monitoring workflows have read-only contents/actions permissions, no key, no private-state download and no automatic deletion. Retain receipts for 30 days.
- Operational-control code must come from reviewed default-branch source, independently of a collector pin that lacks the new diagnostics.
- No external scheduler is provisioned. Record that GitHub scheduling itself cannot provide an independent fallback guarantee.
- Preserve frozen studies/reviews, native custom configuration, collector/deployment-template parity and all public dossier research limits.

## Review Focus

1. A failed Python command piped through `tee` must fail health; a valid receipt must never turn a failed check green. Task 2 executes the real Bash run block.
2. Operations failure must neither affect the health workflow conclusion nor enter successful-health history. Tasks 1–2 pin queried workflow IDs and physical separation.
3. Missing, malformed or truncated evidence must not become a successful observation or completed clean review. Tasks 1–2 cover absent receipts, null observations, truncation and failures.
4. Simultaneous cadence and storage failures must all survive the CLI exit and retained receipts. Tasks 1–2 cover multiple diagnostics and always-run steps.
5. Rollout must work while `IMPACT_SOURCE_COMMIT` remains the existing 0.7.0 SHA. Tasks 2–3 test checkout boundaries and verify activation without moving anchors/pins.

## Working context and file map

Use the existing isolated `reliability/monitor-separation` worktree. The current design-only base is `03cb9a6`; record actual task bases during execution. Read the approved spec and existing tests before implementation. Changes belong in `checks/operations_report.py`, `.github/workflows/monitor.yaml`, new `.github/workflows/operations.yaml`, the reliability tests and three operational guides. No product UI change is required.

Keep test run histories synthetic. Test-only subprocess fixtures may supply a fake `gh` executable and a fixed module clock; do not request real GitHub data in automated tests. Existing network-backed public-health tests already exercise the actual checker; supplement them with workflow shell-boundary tests rather than duplicating its implementation.

### Task 1: Add structured operational failures and actionable CLI output

**Files:** Modify `checks/operations_report.py`, `tests/test_reliability_review.py`.

**Interfaces:** Preserve `schedule_observation(...)`, `summarize(...)` and CLI arguments. Add `operational_failures(report: dict) -> list[dict]`; `summarize` includes its output as additive `operational_failures`. Allow `main(argv: list[str] | None = None) -> None` for direct CLI tests; default invocation remains compatible.

- [ ] Write `test_operational_failures_identify_each_overdue_workflow`. At fixed `2026-11-02T17:00:00+00:00`, use original anchors and only manual successes. Assert ordered codes `collection_schedule_overdue`, `monitor_schedule_overdue`; workflow IDs `collect.yaml`, `monitor.yaml`; expected times 12:43/12:23, deadlines 14:43/14:23, latest successful scheduled creation times null. Each row contains `code`, `workflow`, `expected_trigger_at`, `latest_successful_scheduled_run_created_at`, `grace_deadline_at`, `message`; never attribute a run to an original slot.

```python
report = summarize([], [], datetime(2026, 11, 2, 17, tzinfo=timezone.utc),
                   observation_start=START.isoformat(),
                   public_health={"status": "fresh", "source_failures": 0})
assert report["public_health"]["status"] == "fresh"
assert [f["code"] for f in report["operational_failures"]] == [
    "collection_schedule_overdue", "monitor_schedule_overdue"]
assert report["operational_failures"][0]["grace_deadline_at"] == "2026-11-02T14:43:00+00:00"
```
- [ ] Write `test_operational_failures_retain_storage_with_cadence`: repository size 524288 KiB retains both cadence rows plus `repository_storage_budget_exceeded`. Its workflow/cadence fields are null; its message states the measured size and 524288 KiB budget. Preserve the existing inclusive storage failure boundary and do not alter other existing findings.
- [ ] Parameterize no-due-trigger, within-grace and current scheduled-success cases: no overdue failure rows. Null repository size stays unknown and adds no storage failure. Existing future/pre-anchor/manual exclusions, old failures and truncated-history behavior stay covered; add an assertion that truncation cannot produce `review_without_detected_operational_findings` or completed review.
- [ ] Add actual CLI subprocess cases using synthetic `gh` responses and a fixed clock. With fresh health but overdue cadence, assert exit nonzero, both workflow IDs/codes/deadlines in stderr, complete JSON/summary written before exit. Add simultaneous storage failure and no-operational-failure cases. Assert only `collect.yaml` and `monitor.yaml` histories are queried; `operations.yaml` never supplies successful health history.
- [ ] Run `uv run --frozen pytest -q tests/test_reliability_review.py`; expected RED because structured failures/diagnostics are absent. Record the exact failure before implementation.
- [ ] Implement the additive helper/report field and reuse those rows for CLI errors. Return deterministic order: collection, monitor, storage. Preserve all existing report fields, statuses, thresholds and historical counts; use the original cadence objects to calculate deadlines. Write report/summary first, print concise JSON, then exit nonzero with every failure code/message. Keep existing successful command behavior.
- [ ] Run `uv run --frozen pytest -q tests/test_reliability_review.py tests/test_release_sources.py`; expected PASS, including old consumers. Run the full suite and commit `Explain operational failures without weakening cadence checks`.

### Task 2: Separate public-health and operations workflows

**Files:** Modify `.github/workflows/monitor.yaml`, `tests/test_reliability_review.py`; create `.github/workflows/operations.yaml`. Modify `.github/workflows/ci.yaml` only if a new test file is chosen and must enter its explicit Ruff lists.

**Interfaces:** Consume Task 1's unchanged CLI flags and additive diagnostics. `monitor.yaml` continues checking the pinned runtime; `operations.yaml` checks out `${{ github.sha }}` from its own trusted schedule/manual event and uses current standalone checks. It has no pull-request or workflow-run trigger.

- [ ] Add a test-only reader for named YAML step run blocks (or use an already available parser without introducing dependencies). Execute the actual health run block with Bash and a stand-in upstream command returning 13: assert exit 13 despite `tee`. The current block must fail this test. Also execute its success case and verify the receipt file.

```python
# health_run_block is the extracted real YAML run string; upstream_failure_env
# supplies RUNNER_TEMP/PUBLIC_URL and a PATH containing the exit-13 stand-in.
result = subprocess.run(["bash", "-c", health_run_block],
                        env=upstream_failure_env, capture_output=True, text=True)
assert result.returncode == 13
```
- [ ] Add workflow-boundary tests: health keeps `23 */6 * * *`, dispatch, pinned checkout and no operations/storage command. Operations has `name: Service operations`, dispatch, cron `53 */6 * * *`, default-branch event checkout and only contents/actions read permissions. No secrets, write permission, collector dispatch or private-state command appears in either workflow. The new minute is an implementation choice, not a trigger-delivery guarantee.
- [ ] Execute health summary/receipt handling with valid, absent and malformed report files plus success/failure outcomes. Assert an explicit failed/unavailable summary on failure; do not synthesize `status: fresh`. Run the operational sequence with synthetic fresh health and overdue schedule histories: public health remains successful while the independent operations command fails. Also prove an actual upstream health failure is still nonzero.
- [ ] Pin the operations report, backup/storage and artifact steps to `if: always()` where needed. Verify the retained operations artifact includes `operations.json`, `backup-storage.json` and that run's public-health receipt even after a check fails. A missing upstream result must remain unavailable, rather than a fabricated observation. Keep `if-no-files-found: warn` and retention 30 days.
- [ ] Run the new workflow tests; expected RED because separation, shell propagation and receipt summaries are missing.
- [ ] Update `monitor.yaml`: keep its existing five-minute timeout, pinned checkout, action SHAs and public-health command. Explicitly enable Bash `set -euo pipefail` before the pipeline. Remove operations/storage execution. Add an always-run small inline Python summary and retained `public-health-RUN_ID` artifact; use the check step's actual outcome, tolerate missing/invalid JSON, and preserve failure status. Keep the checker compatible with the existing 0.7.0 source pin; introduce no helper absent from that pin.
- [ ] Create `operations.yaml`: same reviewed checkout/upload action SHAs, five-minute timeout, `persist-credentials: false`, read-only permissions. Check out `${{ github.sha }}`. Obtain a bounded public-health receipt using the existing checker and strict pipeline; run Task 1's CLI with the existing service/cadence variables and then the existing metadata-only storage command/profile. Retain `reliability-review-RUN_ID` receipts even when preceding checks fail. A fresh operations health receipt never supplies a scheduled monitor observation.
- [ ] Run `uv run --frozen pytest -q tests/test_reliability_review.py tests/test_hosted_backup.py tests/test_release_sources.py`; expected PASS. Run full suite and exact CI lint/format commands. Confirm `git diff --exit-code -- .github/workflows/collect.yaml deploy/github-public-service.yaml`. Commit `Separate website health from cadence and storage review`.

### Task 3: Document, verify and roll out the operational separation

**Files:** Modify `docs/SCHEDULE_RELIABILITY.md`, `docs/OPERATIONS.md`, `docs/HOSTED_SERVICE.md`; extend tests only for concrete rollout gaps discovered during verification.

**Interfaces:** Consume Task 2's two workflow names, artifact paths and source boundaries. No new runtime API, schema migration or external scheduler is introduced.

- [ ] Document the independent outcomes, exact schedules, stable failure codes, retained receipts and preserved observation anchors. Keep dated historical accounts; append the actual activation date rather than rewriting old failed conclusions. Explain that the existing 0.7.0 collector pin remains valid and that the operations workflow uses its reviewed event commit. Manual runs verify behavior, not scheduled cadence or continuous uptime.
- [ ] Document fallback assessment: GitHub-triggered redundancy is not independent. Give a manual check/dispatch/recheck procedure that preserves encryption, runtime pin and prior generation; do not auto-dispatch or claim it repairs scheduling. An independent watchdog needs an agreed host/account and scoped credential custody; provision none. Keep research expansion as a subsequent source-led proposal with frozen original studies and no unsupported rates/intent conclusions.
- [ ] Run the full suite; expected all passing. Run exact CI Ruff/format and `npm run format:check`; expected clean. Run `checks/release.py` to a new public source export, repeat frozen tests/build in that export, build the declared-version wheel and run isolated `checks/distribution.py --offline` or its normal cached equivalent. Expected: privacy/fixture checks and installed/external-plugin probes pass; only the existing Git-checkout-only test may skip in the export. No version bump is required because packaged product behavior is unchanged.
- [ ] Inspect the complete diff for private material, changed frozen resources, altered anchors/pins/budgets and collector-template changes. Commit documentation, push the candidate, and require exact-head Python 3.11, Python 3.13 and container CI plus a fresh whole-branch review. Fix real findings under the execution skill before integration.
- [ ] Submit a concrete PR. Following approved integration, dispatch `monitor.yaml` and `operations.yaml` independently from main; do not dispatch collection or change `IMPACT_SOURCE_COMMIT`. Inspect each check and its retained receipts. Expected: a healthy live website can pass health while operations correctly remains red for overdue schedule observations; do not require a green cadence result as the rollout criterion. Website/storage/network failures must be reported honestly if present.
- [ ] Record actual merge/deployment identity, both run IDs/results and unchanged protected settings outside public source. Leave scheduled reliability unresolved until later real schedule events provide evidence. Retain previous source/runtime for rollback; no history rewriting, recovery download or deletion. If GitHub-only infrastructure cannot guarantee delivery, state that limit plainly.

## Self-review and execution handoff

Task 1 owns diagnostic/report compatibility; Task 2 owns failure propagation, physical independence, receipt retention and pin-safe deployment; Task 3 owns documentation, distribution, independent live checks and fallback assessment. Each Review Focus item has explicit coverage above. Research-pilot expansion is the next separately scoped proposal after this operational work, not an unreviewed definition change in this branch.

Preserve the previously chosen **Subagent-driven** execution method: fresh implementer and reviewer per task, followed by whole-branch review. The tasks share the report and workflow interfaces, so pass these exact contracts between them. The approved written design is now recorded; this implementation plan still requires the maintainer's review before code changes.
