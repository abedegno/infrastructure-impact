# Bounded Exact-target Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the approved 174-document Cisco/Aruba import as an inventory-bound, isolated staging operation with separately controlled hosted activation.

**Architecture:** A closed installed manifest supplies exact document identities, hashes and request budgets. A read-only preview binds the selected vault; staging fetches and validates all targets in an isolated copy, then audits/builds/checks the complete candidate. The hosted wrapper backs up only a successfully validated staged vault, preserving ordinary collection and the existing Arista path.

**Tech Stack:** Existing Python 3.11+, SQLite, jsonschema, locked Hatch build, stdlib HTTP tooling, existing JavaScript/Node parity tests and GitHub Actions. No new runtime dependency or storage migration.

**Spec:** [Approved design](../specs/2026-11-07-exact-target-import-design.md), approved by the maintainer on 7 November 2026. Implementation starts only after review of this plan. Preserve the maintainer's subagent-driven execution choice. The observation and design are in PR #37; do not merge, release, activate or dispatch hosted work as part of plan preparation.

## Global Constraints

- Profile `campus-switching-public-gap-2026-11-07-v1`: exactly 174 targets, 174 unique vendor/advisory identities and fetch URLs; 173 Cisco CSAF documents and one Aruba text bulletin.
- Pin exact source SHA-256, vendor advisory ID and exact CVE set. Original discovery URLs are provenance, not fetch fallbacks or inferred aliases.
- At most 3,000,000 bytes per document, 40,000,000 distinct input bytes including cached responses, 80,000,000 received body bytes including retries/error/partial responses, two attempts per target and 348 HTTP attempts total. Refuse all redirects for this profile.
- Preserve the ordinary transport defaults, including its 25-second timeout and retry classification. Requests are sequential with at least one-second spacing; the hosted 40-minute timeout is an independent bound, not a promise of a strict local deadline.
- Preview/final receipts are at most 2,000,000 serialized bytes; no silent truncation. Preview performs no HTTP, migration, writer lock or source-vault write.
- Advisory schema v2, raw evidence, revision IDs/history, existing exclusions, frozen definitions, pending human review and unrelated source errors remain intact. No inferred model/version applicability, comparative security/patch ranking or concealment finding.
- Product source configuration, source pin, schedules, permissions, secrets, recovery backend and all capacity/delivery/monitor limits remain unchanged.
- Failed staging must not promote its database into accepted recovery. The approximately 141 MB simple union warning is not a measured complete candidate; a failed capacity result remains a failed result.
- Operator captures, databases, raw receipts and machine-specific paths stay outside Git/public output. Commit only factual manifest metadata and authored synthetic tests.
- No hosted recovery access, preview/apply, activation or new advisory acquisition is authorized by implementing this plan. Use test-owned keys and offline retained public evidence only for local acceptance.

## Review Focus

1. A custom database path paired with the wrong collector home must not acquire an unrelated lock and appear protected (Task 3).
2. A late second-attempt body or partial error response must consume the same budget as the first response, including cached-content bounds (Task 2).
3. Root-level ambient source settings and modules imported before staging must not route reports/publications into the input or native vault (Tasks 4–5).
4. Failed capacity/build or failed authenticated backup must not replace the recovery pointer or make scheduled collection see the rejected enlarged vault (Tasks 5–6).
5. The installed wheel must carry the closed manifest and the same standalone monitor dependencies as the source checkout, without assuming `checks` or Node is installed (Tasks 5, 7).

## File and interface map

Paths below are repository-relative; keep new modules focused rather than expanding the Arista engine.

| Unit             | Files and responsibility                                                                                                                                                                                                                                                          |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Closed manifest  | New `infrastructure_impact/collection/target_import_profiles.py`, `infrastructure_impact/resources/target-imports/campus-switching-public-gap-2026-11-07-v1.json`, `infrastructure_impact/schemas/target-import-manifest-v1.json`; validate installed factual entries and limits. |
| Transport budget | New `infrastructure_impact/collection/transport_budget.py`; optional restrictions in existing `collection/transport.py`.                                                                                                                                                          |
| Preview/receipts | New `infrastructure_impact/application/target_import.py`, `application/target_import_contracts.py`, `schemas/target-import-preview-v1.json`, `schemas/target-import-result-v1.json`; bounded contracts and stable-copy inventory binding.                                         |
| Staging          | New `infrastructure_impact/application/target_import_stage.py`; explicit stage filesystem ownership, preflight and ingest. Modify `storage/locking.py` and `cli.py` minimally.                                                                                                    |
| Candidate gate   | New `infrastructure_impact/application/import_candidate.py`; full build, existing monitor, capacity and semantic/CSV checks. Add wheel force-includes in `pyproject.toml` for the existing standalone monitor pair, not a fork of their source.                                   |
| Hosted selection | New `infrastructure_impact/collection/maintenance_operations.py`, `ops/target_import_job.py`; minimal explicit dispatch changes in `ops/hosted_job.py`. No workflow permission, scheduling or input changes.                                                                      |
| Acceptance       | New focused test modules named in tasks; extend existing distribution/package probes, CI lint list and operational docs. Keep operational real-data artifacts outside Git.                                                                                                        |

### Shared interface decisions

- `TargetImportProfile` is a frozen value with `profile_id`, `version`, ordered immutable `targets`, the exact limits above and canonical manifest `fingerprint`. Each `TargetImportTarget` has `vendor`, `advisory_id`, `fetch_url`, `discovery_url`, `source_sha256`, `cve_ids` and historical source observation metadata. Lookup `target_import_profiles.profile(profile_id: str) -> TargetImportProfile` accepts installed IDs only.
- `target_import.preview(database: Path, profile_id: str) -> dict` returns the distinct preview format, logical inventory binding, manifest fingerprint, both normalizer fingerprints, target facts and observation time. `target_import_contracts.load_preview(path: Path, profile: TargetImportProfile) -> dict`, `preview_bytes(value: dict) -> bytes` and `result_bytes(value: dict) -> bytes` are the strict 2 MB boundaries.
- `target_import_stage.stage(database: Path, profile: TargetImportProfile, expected_fingerprint: str, output: Path, *, lock_home: Path) -> dict` owns one shared lock and writes only a new isolated output. Return paths are **relative** `private/data/intel.sqlite3` and `public/` plus a bounded result; private paths never appear in public output. Failed results never identify an accepted staged vault.
- `import_candidate.verify(database: Path, public: Path, profile: TargetImportProfile) -> dict` enforces complete-candidate validation and returns sanitized measurements/check outcomes. It never backs up, promotes or publishes.
- `maintenance_operations.resolve_profile(profile_id: str) -> tuple[str, object]` returns kind `arista-refresh` with the unchanged `MaintenanceProfile`, or `target-import` with `TargetImportProfile`. Unknown IDs preserve the hosted `unknown_maintenance_profile` failure before key/recovery access.
- `ops.target_import_job.apply(args, selected, state, output, home, database, key, store, limit) -> None` is the hosted wrapper. It emits existing `apply` mode/effects only in the approved order. Local stage has no workflow effects.

## Task 1: Closed manifest and strict operation contracts

**Files:** Create the manifest/profile and contract/schema modules above; create `tests/test_target_import_profiles.py` and `tests/test_target_import_contracts.py`.

**Consumes:** Installed vendor registry, canonical identity primitives, the approved 174-target operator proposal.
**Produces:** `TargetImportTarget`, `TargetImportProfile`, closed `profile()` lookup and strict preview/result serializers used by later tasks.

- [ ] **Step 1 — RED:** Add authored two-vendor fixtures and tests for ordered canonical fingerprint stability, duplicate fetch URL or vendor/ID, unknown vendor/profile, invalid HTTPS route/hash/CVE, credentialed/foreign URLs, extra keys, Boolean limits, empty sets and unexpected profile target count. Assert the real installed profile has exactly 174 targets, vendor counts `{'cisco': 173, 'aruba': 1}` and the exact design limits. Test missing/extra receipt fields, non-finite values, wrong format and `2_000_001` serialized bytes fail rather than truncate.
- [ ] **Step 2 — Verify RED:** Run `.venv/bin/python -m pytest -q tests/test_target_import_profiles.py tests/test_target_import_contracts.py`; expect missing-module/interface failures before implementation.
- [ ] **Step 3 — Implement:** Populate installed factual metadata from the outside-Git `proposal.json` whose SHA is in the approved observation. Cross-check every entry against the retained successful receipt/capture and retain the original discovery/resolved distinction. Do not commit raw vendor content or local IDs. Implement the shared interfaces and closed schemas; finite canonical UTF-8 serialization, deterministic ordering and fresh isolated return values.
- [ ] **Step 4 — Verify GREEN:** Run the two modules plus `tests/test_targeted_maintenance.py`; old Arista profile metadata/fingerprint and existing manifest resources must remain unchanged. Record the new canonical manifest fingerprint outside Git.
- [ ] **Step 5 — Commit/review:** `feat: add closed Cisco and Aruba import manifest`; fresh task reviewer verifies the metadata source, exact scope and receipt bounds before Task 2.

## Task 2: Per-operation transport limits without changing ordinary collection

**Files:** Create `collection/transport_budget.py`, `tests/test_target_import_transport.py`; modify `collection/transport.py` only for optional restrictions.

**Consumes:** Task 1 limits.
**Produces:** `TransportBudget(max_attempts: int, max_received_bytes: int)` with `start_attempt() -> None`, `consume_received(size: int) -> None`, read-only `attempts`/`received_bytes`; add optional `budget=None` and `forbid_redirects=False` keyword arguments to `transport.fetch()`. Omitted arguments preserve existing behavior.

- [ ] **Step 1 — RED:** Use mocked openers/readers to assert a refused redirect performs no second request even to itself/another target; attempts cap includes retries and 304; size `3_000_001` fails; input aggregate includes cached documents; received-body budget includes non-200 bounded error bodies and readable partial-body exception data. Test exact boundary success and retry exhaustion without off-by-one requests. Regression tests must preserve ordinary redirect/retry/15 MB defaults.
- [ ] **Step 2 — Verify RED:** Run `.venv/bin/python -m pytest -q tests/test_target_import_transport.py`; expected failure is unsupported restriction arguments/missing budget implementation.
- [ ] **Step 3 — Implement:** Account before each actual open and while bounded chunk reads occur, including error paths; callers cannot reset the shared invocation budget between URLs. If a failed read exposes no partial bytes, conservatively charge its requested bounded chunk so unknown partial delivery cannot evade the budget. Cache reuse still verifies per-document length. Refuse redirects in the handler before they can dispatch. Keep normal retry classifications, timeout and access-response screening unchanged; do not globally forbid redirects.
- [ ] **Step 4 — Verify GREEN:** Run new transport tests plus `tests/test_targeted_maintenance.py tests/test_source_access.py tests/test_source_selection.py tests/test_archive.py`. The stage layer, not the generic transport, owns the distinct-input 40 MB accounting and sequential one-second request spacing.
- [ ] **Step 5 — Commit/review:** `feat: bound exact import HTTP attempts and response bodies`; review failure accounting and ordinary compatibility before core staging uses it.

## Task 3: Read-only inventory preview and explicit lock ownership

**Files:** Implement `application/target_import.py`; minimally extend `storage/locking.py`, early CLI dispatch in `cli.py`; create `tests/test_target_import_preview.py` and `tests/test_target_import_cli.py`.

**Consumes:** Task 1 contracts/profile and existing stable-copy/canonical identity patterns.
**Produces:** `preview()`, `target_import.binding(db, profile) -> dict` and `target_import.validate_lock_scope(home: Path, database: Path) -> None`. Add `writer_lock(*, home: Path | None = None)` with unchanged default; explicit home is used only by the new local stage.

- [ ] **Step 1 — RED:** Assert preview does not open source SQLite, migrate, lock, create sidecars or make HTTP; reject nonempty WAL/journal, concurrent copy changes, symlink/overlap/existing outputs, oversized/malformed preview and unknown profile before filesystem/DB startup. Mutate each bound class independently—other-vendor latest payload/revision, target selection, target observation/cache, normalizer or manifest—and assert the fingerprint changes, but observation-time-only changes do not. Unrelated secrets/raw text may not enter receipt bytes.
- [ ] **Step 2 — Verify RED:** Run `.venv/bin/python -m pytest -q tests/test_target_import_preview.py tests/test_target_import_cli.py` and verify the new command/binding tests fail for the absent implementation.
- [ ] **Step 3 — Implement:** The preview uses one stat/journal-checked streaming copy and opens only the copy read-only, without cloning raw evidence into its receipt. Incrementally hash ordered latest logical records and relevant selection/observation/cache facts. Bind installed source configuration SHA as an additional build-input identity. CLI dispatch must happen before ambient initialization. Validate `--home` against the canonical `home/data/intel.sqlite3` path; a custom path is accepted only when explicitly set `IMPACT_HOME` and `IMPACT_DATABASE` resolve to the same supplied pair, otherwise reject as ambiguous. Never read root configuration to infer ownership.
- [ ] **Step 4 — Verify GREEN:** Run new tests plus `tests/test_targeted_maintenance.py tests/test_normalization_maintenance.py`; test the custom-path accepted pair and rejected mismatched pair, real lock contention with collection, and that preview never invokes the lock helper. Only preview is runnable until the stage task connects the second CLI mode.
- [ ] **Step 5 — Commit/review:** `feat: preview exact imports against a stable vault inventory`; review fingerprint coverage, source preservation and early dispatch.

## Task 4: Isolated all-target preflight and ingestion

**Files:** Create `application/target_import_stage.py` and `tests/test_target_import_stage.py`; finish the `target-import stage` CLI in `cli.py`.

**Consumes:** Tasks 1–3 interfaces; `transport.fetch`, registry normalization, `validate_advisory`, existing `ingest`, audit/report/publication functions via the next task's candidate verifier.
**Produces:** `stage()` shared interface. Before Task 5 lands, its integration test injects a candidate-check callable and a passing test-owned candidate; production completion is disabled until the real verifier is connected.

- [ ] **Step 1 — RED:** Test a two-vendor batch with one late bad SHA/CVE/identity/layout: zero normalized imports and no input-vault mutation; any retained capture/failure is inside the isolated stage only. Assert all-target validation before normalized insertion, every old raw/revision row survives success, identical bytes/code are unchanged, and an actual capture date is not reset by replay. Test an existing target identity under a different selected source/hash: reject it as `existing_identity_conflict`, rather than downgrade/overwrite it. An existing identity can be unchanged or reinterpreted only from the same pinned source/capture and exact CVE scope. Test a source blocked on its second attempt, 40 MB aggregate, minimum request spacing, stale binding before HTTP, storage failure and unexpected duplicate source identity. Root/native path sentinels must remain unread/unwritten.
- [ ] **Step 2 — Verify RED:** Run `.venv/bin/python -m pytest -q tests/test_target_import_stage.py`; confirm absent staging causes failure, not a fixture/server setup error.
- [ ] **Step 3 — Implement:** Validate receipt/paths/lock scope first, hold one explicit-home writer lock, stable-copy the checkpoint and recheck binding. Reject any preexisting target identity with a different source/capture/CVE scope before normalization writes; matching pinned evidence under older code may be reinterpreted with explicit parser provenance. Stage paths are `private/data/intel.sqlite3`, `private/home/` for reports/generations and `public/` for the candidate, with no overlap/input symlinks. Fetch only pinned resolved URLs, using one shared budget, no redirects, exact raw hashes and current normalizers. Preflight all records before `ingest`. Maintain success/unchanged and provenance facts without fabricating counterpart selection, model scope, benchmark acquisition or old-error resolution. Process-private reports/config/environment must resolve under the stage or the installed public resources, never the source home/root.
- [ ] **Step 4 — Verify GREEN:** Run new stage/CLI tests plus maintenance/current-evidence/reconciliation regressions. Ensure success and failure both preserve original file SHA/stat/sidecar state. Return a bounded non-completed result on any failure; no raw body/exception/path leaks. Do not build publications in the parent process: Task 5 supplies a fresh-interpreter worker with explicit stage environment before application imports, preventing module-global roots captured by prior imports from leaking into staging. The next task must test real candidate construction rather than treating the injected test verifier as acceptance.
- [ ] **Step 5 — Commit/review:** `feat: stage exact target imports without mutating the input vault`; reviewer checks the all-target boundary and filesystem/environment isolation.

## Task 5: Complete-candidate audit, capacity and installed-wheel verification

**Files:** Create `application/import_candidate.py`, `tests/test_target_import_candidate.py`; modify `target_import_stage.py`, `pyproject.toml`, `checks/package_probe.py`, `checks/distribution.py` as needed for the shipped monitor pair.

**Consumes:** Task 4 staged DB; existing `storage.audit.audit()`, `application.reporting.report()`, `application.publication.build()`, standalone `checks/public_health.py` and `checks/switching_health.py`, native/export selectors and published fragment schema.
**Produces:** Real `import_candidate.verify()` and the completed stage result. The result includes byte measurements, manifest/generation binding, audit/monitor/parity outcomes and no acceptance fields on failure.

- [ ] **Step 1 — RED:** Authored candidate fixtures exceed compressed 8,000,000 or expanded 128,000,000 bytes, corrupt a manifest/part/schema/CSV, alter an exclusion or source/CVE/version binding, or contain mismatched native/static selection facts; each must fail without any input/recovery promotion. Test stale/unknown KEV and pending review are preserved, never fabricated fresh. Test a wheel lacking either monitor companion fails installed-stage verification explicitly. Import query/report modules with a hostile parent-root sentinel before staging and prove that only explicit child-stage paths are written.
- [ ] **Step 2 — Verify RED:** Run `.venv/bin/python -m pytest -q tests/test_target_import_candidate.py`; confirm the missing gate allows/fails the intended assertions before implementation.
- [ ] **Step 3 — Implement:** Have `verify()` launch the current interpreter on the trusted installed module `infrastructure_impact.application.import_candidate` in internal worker mode. Set the subprocess stage environment before any query/report/publication import; fail if the worker exits without its strict bounded result. Audit/report/build in that process with `IMPACT_SOURCES` set to installed `resources/sources.json`, fixed stage-private report/generation paths and no ordinary worker invocation. Measure files with bounded streaming reads, validate the public manifest and existing size limits, run the unchanged standalone monitor both default and archive verification against a temporary public-only loopback origin, then compare selected native/public facts and regenerated CSV via existing Python selectors with a shared evaluation time. Validate all candidate source identities, old-record/exclusion preservation and switching scope. Actual JavaScript hydration parity is pinned by the Node tests and real-data acceptance, not a new production Node dependency.
- [ ] **Step 4 — Package and verify GREEN:** Hatch wheel force-includes the **existing** `checks/public_health.py` and `checks/switching_health.py` at `infrastructure_impact/_standalone/`; no duplicate maintained monitor source. Load this trusted pair by installed package path, with the known source-checkout paths as the development equivalent; no CWD/operator-supplied executable lookup. Verify shipped bytes equal the source pair. Run new tests plus existing static/switching/current-evidence/KEV delivery and monitor tests. Add authored Node native/static JSON/CSV parity cases using existing harnesses. Run the isolated wheel probe with neither project root, `checks`, Node nor ambient source config on the import path.
- [ ] **Step 5 — Commit/review:** `feat: reject unsafe import candidates before recovery promotion`; reviewer must reject a gate that only measures the compact archive or skips full build/semantic checks.

## Task 6: Hosted dispatch with staged-vault-only promotion

**Files:** Create `collection/maintenance_operations.py`, `ops/target_import_job.py`, `tests/test_hosted_target_import.py`; modify `ops/hosted_job.py` minimally and extend `tests/test_hosted_workflow_protocol.py`.

**Consumes:** Tasks 1–5 plus existing authenticated restore, `backup_verified()` and workflow-effect helpers.
**Produces:** Closed `resolve_profile()` and hosted `apply()` interfaces above; current workflow inputs/permissions/schedule remain byte-identical.

- [ ] **Step 1 — RED:** Use only test-owned encrypted fixtures/keys. Unknown profile or conflicting controls fail before key/recovery access. Preview writes only the distinct receipt at `maintenance-preview.json`, with no HTTP, backup or public output. Failed stale binding/preflight/audit/capacity leaves current recovery pointer/assets unchanged and sets no recovery/publication-ready effect. Verify backup receives the staged DB, not original input, and authenticated readback precedes public readiness. Exercise failed backup, failed public-output copy and simulated downstream push/deploy rejection without promising cross-system rollback.
- [ ] **Step 2 — Verify RED:** Run `.venv/bin/python -m pytest -q tests/test_hosted_target_import.py tests/test_hosted_workflow_protocol.py`; new kind/effect tests should fail before dispatch implementation.
- [ ] **Step 3 — Implement:** Resolve kind before opening keys. Keep existing Arista call paths intact; route new preview to its own strict serializer and new apply to the isolated stage wrapper. Do not reuse Arista's `finally` backup or its unconditional `partial`/one-conflict result. On completed stage, verify vault capacity, then invoke existing verified backup/readback, copy only `public/`, and emit `recovery_ready`/`publish_ready` in the existing order. A later copy failure must be reported accurately even if recovery was already promoted; it cannot be reported as full rollback. Preserve current effects protocol and never implicitly collect feeds/archives/CVE/KEV/benchmarks.
- [ ] **Step 4 — Verify GREEN:** Run new hosted tests plus `tests/test_hosted_maintenance.py tests/test_hosted_backup.py tests/test_hosted_workflow_protocol.py tests/test_capacity_profiles.py`; assert old Arista/ordinary receipts and legacy protocol checks still pass. Assert `.github/workflows/collect.yaml` and `deploy/github-public-service.yaml` schedule/permissions/input sections are unchanged.
- [ ] **Step 5 — Commit/review:** `feat: wrap staged target imports in verified hosted recovery`; focus review on failed-candidate recovery isolation, helper dispatch before keys and readiness ordering.

## Task 7: Distribution, documentation and honest real-data acceptance

**Files:** Add new focused modules to `.github/workflows/ci.yaml` lint/format lists without changing workflow scheduling/permissions; extend `checks/package_probe.py`, operational/releasing docs and a dated `docs/research/` acceptance note. Keep `resources/openapi.json` and advisory schema v2 unchanged: this is an operator CLI, not a new HTTP API.

**Consumes:** All prior tasks; approved public-only source receipts/copies and existing parity harnesses.
**Produces:** Small reviewed commits, distribution proof, complete test receipts and a truthful acceptance/activation handoff.

- [ ] **Step 1 — RED:** Extend package/resource probes to require the installed manifest/schemas and byte-identical standalone pair; assert every production new module is included in clean release export and explicit test lint coverage. Reuse authored fixture-generation policy and privacy checks; no vendor capture or machine path may enter source exports.
- [ ] **Step 2 — Verify RED:** Run focused new probe/coverage assertions before the final packaging/docs changes; expected missing resources or coverage must be observable.
- [ ] **Step 3 — Implement/docs:** Document both local commands, explicit lock-home/custom-path rules, pinned-byte drift handling, stage directories/privacy, failures/CLI exit codes and source retrieval versus offline replay. Explain all existing activation gates and the measured/potential capacity block. Preserve review-pending/partial-history caveats. Define local CLI statuses: preview/stage-completed `0`, failed stage/lock contention `1`, malformed input/parser errors `2`; failed output must not look accepted.
- [ ] **Step 4 — Full verification:** Run focused tests, full `pytest`, both exact CI Ruff commands and existing Node checks; build/inspect clean source and wheel, run isolated distribution/privacy/fixture checks and Python 3.11/3.13 checks. Local HTTP-server tests require permitted loopback binding; distinguish sandbox failures from product failures and rerun only affected tests when appropriate. Do not change dependency locks or versions incidentally.
- [ ] **Step 5 — Offline real-data acceptance:** Verify original public stage/capture hashes; use only a stable disposable copy. Replay the 174 retained captures through current normalizers without forging new successful HTTP observations, then audit/build and measure the resulting laboratory candidate and run source/family/version, existing-record/exclusion and Node native/static CSV/JSON checks. Label this **offline retained evidence**, not a fresh hosted apply. Preserve originals. The available local public stage is not the complete 966-record hosted vault: this lab cannot certify actual hosted union capacity or acceptance. Record that remaining check explicitly; do not reconstruct missing raw histories from snapshot rows or access recovery without approval. If the laboratory candidate fails limits, record exact measurements and stop its promotion; no limit increase or evidence deletion.
- [ ] **Step 6 — Review and commit:** Fresh whole-branch review of implementation/spec coverage and failure semantics. Commit the dated acceptance record and source/docs fixes only; keep every raw operational artifact outside Git. Push a reviewable implementation PR, or update the existing unmerged branch/PR, with its final scope and actual validation results. Do not merge or activate on the strength of this plan's approval.

## Self-review and execution handoff

Spec coverage maps manifest/limits to Tasks 1–2; read-only preview/lock scope to
Task 3; isolated preflight/ingestion to Task 4; full-candidate/capacity and wheel
behavior to Task 5; hosted compatibility/effects to Task 6; operational acceptance
and limitations to Task 7. Each Review Focus condition has explicit owning tests.
Signatures/profile kind/relative paths above are shared interfaces for task
implementers and reviewers. They must not silently diverge.

Capacity is a release blocker, not scope for weakening checks. Passing local
laboratory tests is distinct from validation against an authenticated complete
hosted inventory. Any need for publication restructuring becomes a separate
reviewed design. No task requires new hosted credentials or dispatch.

Please review this plan and confirm it captures the intended implementation.
After approval, use the preserved **subagent-driven** method: one implementer and
fresh task review per completed unit, followed by whole-branch review. Do not
start product code until that plan review returns.
