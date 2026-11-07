# Exact-target Refresh and Current-evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refresh exactly the two reviewed Arista advisories and consistently separate an unsupported retained interpretation from current analytics without deleting history.

**Architecture:** A shared pure partition produces current records, retained exclusions and a generation-bound decision report. A closed maintenance profile uses the existing parser/selection, writer, audit and authenticated recovery paths, with preview-bound application and no ordinary acquisition. Native and static consumers share the published partition; browser code validates decisions rather than inferring them.

**Tech Stack:** Existing Python 3.11+, SQLite, jsonschema, JavaScript/Node test harness, GitHub Actions and locked build/hosted dependencies. No new runtime dependency or migration.

**Spec:** [Approved design](../specs/2026-11-06-targeted-refresh-current-evidence-design.md), approved by the maintainer after PR #33 was opened. Base implementation is merged PR #32 at `a9014f01a697c98103e908a9941a91f62417d890`.

**Execution status:** Implementation, local verification and final review are complete; integration is tracked in [PR #33](https://github.com/abedegno/infrastructure-impact/pull/33). See the [acceptance record](../../research/2026-11-06-targeted-refresh-acceptance.md). The checkboxes preserve the approved plan; the handoff below records its original approval-stage instructions. Hosted activation remains separately gated.

## Global Constraints

- Preserve advisory schema v2 and immutable evidence/revision history; never rename CVE-2023-5501 to CVE-2024-6858.
- Profile `arista-reviewed-2024-0099-0103-v1` has exactly two primary HTML targets and the one reviewed SA-0103 CSAF alternate from the spec.
- At most three distinct retrieval URLs; two-million-byte cap per document; existing transport retry bound; redirects outside the exact set fail.
- Preview: read-only database, no migration, HTTP, writer lock or input-vault write. Unknown profile fails before recovery assets are opened.
- Decision report: at most 1,000 decisions and two million serialized bytes; bounds fail publication rather than truncate decisions.
- Preserve default sources, frozen study/review definitions, human-review status, schedules, permissions, recovery backend/keys, capacity and delivery limits.
- No arbitrary URL inputs, backfill, Cisco source enrolment, generic model/version matching or new collection HTTP endpoint.
- Raw captures, private/operator artifacts and databases stay outside Git/public output. Use synthetic public fixtures and explicitly public-only local stages.
- Keep release, source-pin activation, hosted preview and one profile application as separate later approval gates. Merging code does not dispatch them.

## Review Focus

1. A new revision or changed selection between preview and application must refuse before HTTP or normalized writes (Task 3).
2. Failure of the second primary or an unexpected alternate error must prevent deployment while preserving valid capture history and authenticated recovery behavior (Tasks 3, 6).
3. Another record sharing the CVE, ID prefix or URL with a different hash must not inherit exclusion (Task 2).
4. Old generations remain readable; new-generation missing/mixed disposition assets must fail without changing the accepted generation (Tasks 4, 5).
5. Current CSV, severity/eligibility/dossier counts and KEV context must not silently regain a retained exclusion through a secondary reducer (Tasks 4, 5, 7).

## File and interface map

Package-relative paths below are under `infrastructure_impact/`; `tests/`, `checks/`, `ops/`, `docs/`, `deploy/` and `.github/` are repository-relative.

| Unit | Files and responsibility |
| --- | --- |
| Identity and partition contracts | New `application/evidence_identity.py`, `application/current_evidence.py`, `schemas/current-evidence-v1.json`; optional plugin policy hook in `plugins/contracts.py` and dispatch in `plugins/registry.py`. |
| Arista policy | New `plugins/arista_current_evidence.py`; register through `plugins/arista.py`. Exact source-led conflict predicate only. |
| Maintenance engine | New `application/maintenance.py`, `collection/maintenance_profiles.py`; optional exact-route restriction in `collection/transport.py`; CLI subcommands in `cli.py`. |
| Current/historical publication | New `application/current_views.py`; `application/query.py`, `application/cohort.py`, `application/reporting.py`, `application/publication.py`, `application/evaluation.py`, `application/extraction_validation.py`, `exports.py`, `http.py`, `application/research_reports.py`, `resources/openapi.json`. |
| Static/browser | `application/static_delivery.py`, `web/delivery.js`, `web/snapshot.js`, `web/app.js`; new `web/current-evidence.js` for the report contract. |
| Hosted control | `ops/hosted_job.py`, `.github/workflows/collect.yaml`, matching `deploy/github-public-service.yaml`. |
| Acceptance and documentation | `checks/public_health.py`, `checks/package_probe.py`, `checks/distribution.py`, `.github/workflows/ci.yaml`, relevant operating/API/plugin guides and a dated acceptance receipt. |

Use focused new modules; avoid moving unrelated logic. Implementation may extract a small shared CSV/selection helper where required by parity, but not restructure unrelated reports.

## Task 1: Identity, policy extension and partition contracts

**Files:** Create the identity/partition/schema units above and `tests/test_current_evidence.py`; modify plugin contracts/registry only for the optional hook.

**Interfaces:**
- `evidence_identity.canonical_json(value) -> bytes`: finite, sorted-key, compact UTF-8 JSON; preserve JSON type distinctions.
- `record_key(record: dict) -> str`: SHA-256 of typed vendor/advisory ID/revision ID/source URL/source SHA identity. Do not include fields changed by public projection, such as metrics/notes, or observation-time analysis metadata.
- Append `VendorPlugin.current_evidence_policy: Callable[[list[dict], dict], dict] | None = None` so existing positional plugins remain compatible. The second argument is the validated private context dictionary defined below.
- `PluginRegistry.current_evidence_decisions(vendor, records, selection_context) -> dict`: isolated inputs; default empty decisions/issues; validate official proofs, exact record references and policy fingerprint.
- `current_evidence.partition(records, selection_context, *, registry, publication, generated_at) -> dict` returns `records`, `retained_advisories` and `current_evidence`. Retained entries wrap the original record plus `decision_id`; their record scope is `retained_latest_excluded`.
- `current_evidence.collect_policy_input(db, records, *, registry) -> dict` reads only the registered policy's referenced retained proof captures. Its private context has selection metadata and source frames `{source_url, source_sha256, evidence_id, source_observed_at, raw_b64}`. Enforce two-million decoded bytes per frame and eight-million serialized bytes for the private context; verify decoding and hashes before a hook sees it. This context is not a public report and must never enter an artifact or log.
- Report v1 has `availability`, publication/time, policy identities, decisions, issues and counts `current`, `retained_total`, `excluded`. Unavailable older-generation reports have null counts, not fabricated zero exclusions.
- Publish this report using canonical compact UTF-8 JSON; include its final newline when enforcing the two-million-byte wire limit. The same encoding/limit must be used by validation, writing and monitoring.
- Decision ID hashes policy/version/fingerprint, target key and proof identities; exclude analysis time/publication so identical facts stay stable. Disposition is `excluded_from_current`; reason is `reviewed_representation_scope_conflict`. An unresolved proof is an issue, not an exclusion.

- [ ] **Step 1 — RED:** Add tests with independent synthetic current/excluded records and a synthetic plugin hook. Assert disjoint current/retained sets, their union equals the retained input inventory, original records unchanged, stable decision IDs, publication binding, default-plugin pass-through and typed identity validation. Mutation cases must reject unknown target keys, forged caller flags, non-official proofs, duplicate decisions, mismatched/base64-overlimit proof frames and exact report/context bounds. Test booleans cannot impersonate numeric revision IDs. Hook outputs may reference validated facts and registered reason text, never echo raw input or arbitrary diagnostics.

  Name the core regression `test_partition_preserves_retained_record_without_current_claim`; its fixture supplies one eligible and one explicitly excluded synthetic record:
  ```python
  result = partition(**partition_case)
  assert len(result["records"]) == len(result["retained_advisories"]) == 1
  assert result["current_evidence"]["counts"] == {"current": 1, "retained_total": 2, "excluded": 1}
  ```
- [ ] **Step 2 — Verify RED:** `uv run --frozen pytest -q tests/test_current_evidence.py`. Capture an assertion failure demonstrating the absent partition behavior; fix test setup/import issues before counting a regression as RED.
- [ ] **Step 3 — GREEN:** Implement the interfaces and strict schema. Keep policy fingerprints separate from normalization semantics; record actual fingerprint effects rather than assuming no churn. A present hook cannot mutate another vendor's inputs or declare an unsupported disposition.
- [ ] **Step 4 — Verify GREEN:** Run the new suite with `tests/test_normalizer_fingerprints.py`, then the project test command before claiming the task complete. Check an external plugin with no hook still functions.
- [ ] **Step 5 — Commit:** `feat: define current-evidence partition and policy contracts`.

## Task 2: Exact Arista conflict policy

**Files:** Create `plugins/arista_current_evidence.py`, `tests/test_arista_current_evidence.py`; modify `plugins/arista.py`.

**Consumes:** Task 1 hook/result/identity contracts and existing source-selection metadata.
**Produces:** `arista_current_evidence.decide(records, selection_context) -> dict`, registered on the Arista plugin, with a versioned/fingerprinted policy identity. No stored-advisory rewrite.

- [ ] **Step 1 — RED:** Create original synthetic CSAF/HTML records and selection context representing the reviewed pair. Assert exactly the legacy record moves out of current scope while CVE-2024-6858 stays current. Mutate each target predicate separately: vendor, literal ID, URL, revision reference, CVE set, target hash, selected primary identity/CVE/hash, absent/conflicting selection and absent alternate-conflict proof. Assert no exclusion for a same-CVE unrelated record or a later matching representation with another hash. Missing proof must be visibly unresolved and cannot satisfy cleanup acceptance.

  Name the pivotal test `test_only_exact_legacy_scope_is_excluded`:
  ```python
  result = partition(**arista_case)
  assert result["retained_advisories"][0]["record"]["cves"] == ["CVE-2023-5501"]
  assert result["records"][0]["cves"] == ["CVE-2024-6858"]
  ```
  Synthetic frame hashes must be real hashes of synthetic bytes; substitute the policy's reviewed hash only in tests. Never ship synthetic trust anchors as production evidence.
- [ ] **Step 2 — Verify RED:** `uv run --frozen pytest -q tests/test_arista_current_evidence.py` must fail on the expected exclusion, not fixture setup.
- [ ] **Step 3 — GREEN:** Implement only the spec's exact target hash `3491af5ed3486c8e74fd04cd432a5072bf0938733cd059d9d24e7f3f2355ef74`, literal ID `Arista Networks Security Advisory 103`, CVE set `{CVE-2023-5501}` and independently validated selected HTML scope `{CVE-2024-6858}`. Reparse the private primary frame through the reviewed HTML parser and independently inspect the alternate frame as comparison evidence; bypassing the direct-CSAF normalization guard is permitted only for this comparison, never for current claims. Cross-check retained record/view/hash references. An unavailable view's generic error code alone cannot prove the literal discrepancy; malformed or absent frame proof stays unresolved. Public output uses registered reason text and source references only.
- [ ] **Step 4 — Verify GREEN:** Run Tasks 1–2 tests plus `tests/test_source_selection.py` and `tests/test_arista_reconciliation.py`; verify old normalized payloads and first capture metadata are unchanged.
- [ ] **Step 5 — Commit:** `feat: exclude the reviewed contradictory Arista interpretation from current scope`.

## Task 3: Bound preview and exact-target apply engine

**Files:** Create the maintenance/profile units and `tests/test_targeted_maintenance.py`; modify transport and CLI. Extend `docs/NORMALIZATION_MAINTENANCE.md` with local commands.

**Consumes:** Tasks 1–2 identities/policy; existing parser, resolver, evidence and selection writers.
**Produces:**
- Frozen `MaintenanceProfile` with ID/version, two primary URLs, exact allowed retrieval set, byte limit, expected primary identities/CVE sets and policy fingerprint.
- `maintenance.preview(database: Path, profile_id: str) -> dict`: strict, sanitized receipt with `fingerprint`, `baseline_fingerprint`, profile/policy/normalizer fingerprints, target metadata, missing-input issues and observation time.
- The accepted preview fingerprint binds the canonical latest-record inventory plus relevant selection facts and profile/policy/normalizer identities. Hash ordered record identities and normalized-payload digests incrementally rather than copying all source bodies into the receipt. Exclude preview observation time. It is a consistency hash, not authentication against a hostile rewrite of all files.
- `maintenance.apply_profile(db, profile: MaintenanceProfile, expected_preview_fingerprint: str, *, fetcher=None) -> dict`: existing service-style writer core; caller owns the one process lock. Recompute the binding before HTTP. Return explicit primary/alternate outcomes, imports/unchanged results, decisions, before/after keys and proof fingerprints.
- `maintenance_profiles.profile(profile_id: str) -> MaintenanceProfile` is the closed registry lookup. `MaintenanceBaselineChanged(ValueError)` identifies a valid request whose accepted state binding no longer matches.
- CLI `impact maintenance preview --database PATH --profile ID --output PATH` and `impact maintenance apply --database PATH --profile ID --preview PATH --output PATH`. Apply validates the preview file and owns the writer lock; preview never does. Refuse symlink/existing output destinations consistently with reconciliation tools.
- `transport.fetch(..., allowed_urls: frozenset[str] | None = None)` or an equivalent caller-owned exact redirect perimeter; omitted restriction preserves ordinary transport behavior. Profile calls use the lower 2,000,000-byte cap and one invocation cache per approved URL.

- [ ] **Step 1 — RED:** Test the exact two target URLs and one permissible alternate, no unrelated feeds/archives/CVE/KEV acquisition, three-URL/capture bounds, retry bound, same-host hostile redirects and over-limit cached 304 content. Test unknown profile before opening a database; malformed preview; baseline revision/selection drift before HTTP; writer contention; identical-byte idempotence; missing second primary; expected literal alternate conflict versus HTTP/layout error. Assert no normalized writes if either primary fails validation, and every old revision/evidence row remains unchanged after success.

  `test_stale_preview_refuses_before_fetch` must use the real writer core and a fixture that appended a revision after preview:
  ```python
  with pytest.raises(MaintenanceBaselineChanged):
      apply_profile(db, profile, accepted_fingerprint, fetcher=deny_fetch)
  ```
  `deny_fetch` fails the test if any network boundary is reached; do not mock the binding calculation or writer core.
- [ ] **Step 2 — Verify RED:** Run `uv run --frozen pytest -q tests/test_targeted_maintenance.py`; confirm the profile-selection and drift tests fail behaviorally.
- [ ] **Step 3 — GREEN:** Implement read-only preview and exact-profile fetch/validation before ingestion. Reuse reviewed resolution and selection retention. Capture/observation writes from failed attempts may remain, but no candidate publication is accepted. A later SQL/write failure may preserve independently appended history; receipt must report failure, never a completed cleanup. Recompute the Task 1 partition and require the intended cleanup proof before accepting an apply result.
- [ ] **Step 4 — Verify GREEN:** Run the new suite, source-access/selection/replay regressions and the project test command. Check default transport and generic reparse remain unchanged; no nesting of the existing writer lock.
- [ ] **Step 5 — Commit:** `feat: add preview-bound exact-target maintenance`.

## Task 4: Native current views, retained API and export boundaries

**Files:** Modify query/reporting/publication/evaluation/export/HTTP/OpenAPI units in the map. Create `tests/test_current_evidence_delivery.py`; extend existing API/evaluation/privacy tests where their behavior changes.

**Consumes:** `partition(...)` and its report/retained wrappers.
**Produces:** `current_views.rebuild(data: dict, partition_result: dict) -> dict`, a pure shared current-view assembly used by query/reporting/projection; `cohort.coverage_from_checks(records, checks, *, cohort, vendors) -> list[dict]`, with the existing DB coverage wrapper delegating to it; `exports.retained_assessment_export(data) -> dict` and `exports.retained_csv_export(data) -> str`. Add GET/HEAD routes `/api/v1/current-evidence` and `/api/v1/retained-advisories`, including explicit JSON/CSV download format selection on the retained route. Native pagination remains 100 default/500 maximum with at most 200 requested CVE IDs. `retained_advisories` lists excluded latest records only; `retained_total` counts the current/excluded union, not all historical revisions.

- [ ] **Step 1 — RED:** Publish a synthetic dataset with one excluded record, its current primary and an unrelated record sharing the old CVE. Assert default advisories/assessments, catalogue, scorecards, coverage/comparisons, groups/families, eligibility/readiness and current research inputs all use the same current set. Assert `counts.advisories` is current, new totals reconcile the retained union and `all_cves` excludes only CVEs absent from every current record. Confirm source audit/history still reference the excluded original.
- [ ] **Step 2 — RED:** Test the public boundary reconstructs the retained union and recomputes policy decisions, rejecting inconsistent supplied partitions, missing decision references or mixed generation metadata. Test explicit retained exports contain record scope, disposition, reason, decision ID and policy identity/fingerprint on every assessment row, with existing CSV formula escaping. Default CSV must contain none of those excluded assessments.

  `test_current_csv_does_not_reintroduce_excluded_identity` reads actual CSV rows; the fixture also contains an unrelated current record for the same CVE:
  ```python
  rows = list(csv.DictReader(io.StringIO(csv_export(current_data))))
  assert not any(r["advisory_id"] == "Arista Networks Security Advisory 103" for r in rows)
  assert any(r["advisory_id"] == "UNRELATED-SAME-CVE" for r in rows)
  ```
- [ ] **Step 3 — RED:** Use a synthetic evaluation definition supported only by an excluded record. Preserve its expectation and separately retained historical outcome, but mark the current result `current_scope_excluded` with the decision reference; exclude it from current pass counts. Apply the same rule to extraction validation. Assert frozen real resource bytes and original blind packets remain unchanged. Test KEV context remains available for a historical CVE without restoring its unsupported vendor assessments.
- [ ] **Step 4 — GREEN:** Wire the partition before current reducers and re-run affected reducers at the privacy boundary. Feed `coverage_from_checks` the independent check facts from existing coverage rows, recalculating assessment-derived states against current records; do not trust previously calculated coverage counts. Carry Task 1's private context only under `research.current_evidence_input`; recompute decisions using it, then remove it before the general JSON clone/sanitization or any public serialization. Preserve caller input immutability. Add a private-body sentinel test proving neither raw/base64 frames nor free-form hook diagnostics reach snapshots, exports, indexes, logs or manifests. Keep full retained context for history/audit and strict new-generation metadata. Implement the new routes, schema serving and OpenAPI; non-read methods remain 405. Older publications expose report availability `unavailable`/`not_reported` and null disposition counts without reinterpretation.
- [ ] **Step 5 — Verify and commit:** Run new delivery tests plus static-delivery, exports/API, evaluation, dossiers and privacy regressions, then `uv run --frozen pytest -q`. Commit `feat: separate current analytics from retained excluded evidence`.

## Task 5: Static transport, browser views and historical downloads

**Files:** Modify static-delivery and web files in the map; create `tests/test_current_evidence.js` and `tests/test_current_evidence_ui.js`; extend `tests/test_current_evidence_delivery.py` and existing Node/static harnesses.

**Consumes:** Task 4 current dataset, strict v1 disposition report and retained envelopes.
**Produces:** `validateCurrentEvidence(report, publication, generatedAt)` in `web/current-evidence.js`; `selectRetainedSnapshot(source, cveIds, options)`, `exportRetainedSnapshot(data)` and `retainedSnapshotCSV(data)` alongside existing current selectors. Add generation-bound static retained parts; visible current/retained-total/excluded counts and an explicit retained-exclusions view. No browser source-policy inference or recomputation of Python record-key hashes.

- [ ] **Step 1 — RED:** Drive the real Python publication through the existing Node VM/static fetch harness. Compare native/current JSON and CSV with browser selections/exports for all records, vendor/CVE filters, empty selections and explicit retained exclusions. Assert historical CSV rows stay labelled and never appear in current downloads. Show a retained-result link when a current search has only excluded evidence, without calling that product unaffected.
- [ ] **Step 2 — RED:** Test missing/hash-corrupt/new-generation decision assets, retained-part omissions, wrong decision references, wrong generation, repeated loads and out-of-order responses. Preserve the accepted UI/report/download state on failure. An old generation without capability metadata remains readable with dispositions unavailable, not zero.
  Name the generation failure `test_mixed_generation_decision_report_is_rejected`, asserting validator failure and unchanged accepted download references. Include exact revision identifiers above JavaScript's safe integer range and boolean/number confusion using the existing lossless JSON handling; no numeric coercion may make mismatched records equivalent.
- [ ] **Step 3 — GREEN:** Add a versioned static-index capability for current-evidence delivery, keeping existing index/part/default-load limits. Write `current-evidence.json`, bounded retained fragments and required schema/script assets into the manifest. Full snapshot and gzip archive include both collections without duplicate record payloads in the decision report. Browser labels are plain scope statements, not certification of current impact.
- [ ] **Step 4 — Verify GREEN:** Run `node tests/test_current_evidence.js`, `node tests/test_current_evidence_ui.js`, existing snapshot/KEV/switching suites and Python delivery parity tests; run `npm run format:check`.
- [ ] **Step 5 — Commit:** `feat: expose retained exclusions with strict static and browser parity`.

## Task 6: Hosted preview/apply control and recovery integration

**Files:** Modify `ops/hosted_job.py`, `.github/workflows/collect.yaml`, `deploy/github-public-service.yaml`; create `tests/test_hosted_maintenance.py`; extend recovery tests where shared behavior changes.

**Consumes:** Task 3 profile validation, preview and apply core; Tasks 4–5 publication builders.
**Produces:** Helper flags `--maintenance-profile`, `--maintenance-mode {preview,apply}`, `--maintenance-preview-fingerprint`; manual workflow inputs with matching names using underscores. Empty inputs keep ordinary behavior. A named profile requires an explicit mode; apply requires the accepted fingerprint. Preview forbids a fingerprint; profile modes conflict with positive generic replay or a replay vendor override.

- [ ] **Step 1 — RED:** Exercise helper entry points with synthetic encrypted recovery and stubbed network boundaries. Unknown/malformed profiles/modes and incompatible controls fail before key/recovery access. Preview authenticates/restores privately, opens the restored vault read-only, emits only a sanitized bounded receipt, and never invokes collect, benchmark acquisition, backup, state commit or Pages upload. Assert original state bytes and decrypted database contents remain unchanged.
  Name the side-effect test `test_hosted_preview_has_no_writer_or_publication_side_effects`; use actual encrypted synthetic restore and receipt generation, with failing sentinels only at forbidden writer/network/deployment boundaries.
- [ ] **Step 2 — RED:** Apply owns one writer lock through refresh, report/partition validation, audit, candidate build and authenticated backup/readback. Test baseline drift before HTTP and no deployment on second-primary, SQL, audit, policy-proof, backup or readback failure. Failed captures may be retained through the existing authenticated failure-recovery path, but no corrupt pointer or success receipt may escape. Expected scope conflict stays explicit partial status.
- [ ] **Step 3 — GREEN:** Separate ordinary, preview and apply orchestration. Do not call `collect_once()` or benchmark acquisition for a profile. Validate the request using pinned-source code before opening recovery data. Gate recovery-state commit and every Pages step off the explicit mode/outcome, including `always()` cleanup paths. Upload only the bounded sanitized preview artifact in preview mode.
- [ ] **Step 4 — Verify GREEN:** Run new hosted tests with `tests/test_hosted_backup.py`, `tests/test_normalization_maintenance.py`, phase-event and deployment-template parity tests. Verify empty-input ordinary collection still follows its existing path and workflow/template bytes match. Use already pinned Actions; no permission, schedule, anchor, key/backend or budget change.
- [ ] **Step 5 — Commit:** `feat: add opt-in hosted targeted preview and apply modes`.

## Task 7: Monitor, installed-package and complete acceptance gates

**Files:** Modify `checks/public_health.py`, `checks/package_probe.py`, `checks/distribution.py`, OpenAPI coverage and `.github/workflows/ci.yaml` for new tests/assets. Update `docs/API.md`, `docs/PLUGINS.md`, `docs/NORMALIZATION_MAINTENANCE.md`, `docs/RELEASING.md`, `docs/OPERATIONS.md`, `docs/rollouts/2026-11-06-arista-targeted-refresh-proposal.md` and `CHANGELOG.md`. Add `docs/research/2026-11-06-targeted-refresh-acceptance.md` with the actual acceptance date if execution occurs later; retain operational receipts/captures outside Git.

**Consumes:** All earlier interfaces; requires one integrated branch. This task adds integration probes, not another alternative implementation.
**Produces:** A reproducible synthetic and original-public-source acceptance packet, exact-head source/wheel/CI verification and a reviewable release/deployment proposal. No actual release/dispatch.

- [ ] **Step 1 — RED:** Extend the public monitor and installed-wheel probe to reject missing or inconsistent new-generation disposition/retained assets and verify union/count/generation invariants. Prove the external vendor plugin without a hook still works. Verify every new schema/API/static route in source and installed-package contexts.
  `test_monitor_rejects_new_capability_without_disposition_asset` must invoke the real checker against a synthetic local HTTP publication, remove that one asset, and assert a failed check while the previously accepted generation stays intact.
- [ ] **Step 2 — GREEN:** Add those probes and document commands, unavailable old-generation states, explicit historical export semantics, preview fingerprint/drift handling, partial outcomes, and semantic downgrade risks. Wire all new tests into existing CI lint/format/Node commands without changing hosted settings.
- [ ] **Step 3 — Source acceptance:** In a separate explicitly public-only stage, preserve complete before/after evidence and revision rows; replay the two reviewed primaries plus alternate with actual URL/time/hash provenance. Verify SA-0099 has CVE-2024-27890/27892 branches, SA-0103 HTML has CVE-2024-6858 and the exact old CSAF is retained but excluded from every current output. Compare current and labelled retained JSON/CSV/native/static results. Repeating identical bytes must not append normalization revisions. Use a preview fingerprint from that stage only; never present it as a hosted fingerprint.
- [ ] **Step 4 — Release verification:** Run full Python 3.11/3.13 suites, exact CI Ruff commands, the complete Node suites, Prettier, both frozen dependency-export parity checks, clean allowlisted source/privacy export, wheel build/license/resource inspection, container verification and installed external-plugin probe. Record frozen-resource equality, actual parser/policy fingerprint changes and representative publication sizes against unchanged limits.
- [ ] **Step 5 — Review and commit:** Obtain a fresh whole-branch review covering all reducers, selectors, exports and hosted failure paths; resolve every important finding and re-run affected gates. Commit the acceptance/docs changes, push and open a reviewable PR. State unresolved evidence gaps and the independent-human-review status; do not claim fair vendor rates or completed hosted cleanup.

## Execution and rollout handoff

Use the maintainer's preserved subagent-driven method. Each task gets a focused implementer and fresh task review, with one writer at a time across shared interfaces. Run independent read-only investigations in parallel only where they cannot mutate shared state. Keep real captures, stage databases, RED/GREEN receipts and review ledgers outside Git.

The current task is plan preparation only. After plan review/approval, execute Tasks 1–7. After implementation approval, prepare exact source assets and a runtime activation proposal. Hosted read-only preview and profile apply still need their own explicit authorization; scheduled collection can invalidate a preview, so recheck its fingerprint before any approved apply. Never substitute a broader reparse or ordinary collection when the exact profile refuses.

## Plan self-review

- Spec coverage: profile/bounds/preview/apply (Tasks 3, 6); shared policy/retention (1–2, 4); native/static/browser/export parity (4–5); older publications, frozen review and KEV separation (4–5); recovery/rollout (6–7); packaging/privacy/verification (7).
- Interfaces: Task 1 owns canonical identity/report/hook names; Task 3 owns preview and core apply; callers in Tasks 4–6 consume those contracts. No public trusted-validation bypass is introduced.
- Review Focus: each of the five listed failure classes has an explicit owning RED test above.
- Scope: the maintenance engine and current-evidence views are coupled by the same cleanup acceptance predicate, so this is one coordinated plan rather than independent deployments.
- Proportion: implementation bodies are intentionally omitted; exact signatures, ownership, bounds and observable tests carry the decisions.
