# Public-source Coverage Repairs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. This preserves the maintainer's existing execution choice. Steps use checkbox (`- [ ]`) syntax. Implement after maintainer review of this plan.

**Goal:** Repair evidenced Aruba/Arista collection gaps and provide honest read-only coverage diagnostics before extending release-history analysis.

**Architecture:** Extend existing vendor plugins, archive listing/queue, source-bound research and CVSS extraction. Add an operator-only gap report over existing read-only storage; do not change public comparison contracts or create parallel advisory storage. Complete public-only staged acceptance before proposing any hosted change.

**Tech Stack:** Existing Python >=3.11, SQLite, jsonschema, stdlib HTTP/text parsing, pytest and vanilla JavaScript/Node. No new runtime dependency or dependency-pin update.

**Spec:** [Approved coverage-first design](../specs/2026-11-05-source-coverage-repairs-design.md).

## Global Constraints

- Primary vendor and official CVE/NVD/KEV sources only; no third-party aggregator as affectedness authority.
- Advisory schema v2, frozen study definitions/source bindings, original review resources, existing identifier semantics and dependency pins remain intact.
- No automatic product/model/version/date matching or inferred software release dates. No equivalence/security ranking, causal Glasswing finding or concealment claim.
- Existing source defaults, hosted schedules, automatic publication behavior, workflow permissions, runtime pin, secrets and recovery/storage settings remain unchanged.
- Preserve at most 20 pages/200 documents per archive invocation; 512,000-byte target parts, 8,000,000-byte maximum parts, 2,000,000-byte index and 20,000,000-byte default monitor budget. Preserve existing compressed/expanded archive and storage limits.
- No customer names/data, raw vendor captures, credential/token material, local identities or private operational receipts in public source/history/assets.
- New automated checks remain independent-human-review pending. The maintainer reviews personally; no contact with another reviewer is authorized.
- No package-version bump, source tag, release publication, hosted secret wiring/backfill or activation in this implementation milestone. Record remaining blockers explicitly.

## Review Focus

1. An affected version/CVE block must not leak into a different product or an unaffected/triage section; pin this in Tasks 1–2.
2. A recognized non-CVE notice that later becomes an advisory must not remain ignored; pin ordinary collection, archive and replay in Task 2.
3. Directory exhaustion, duplicate representations and changed pages must not become invented vendor completeness; pin queue/window identities and unknown totals in Tasks 1 and 3.
4. Operator reports must neither write/migrate the database nor fetch sources or credentials, including implicit configuration fallback; pin SQLite query-only, network traps and explicit CLI inputs in Task 3.
5. Source parsing alone must not appear as successful study/CVSS extraction; pin source locators, typed score validation, native/browser selectors and installed-wheel behavior in Tasks 1, 2 and 4.

## Files and task boundaries

- Task 1 owns new Aruba text/layout helpers, its plugin wiring and the necessary Aruba study/CVSS dispatch. It produces opt-in historical sources and native normalized/study evidence.
- Task 2 owns Arista current applicability and advance-notice handling, its plugin/research bridge, and notice revision regressions.
- Task 3 owns a new read-only operator report/CLI/schema, the combined opt-in sources example, and Cisco readiness documentation/tests. It consumes Task 1–2 source formats and existing archive states, not their private helper bodies.
- Task 4 owns integration acceptance, CI test-path additions, distribution probes, public-method documentation and the dated public-source staging summary. Actual bytes/receipts remain outside Git.

Shared integration points (`adapters/switching.py`, `adapters/cvss.py`, plugin fingerprints) are edited sequentially. Do not independently refactor these modules. Existing source-selection chronology and immutable-publication validation stay active.

---

### Task 1: Aruba historical discovery, text normalization and source-bound study evidence

**Files:**
- Create `infrastructure_impact/adapters/aruba_text.py`.
- Modify `infrastructure_impact/plugins/archive_listings.py`, `infrastructure_impact/plugins/aruba.py`, `infrastructure_impact/adapters/switching.py`, `infrastructure_impact/adapters/cvss.py`.
- Create `tests/test_aruba_text_coverage.py`; extend `tests/test_switching_backfill.py` only for archive integration.

**Interfaces:**
- Add `archive_listings.aruba(raw: bytes, url: str, vendor: str) -> ArchivePage` for the positively reviewed `https://csaf.arubanetworking.hpe.com/2021/` directory.
- Add `aruba_text.parse(raw: bytes, url: str, vendor: str) -> dict` for advisory-v2 output and `aruba_text.research_evidence(raw: bytes, url: str, vendor: str, document: dict) -> dict` for existing switching evidence templates. Both re-read the source through shared internal parsing, never treating normalized fields as source authority.
- Add `aruba_text.metric_inputs(raw: bytes, url: str, vendor: str, document: dict) -> dict` returning `{metrics: [...], severity: [...], issues: [...]}`. Each metric has exactly `metric` (source CVSS version/baseScore/vectorString), `cve_id`, `source_locator`, `form`, `context`; each severity has `rating`, `source_locator`, `scheme`, `namespace`. These are internal source inputs, not published metrics. Feed them through existing `cvss.extract` validation and source/provenance construction; do not bypass `_validate` or read normalized `document['metrics']`.
- Existing JSON/CSAF behavior and plugin signatures remain compatible. Task 3 supplies the combined opt-in example; defaults remain untouched.

- [ ] **Step 1: Write source-layout regression tests.** Use project-authored synthetic signed text following the reviewed 2021-013/019 structures, with synthetic CVE IDs. Pin four header CVEs, a continued header, literal 6300/6400 family text, section-specific vectors, exact initial/revised dates, shared versus per-CVE statements and original bytes. Assert four bound affected claims for the reviewed shared-scope pattern and explicit unaffected AOS-CX evidence for the reviewed exclusion pattern. No exact 6300M/6410 model applicability may be inferred from family text.
- [ ] **Step 2: Add adversarial/listing tests.** Require listed links only; reject other hosts, `../`, percent-encoded traversal, other years, queries/fragments/credentials, malformed/changed listing structure and unrecognized signed-text sections. Count duplicate entries separately from unique URLs; terminal listing must keep vendor-wide total/completeness unknown. Unknown years/layouts stay unsupported. Preserve generic “other products” text without inventing product claims.
- [ ] **Step 3: Run RED.** Run `.venv/bin/python -m pytest -q tests/test_aruba_text_coverage.py tests/test_switching_backfill.py -k 'aruba or historical_text'`. Confirm failures exercise missing behavior rather than an invalid fixture or import setup; record the relevant failures.
- [ ] **Step 4: Implement the source helpers and plugin wiring.** Keep text parsing and source locators focused in `aruba_text.py`; use existing `base`/`assessment`, date/availability, evidence-template and metric-validation contracts. Retain signed framing without claiming signature verification. Unknown dates/versions/metrics remain explicitly unknown. Add all new parsing/research dependencies to the normalizer fingerprint inputs.
- [ ] **Step 5: Implement typed metric dispatch.** Restrict the new text path to the reviewed Aruba representation and route. Bound metrics to their explicit CVE section; incomplete/invalid forms retain current diagnostic behavior. Preserve ordinary full-scope valid metrics and study score ownership; no source-product IDs or applicability may be invented to attach a score.
- [ ] **Step 6: Exercise resumability and strict boundaries.** With an explicit empty base configuration plus the opt-in Aruba archive, use synthetic fetches through ordinary archive and switching staging entry points. Interrupt a bounded invocation, resume it and assert no lost source identity/evidence, no duplicate disclosures, no changed defaults/frozen resources and no false pre-2022 or whole-portfolio completeness claim. Confirm `research_evidence` actually contributes valid study claims and source-bound remediation facts; normalized success alone is insufficient.
- [ ] **Step 7: GREEN and commit.** Run the new tests plus `tests/test_switching_backfill.py`, `tests/test_switching_evidence.py`, `tests/test_cvss_enrichment.py`, `tests/test_normalizer_fingerprints.py` and relevant existing Aruba/history tests. Run focused ruff/format and `git diff --check`. Commit the independently testable Aruba deliverable and report RED/GREEN evidence.

### Task 2: Arista applicability, platform exclusions and advance notices

**Files:**
- Create `infrastructure_impact/adapters/arista_current_scope.py`.
- Modify `infrastructure_impact/plugins/arista.py`, `infrastructure_impact/adapters/switching.py`; modify collection/replay code only for a demonstrated notice-transition defect.
- Create `tests/test_arista_current_scope.py`, `tests/test_coverage_notice_transitions.py`.

**Interfaces:**
- Add `arista_current_scope.parse(raw: bytes, url: str, vendor: str) -> dict` for the reviewed routes `24853-security-advisory-0202` and `25023-security-advisory-0203`.
- Add `arista_current_scope.advance_notice(raw: bytes, url: str, vendor: str) -> dict` for the positive advance-notice representation on `25024-security-advisory-0204`; use the existing plugin `non_cve_notice` path.
- Extend the existing reviewed Arista research bridge for new source-format labels; preserve existing evidence shape. New helper names/formats are consistently pinned in code, tests and plugin fingerprints.

- [ ] **Step 1: Write synthetic applicability tests.** Pin distinct affected non-EOS product/version lists, literal EOS unaffected platform lists, products under triage and source configuration text. Include 7050X3, the literal slash label `720XP/722XPM`, `750X` and `7500R` as separate labels: do not resolve slash/near-match names beyond existing reviewed aliases. A listed unaffected platform remains unaffected when the source also says underlying code will be fixed. A future defense-in-depth fix has no invented availability date or required upgrade event.
- [ ] **Step 2: Write source-scope negatives.** Nested lists, missing/changed status markers, incomplete lists, another CVE in unrelated prose, another product's versions, unknown product labels, removed MPTCP wording and hostile markup must not broaden status/model/CVE scope. The source-wide CVSS score is independent of platform affectedness; preserve existing unsupported/incomplete HTML metric diagnostics rather than inventing scores.
- [ ] **Step 3: Write notice transition tests.** A positive non-CVE advance notice retains source evidence and creates no CVE/product assessments, bundle or fix event. An empty page, an access challenge and a CVE-bearing unaffected advisory must not become notices. In synthetic successive source revisions, replace advance notice with actual CVE/product evidence on the same URL; ordinary collection, archive processing and retained-source replay must stop treating the updated source as permanently ignored. Restrict the reviewed advisory representation as tightly as the observed bytes permit; do not assume an unobserved publisher layout is supported.
- [ ] **Step 4: Run RED.** Run `.venv/bin/python -m pytest -q tests/test_arista_current_scope.py tests/test_coverage_notice_transitions.py`. Record the behavior failures before implementation.
- [ ] **Step 5: Implement narrowly reviewed parsing and notice classification.** Parse publisher identity/revision/date and section hierarchy without broad generic HTML inference. Reuse existing non-CVE classification and evidence retention; do not introduce a notice table or bypass ordinary advisory validation. Update the plugin dependencies and study bridge together so successful source normalization is reflected in valid study evidence.
- [ ] **Step 6: Review the existing Cisco notice separately.** Inspect only authorized primary source bytes or dedicated public-stage captures. Implement a positive existing-contract informational route only if observed bytes support it; otherwise record the source as unresolved. Do not infer a notice from `notice` in a URL or silently relax Cisco identity/CVE rules.
- [ ] **Step 7: GREEN and commit.** Run both new suites with existing Arista scope/history/management/routing, retained-source replay, source-selection and switching-evidence tests. Include strict public projection and JSON/CSV selection assertions on the synthetic new claims. Run focused lint/format and `git diff --check`; commit and report source-format/fingerprint changes and any unresolved Cisco notice.

### Task 3: Read-only gap inventory and Cisco operator readiness

**Files:**
- Create `infrastructure_impact/application/coverage_gaps.py`, `infrastructure_impact/schemas/coverage-gaps-v1.json`, `tests/test_coverage_gaps.py`.
- Modify `infrastructure_impact/cli.py`; create `examples/switching-coverage-sources.json` and `docs/source-coverage.md`.
- Extend `tests/test_cisco_openvuln.py`/`tests/test_switching_backfill.py` only for readiness cases not already covered.

**Interfaces:**
- Add `coverage_gaps.report(db, config: dict, *, vendor: str | None = None, limit: int = 32) -> dict`; consume existing source audit/archive/backfill state and bounded retained-source triage without invoking retrieval. Require `1 <= limit <= 200` and reject Boolean limits/unknown vendors.
- CLI: `impact coverage-gaps --database PATH --config PATH [--vendor ID] [--limit N] [--output PATH]`. Both database/configuration paths are mandatory; open with `connect(path, read_only=True)`, validate the explicit configuration and emit UTF-8 JSON. Do not fall back to environment/native paths, migrate/create a missing database, acquire a writer lock or publish a report.
- Root report fields: `schema_version` (1), `generated_at`, `scope`, `last_run`, `sources`, `triage`, `limitations`. `scope` identifies selected vendor/null and sample limit. `last_run` is the separately labelled persisted global last-run summary/null, never allocated across vendors. `triage` includes available/sample/truncation counts and bounded per-source outcomes.
- Each source row identifies vendor, official source URL/kind, observed/requested window or null, archive/backfill invocation identity or null, current health metadata/null, retained source evidence references, queue outcomes and unknown publisher total/completeness. Keep parsed advisories and recognized notices separate. Preserve source-specific duplicates and unknown/alias states; source-row totals are nonadditive across representations/windows. Only controlled classifications/error codes and whitelisted metadata are emitted; never raw diagnostics, payloads or credentials.
- JSON Schema is closed at every defined object boundary. Exact nested field names are an implementation detail to settle consistently once in the schema and tests; all behavior and distinctions above are binding. Existing public study/scorecard/API contracts stay unchanged.

- [ ] **Step 1: Write report/CLI tests.** Build synthetic queue, health, notice and normalized-source states through current storage operations. Assert discovered/retrieved/parsed/notices/pending/access failures/unsupported outcomes remain distinct; unknown totals/dates/models remain unknown; a parsed notice is not an affectedness classification. Historical attempts, current source state and replay outcomes must not be summed as one failure count. Two known representations of one advisory must not be reported as two disclosures; unresolved aliases remain explicit rather than guessed.
- [ ] **Step 2: Pin read-only behavior.** Use a real temporary SQLite file opened query-only and compare table contents/schema before/after. Trap HTTP/client/credential access and writer-lock acquisition. Missing explicit database/config paths and missing files fail without creating files or loading native configuration. An explicit empty configuration does not trigger defaults. Validate unknown vendor, malformed paths/configuration and invalid limits; never echo secret values or raw exceptions in JSON.
- [ ] **Step 3: Run RED.** Run `.venv/bin/python -m pytest -q tests/test_coverage_gaps.py`; verify missing report behavior is the cause of failures.
- [ ] **Step 4: Implement report, closed schema and CLI.** Reuse read-only existing helpers only after confirming they neither fetch nor mutate. Project whitelisted source identities, safe outcome codes and source evidence metadata; no public raw error strings. Keep bounded triage sample/truncation explicit. Schema-validate the output and add mutation tests for extra/private fields and invalid counters/types. A report failure does not justify weakening read-only mode or gates.
- [ ] **Step 5: Add opt-in sources and Cisco instructions.** Example configuration uses empty ordinary feeds and the reviewed Aruba year archive; include explicit Arista source URLs and a documented optional Cisco openVuln enumeration seed through supported existing configuration keys. Validate it without network. Document client registration/environment names, missing or partial credentials, persistent quotas, resume, and enumeration versus document retrieval. Do not put values in examples or probe real credential state while generating the report. Add only uncovered synthetic client cases; existing passing client behavior does not require a rewrite.
- [ ] **Step 6: GREEN and commit.** Run new report/CLI tests, configuration/source audit/triage tests, `test_cisco_openvuln.py`, switching backfill and archive/replay regressions. Verify schema installed-resource paths, lint/format and `git diff --check`; commit the operator deliverable. Document that real authenticated Cisco history remains blocked until authorized credentials exist.

### Task 4: Integrated public-source acceptance, delivery and documentation

**Files:**
- Create `tests/test_coverage_repairs_integration.py`; extend shared Node selector fixtures/tests if new cases expose a parity gap.
- Modify `.github/workflows/ci.yaml` only to add new test paths to existing lint/format commands; extend `checks/distribution.py`/`checks/package_probe.py` for newly shipped report/schema/plugin behavior where needed.
- Modify `README.md`, `docs/source-coverage.md`, `CHANGELOG.md`; create `docs/research/2026-11-05-coverage-repair-observations.md` after actual staging evidence exists. Use an Unreleased changelog entry; package/dependency versions stay unchanged.

**Interfaces:**
- Consume Task 1–3 plugins, research/metric dispatch, CLI/configuration and strict operator schema.
- Produce synthetic end-to-end source→normalization→study/public projection→Python/browser selection→JSON/CSV acceptance, plus an isolated actual public-source stage and a dated summary of its observed successes/gaps.

- [ ] **Step 1: Write integration regressions before fixes.** Combine a synthetic Aruba shared/per-CVE source, Arista affected/unaffected/triage source and advance-notice transition in a fresh explicit-path vault. Assert exact source hashes/revisions, all intended claims and no invented model matches, strict metric quality states and JSON/CSV/native/browser row parity at a fixed evaluation time. Assert the gap report is schema-valid/read-only and distinguishes notices from failures. Old generation inputs remain immutable.
- [ ] **Step 2: Run focused RED/GREEN.** Run the new integration suite and relevant existing Node switching/strict-contract tests. Fix only demonstrated integration defects in the owner modules, preserving source semantics and all independent validation. Add a covering regression for each fix.
- [ ] **Step 3: Run bounded actual public-source acceptance.** Use a new isolated public-only stage with all `IMPACT_HOME`, `IMPACT_DATABASE`, `IMPACT_SOURCES`, `IMPACT_PUBLICATIONS`, `IMPACT_SNAPSHOT` paths explicit. Remove ambient `CISCO_OPENVULN_CLIENT_ID` / `CISCO_OPENVULN_CLIENT_SECRET` from the staging subprocess environment without inspecting or printing values; no authenticated live run is authorized. Enumerate the published 2021 directory, process only its listed documents within the existing 20-page/200-document cap, and test the three reviewed Arista sources. Retain exact raw bytes/metadata outside Git. If anonymous access is blocked, retain the real error; authorized earlier dedicated public-stage captures may be replayed only when separately labelled with their original metadata. Never use native/customer/hosted-recovery data or execute a bot challenge.
- [ ] **Step 4: Verify actual study/report acceptance.** Generate a local publication from the stage and run strict writer/index/default monitor checks. If the sole-source set lies outside the frozen benchmark cohort, preserve the ordinary empty-cohort result; any replay-only selection override must use actual retained CVEs, leave the frozen cohort unchanged and be explicitly labelled. Report per-source enumerated/retrieved/parsed/notices/unsupported/blocked counts, source dates and unqualified model statements. Do not promise 19/19 Aruba parsing or complete Cisco/vendor history. Run the read-only gap CLI and verify no database/source-state changes.
- [ ] **Step 5: Write method and stage observations.** Explain corrected input coverage, source-specific limits, unresolved sources and missing Cisco authorization. Distinguish counts from security quality, configuration applicability from underlying component code, and notice classification from recovered vulnerability evidence. Preserve pending human review and old frozen results. Link release-history as the next milestone without claiming it implemented.
- [ ] **Step 6: Run final quality once on final code.** Run `.venv/bin/python -m pytest -q`; all relevant existing Node snapshot/KEV/switching suites and format check; exact CI ruff check/format; actionlint if CI changed; frozen runtime/build export comparison with pinned uv 0.11.21; wheel build and isolated external-plugin probe; clean source-export/private-artifact/synthetic-fixture checks. Run a supported Python 3.11 suite from clean export and retain the existing documented Git-only skip. Repeat a broad check only for changed code, a failure or a specific unresolved concern.
- [ ] **Step 7: Commit and hand off for final review/CI.** Commit integrated tests/method/observations and necessary narrow fixes. Report the exact source SHA, commands/results, actual stage counts/timings and blockers. Preserve source captures and receipts outside public source/assets. Complete independent whole-branch review before proposing PR/release activation; exact-head remote Python 3.11/3.13/container CI is the subsequent PR gate. Do not tag, merge, change pin, provision credentials or dispatch the hosted collector.

## Plan self-review

- Spec coverage: historical Aruba discovery/text/study/CVSS → Task 1; Arista exclusions/conditions and notice revision handling → Task 2; safe operator accounting and Cisco readiness → Task 3; source-backed acceptance, packaging, documentation and remaining blockers → Task 4.
- Interfaces: existing plugin signatures and advisory/public report schemas stay unchanged; new source helpers and the new operator-only report are explicitly scoped. Cross-task schema/format names are documented by each producer and consumed without duplicate implementations.
- Review Focus: all five classes have owning regression steps above, including no network/writes during operator reporting and notice-to-advisory transitions.
- Source and authorization boundaries: actual public bytes/receipts remain outside Git; no native/private/hosted recovery evidence, workflow/default/secret/limit/version changes. Real Cisco authorization and later release-history design remain explicit dependencies.
- Scope/proportion: four independently testable deliverables; setup and documentation are folded into their owners. No new public UI, statistics, security ranking, automatic matching or persistent advisory store.
