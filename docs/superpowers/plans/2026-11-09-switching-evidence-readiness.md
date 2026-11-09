# Switching evidence readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Expose accurate study-specific validation and repair source-proven fix evidence before extending coverage.
**Architecture:** Extend current query/projection, publication/API and browser paths. Keep literal fix claims separate from proven affected-to-fix links and grouping.
**Tech Stack:** Existing Python, pytest, JavaScript/Node, JSON Schema and GitHub Pages publication formats.
**Spec:** docs/superpowers/specs/2026-11-09-switching-evidence-readiness-design.md

## Global Constraints

- No hosted activation/configuration/schedule/permission changes or original vault/key access.
- Use packaged sources configuration for tests; never read /Users/jonw/cve/sources.json.
- Backward-compatible optional report fields; old generations remain readable.
- No frozen cohort changes, inferred version/model matching or human-review certification.
- Keep raw captures/databases/generated publications outside Git. No capacity-limit changes.

## Review Focus

- Changed article wrappers must produce structural matches only with a matching source-owned section digest (Task 1).
- Current exclusions must not regain support through retained or spoofed report inputs (Task 1).
- Old publications without the new report must show unavailable, not zero success (Task 1).
- Negation/lifecycle text about another product must not authorize a fix for the selected product (Task 2).
- Missing bundle evidence must not masquerade as verified independent upgrade events (Task 2).

### Task 1: Publish study-specific validation and blind packet

**Files:** query.py, current_views.py, publication.py, publication_v2.py, http.py, static_delivery.py, web/switching-view.js and app.js as necessary; switching_validation.py; resources/openapi.json; focused existing/new tests and docs/switching-comparison.md (all under infrastructure_impact unless noted).
**Interfaces:** Produce optional top-level `switching_validation`, `switching_review_packet`, `switching_reviewed_source_scopes`. Reuse switching_validation.report(records, scopes, retained_advisories=...) and packet(records), existing publication/generated_at envelope. Study view can consume these optional bootstrap fields without embedding them into closed switching comparison schemas.

- [x] Write failing tests: vault-backed query computes switching section digests; projection recomputes outcomes from sanitized current inputs, preserves exact vs section matches and pending human review, and does not accept spoofed reports; excluded current evidence stays excluded.
- [x] Test v1/v2 publication roots, native `/api/v1/switching-validation` and `/api/v1/switching-review-packet`, static JSON paths, bootstrap/browser access and old-generation unavailable handling. Require identity parity and blind packet without expected labels/parser output.
- [x] Implement smallest shared path. Do not change legacy global validation/readiness semantics or silently include alternate records. Reuse existing ownership/privacy filtering for digests; reject/drop private field extras by explicit projection. New reports must survive native/static current selections without becoming cohort-filtered accuracy claims.
- [x] Show vendor sample counts, exact and structural matches, unavailable/disagreement outcomes and human-review-pending in the study view, with accepted-generation report and blind-packet links. Update OpenAPI and method documentation.
- [x] Run focused pytest/Node parity, formatting/lint and privacy/current-evidence tests; commit a coherent task change after self-review. Record red/green evidence and limitations in task report.

### Task 2: Correct fix availability and expose patch metric limits

**Files:** adapters/switching.py; application/switching_comparison.py and switching_evidence.py as necessary; schemas/switching-{comparison,overview,summary}-v1/v2.json and web switching contracts/reducer/view only if optional metrics are added; tests/test_switching*; docs/switching-comparison.md.
**Interfaces:** Consume Task 1 study diagnostics through optional bootstrap fields. Preserve current `counts.remediation_events` and strict `_fix` ownership unless a new source-proven binding is explicitly represented and validated in Python/JS; never broaden it by shared family/CVE alone.

- [x] Reproduce HPESBNW04669: fixed AOS-CX product IDs with numeric versions and explicit resolution text should retain reported fixed availability; affected branches remain workarounds and do not inherit the fix. Write negative tests for plans, partial fixes, negated availability, foreign products, lifecycle language and missing product IDs.
- [x] Implement a narrow source-structural availability repair for the supported Aruba wording. Keep provenance and literal product/CVE ownership. No generic keyword relaxation and no range matching. If scope cannot be established, retain unknown.
- [x] Add useful metric-specific diagnostic presentation derived from accepted report facts: observed affected CVEs, observed source coverage unknown, model qualification gaps, known bundle membership versus absent grouping evidence, and fixed-only claims without proven affected-to-fix linkage. Do not represent counted `unbundled_publications` as verified independent patch cycles. Prefer deriving display from existing facts; introduce optional aggregate fields only where required and test native/browser parity and old publications.
- [x] Check report-wide issues are not presented as a vendor's own failed source. Source-specific failures use row.coverage.sources ownership; report-level limitations remain labelled separately.
- [x] Run adapter negative tests, Python/JS reducer/export/contract parity and focused real-source check outside Git. Commit and document remaining attribution gaps; no invented patch linkage or bundle membership.

### Task 3: Triage relevant public historical gaps

**Files:** docs/research/2026-11-09-switching-coverage-followup.md; local outside-Git receipts/worklist only, unless a further source-parser change is justified and tested in a subsequent task.
**Interfaces:** Consume the verified public source audit and existing coverage-gaps CLI / public capture path, not the original private database. Continue using existing bounded configuration and source policies.

- [x] Identify existing isolated public staging evidence/configuration from documented receipts without opening original sources.json or vault/key. Prefer retained captures and cache to new requests.
- [x] Triage known Aruba 2021 TXT links and Arista error sources by documented publication period and family; retain unknown dates rather than guess from CVE IDs or URL sequence.
- [x] Record discovered/retrieved/parsed/qualified distinctions, supported local replay results, exact source errors and a prioritized actionable source/import list. Do not sum overlapping counters or claim full historical completeness.
- [x] Verify worklist provenance and tests appropriate to any actual parser changes; record blockers and leave a reviewable publication proposal rather than activating hosted collection.

### Task 4: Close the two reviewed EOS typed-bridge gaps

**Files:** adapters/switching.py (or a small focused module it delegates to), adapters/arista.py for the demonstrated product-boundary correction, tests/test_switching_evidence.py or new focused tests; docs/switching-comparison.md.
**Interfaces:** Reuse the existing `_arista_reviewed` typed bridge, core parser and typed claim shape. No schema change, synthetic publisher product IDs, inferred model bindings or fixed-release events.

- [x] Read the five-lead source triage in docs/research/2026-11-09-switching-coverage-followup.md. Only SA-0128 (`23115-security-advisory-0128`, CVE-2025-8872) and SA-0201 (`24847-security-advisory-0201`, CVE-2026-111943) are included in this task; earlier table/multi-CVE layouts stay explicit backlog.
- [x] Write failing authored-fixture tests that these exact official routes bridge `Arista affected software HTML` with EOS version expressions, separate TerminAttr scope on 0201, source locators, publication/revision identity and no invented product ID/model/remediation. Require raw bytes re-parsed rather than trusting supplied document assessments.
- [x] Negative tests: unexpected source CVE identity/group, foreign route or format, changed required section/history, swapped/missing product headings, shared/multi-CVE scope, and platform slash labels cannot become model-qualified. Do not normalize TerminAttr as the EOS family.
- [x] Reproduce and repair the core `arista_software` boundary defect seen in SA-0201: a subsequent unrecognized CloudVision Portal heading must clear the active TerminAttr product. Test both normalized and typed outputs against cross-product version inheritance. Preserve recognized groups, and keep unknown product context visibly unsupported rather than attributing it to the previous product. Fix the core boundary rather than compensating by trimming only typed output.
- [x] Implement narrow route/structure/CVE-owned bridging using existing pure parser and shared claim construction. Exact product label `EOS (source platform scope applies)` may establish OS-family context for these reviewed routes, not general prose/model matching. Generated core HTML product keys are not publisher IDs, so typed product_id stays null.
- [x] Offline replay both captured official sources from the outside-Git triage cache, validate complete typed evidence, compare CVE/version ownership, and run Python/JS contract/reducer tests. Commit the small repair and report exact outcomes without claiming new independent CVEs or hosted changes.
