# Reliability build reasons and unique respins

> **For agentic workers:** Use executing-plans for the shared native/browser contract; independent source research runs in parallel. Execute the checks below before publication.

**Goal:** Implement the user's round-six corrections without turning timing, missing versions or document revision dates into security/reliability claims.

**Architecture:** Retain source-scoped observations beneath unique respin pairs. An optional catalogue discriminator enables corrected derivation while historical catalogues remain readable. Build reasons are explicit source-backed release facts, independent of timing classifications and model applicability. Native and browser derivations, review packets, CSV and staircase markers share the same contract.

**Tech stack:** Existing Python application, JSON Schema, static JavaScript and GitHub Pages workflow.

**Spec:** User's round-six items 1–5, following `docs/research/2026-11-27-reliability-staircase-delivery.md`.

## Constraints and review focus

Public anonymous primary sources only; preserve robots/access outcomes, source URL, locator, fingerprint class and retrieval time. No full vendor documents in Git, private evidence, credentials or customer data. Keep release/document-revision/notice/action dates distinct. Unknown remains unknown; human review remains pending. No schedule, permissions, secrets or profile changes.

Review controls: null/resolved predecessor collision; different scoped dates and capture classes; unsupported reason or advisory identity; suffix lead transferring reason to exact target; old roots retaining their semantics.

## Tasks

- [ ] Reproduce duplicate pairs and add failing tests in `tests/test_reliability_build_reasons.py`; implement unique pair derivation in `application/release_catalogue.py`, retaining scoped observations for annual calculations. Reject duplicate published pairs.
- [ ] Add optional source-backed reason fields to catalogue/report schemas. Validate proof identities and derive security/defect/both/unknown; never classify from timing. Test source scope, invalid proof and historical compatibility.
- [ ] Mirror the derivation and marker/review display in `web/release-reliability.js`; regenerate browser contracts. Verify native/browser/CSV parity and source/date wording.
- [ ] Integrate bounded primary-source research packets, supported release references, and an explicit outside-cohort 17.9.6 result. Refresh pending review output and document unknown dates/rates.
- [ ] Run focused tests, full regression/required CI, formatting and public identity checks; obtain a fresh branch review. Merge and run one existing publication, updating only the source pin. Verify served roots and actual browser exports; stop with the requested summary.
