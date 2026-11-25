# Release Reliability Views Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development for independent core, UI and delivery tasks, followed by fresh reviews. Reuse this isolated worktree.

**Goal:** Implement round 4 steps 5–8 with honest release metrics, source-linked staircase context, exports and review evidence.
**Architecture:** Small optional generation-bound report from packaged extracted facts; selection-independent catalogue metrics, separately selected upgrade annotations. Reuse existing v1/v2 publication and identity checks, never hydrate all study claims for this feature.
**Tech Stack:** Python/JSON Schema/pytest and existing browser JavaScript/Node tests.
**Spec:** `docs/superpowers/specs/2026-11-25-release-reliability-views-design.md` and the original user round 4 request.

## Global Constraints

- Public anonymous sources only; no new collectors, credentials or bypass.
- Dates and model scope retain source meaning; all human reviews pending.
- Unknown evidence and rates remain null; counts describe disclosure/collection, not quality.
- Existing study, upgrade counts and filters remain unchanged.
- No schedules, workflow permissions, secrets or live pin changes during implementation.

## Review Focus

- Generation identity checked before root data use; missing older roots remain unavailable.
- Unknown action dates never become later-withdrawal claims; model-unresolved joins stay context.
- Scenario/policy duplicates never inflate date/target annotation counts.
- Research excerpt, original eligibility, partial counts and denominators remain distinct.
- Unsafe links, CSV formulas, malformed reports, future captures and incomplete rate coverage fail closed.

## Shared Interfaces

Python `application/release_reliability.py`:

- `build_report(catalogue=None, config=None, *, publication, generated_at) -> dict`
- `validate_report(report, *, publication=None, generated_at=None) -> dict`
- `with_upgrades(report, selected_upgrades) -> dict` (copy; same identity; no changes to original upgrade facts)
- `csv_export(report, *, max_bytes=None) -> str`

Report root fields: `schema_version:1`, `publication`, `generated_at`, `availability`,
`dataset_observed_at`, `catalogue_sha256`, `catalogue` (null when unavailable),
`config`, `annual`, `respins`, `upgrade_annotations`, `upgrade_selection`,
`review_packet`, `validation`, `limitations`, `method`.
`annual` rows have vendor/train/year/period bounds/year_to_date and `metrics`.
Metrics keys: `releases_shipped`, `deferred_or_withdrawn`, `possible_respin_30`,
`possible_respin_90`, `corrective_respin_30`, `corrective_respin_90`,
`software_defect_notices`, `deferral_notices`.
Every metric: observed_count/numerator/denominator/rate (nullable), coverage,
evidence_class, model_unresolved_count, reason. Core owns final schema and must
notify other workers before changing these interfaces.

Annotations group vendor/train/date/target; contain scenario/policy references,
source matches with type/classification/separate dates/scope status/evidence, and
unknown-state caveats. Core owns exact field names; UI worker consults schema/tests
once written. `review_packet` is an array; standalone packet also includes sources.

JS global `InfrastructureReleaseReliability` exposes
`validate(report, identity)`, `withUpgrades(report, selectedUpgrades)`,
`csvExport(report)`, `render(report,state)`, `renderSteps(report,rows,selection)`.
Python/JS annotation/export parity verified by shared fixtures.
Accepted browser delivery exposes `releaseReliability()` returning report or null.
The report is independent of the study filters; upgrade_selection is null until
selected analysis is supplied. API `/api/v1/release-reliability?format=json|csv`
returns base report. Optional `include_upgrades=1` accepts existing study selection
controls and uses source-owned selected analysis; without it study controls fail.

## Tasks and file ownership

- [x] **Core**: new application/release_reliability.py, schemas/release-reliability-v1.json, resources/release-catalogue.json copied from frozen facts, tests/test_release_reliability.py. Tests first for null rates/complete supported fixture, dates, per-model scope, dedup, CSV and unavailable/future capture. Generate review/validation sections. Do not edit delivery/UI files.
- [x] **Delivery**: publication.py, publication_v2.py, publication_reader.py, static_delivery.py, http.py, web/delivery.js, web/publication-v2.js, switching_evidence.py contract list, OpenAPI, delivery tests. Add packaged report root and standalone review root, ordinary CSV download, identity-first optional loaders, API and asset/schema registrations. Add reader script assets before app. Never inline another large study catalogue or recompute full upgrade walks during publication. Do not edit UI/core files.
- [x] **UI**: new web/release-reliability.js, web/app.js, web/switching-analysis.js, web/customer-comparison.js, tests/test_release_reliability_ui.js and relevant Node wrapper. Render per-train tables and selected step markers, safe source/date details and JSON/CSV downloads; preserve/update pinned narrative. No raw vendor fetch or local persistence. Do not edit delivery/core files.
- [x] **Integration/root**: docs README/changelog/tool guide, switching_validation.py separate reliability checks, validation/report tests, schema/native/browser parity, candidate generation and visual review. Merge #84 after green CI. Review and commit task changes, then fresh whole-branch review. Prepare PR and concrete activation only after tests and review; no permission/schedule/secret changes.

## Rulings

The user's 'Proceed' approves the recommended second delivery. Existing preference
opts out of another planning approval loop. Implement all tasks, preserving the
original request's publication/configuration approval boundary. Dataset/platform
coverage limitations are product output, not grounds to invent rates or keep searching.

## Verification record

Implementation and fresh review completed. Combined final feature verification:
201 passed, one intentional skip. Browser candidate accepted the generation,
rendered all three train cards and exercised JSON, CSV, pending-review and jump
controls. Public source export checks passed. Full CI and production deployment
remain release gates; see the dated publication summary for data limitations.
