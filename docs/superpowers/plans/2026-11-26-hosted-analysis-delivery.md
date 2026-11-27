# Hosted Analysis Delivery Profile Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development. User's standing opt-out permits continuous execution with the preserved method.

**Goal:** Wire the certified eight-view transport into a closed opt-in hosted operator profile without activating it.
**Architecture:** One implementer owns the tightly coupled profile/build/hosted/isolated verification interfaces. Parent rehearses the public operator path, validates evidence equivalence, documents activation and prepares the PR.
**Tech Stack:** Existing Python/JSON/bash workflow and pytest; no new dependencies.
**Spec:** docs/superpowers/specs/2026-11-26-hosted-analysis-delivery-design.md

## Global Constraints

Use synthetic/public inputs only, no .env, vault/private artifacts or new vendor
fetches. Do not run hosted collection or dispatch. No dependencies or scientific,
advisory schema, source membership, native wire, inference or budgets change.
Keep part8MB, selected/export128MB, rawcache16MB and site1GB limits.
No source-pin/repository-variable changes, schedules, permissions, secrets or actual
activation. Defaults stay blank and omit new arguments/metadata. PR90 stays unmerged.

## Review Focus

- Invalid selector, wrongformat or missing scientific opt-in fails before any state/key/collector effect, including workflow private collector ordering.
- Blank profiles preserve exact legacy argv/kwargs/context shapes and old pinned helpers still work when the feature is off.
- Writer and isolated verifier independently bind the same installed profile; paired manifest/request/context injection or removal cannot select a mode.
- Profile options are immutable, year2025 stays fixed, and unknown IDs/types/hash changes/duplicate or mismatched views reject.
- Every path that publishes (ordinary, generic maintenance, target-import apply) forwards the profile; preview does not acquire publication effects.

### Task 1: Closed profile and complete operator/verification wiring

**Files:** Create application/analysis_delivery_profiles.py and resources/analysis-delivery/campus-switching-common-views-v1.json. Modify application/publication.py, publication_v2.py, worker.py, cli.py, ops/hosted_job.py, target_import_stage.py, import_candidate.py and .github/workflows/collect.yaml as necessary. Add tests/test_analysis_delivery_profiles.py and tests/test_hosted_analysis_delivery.py, extend existing scientific-profile/target-import/workflow/package probes where they own assertions. Work under infrastructure_impact/ for package files. No JS changes expected.

**Interfaces:** `analysis_delivery_profile=''` new closed selector at build/publish/collect_once/hosted CLI/stage/verify/native_parity; CLI flag `--analysis-delivery-profile`. Workflow input `analysis_delivery_profile`; env ANALYSIS_DELIVERY_PROFILE from input or vars.IMPACT_ANALYSIS_DELIVERY_PROFILE. Profile module provides profile(id), hosted_profile(...), immutable DeliveryProfile.identity() (`profile_id`, `input_sha256`), options()/build_options() with fresh normalized choices. Exact internal helper signatures are implementer-owned; document them in the report. Resource ID campus-switching-common-views-v1; ordered vendors None,cisco,aruba,arista, each windows all,2025; scope_level=os_family,cve_ids=None. Low-level raw writer and verification options remain supported; named/raw simultaneous verification rejects.

- [ ] Write RED resource/early-effects/default/forwarding tests, actual synthetic publication/native-query verification and workflow old-helper tests.
- [ ] Implement bounded installed resource with pinned digest and closed validation; fresh copies. Package probe asserts installed bytes and identity.
- [ ] Wire build/publish and collect_once/hosted ordinary+maintenance paths, including relevant CLI boundaries. Reject missing scientific/v2/recovery-only combinations before effects; do not inject extra kwargs when blank.
- [ ] Bind private target-import context/request + isolated explicit CLI selector to installed identity, reload independently and pass derived options to native verification. Preserve legacy argv; test missing/extra/null/hash/paired tampering and absent/unexpected/mismatched selected roots. Do not weaken low-level prototype semantics.
- [ ] Wire workflow blank input/variable through capability preflight and invocation. Validate before private collector and reject unsupported helper before effects. Keep exact schedules, permissions, secrets and default flags/effects.
- [ ] Run focused tests, lint/format, self-review, commit/report exact RED/GREEN evidence, interfaces and limitations. No full suite, push, merge or hosted changes by implementer.

### Task 2: Public rehearsal, docs, whole-branch gate (parent)

- [ ] Confirm installed options equal independent PR91 eight-view receipt at data/analysis-worker-20261126/eight-native-receipt.json; no giant native/browser repetition for unchanged writer/frontend.
- [ ] Independently exercise authored operator CLI/native proof/default and failure paths from existing fixture helpers, plus workflow script without secrets/network. Record what was actually run.
- [ ] Document operator invocation, ordinary/maintenance/preview semantics, compatibility, capacity proof boundary and separate activation/rollback proposal. Update README/changelog/guide.
- [ ] Task review and fixes, fresh whole-branch review with one consolidated final wave if necessary; exact CI targets/public source export. Push one coherent PR after review to avoid cancelled duplicate full CI runs; CI matrix is full regression gate. No live activation or dispatch.
