# Switching projection copy reduction implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Avoid two redundant large switching input copies without changing publication outputs, input normalization/rejection, or isolation.
**Architecture:** Extract and JSON-validate the input outside generic clones; borrow only native JSON trees until the existing isolated allowlist projection. Noncanonical Python values use old normalization fallback.
**Tech Stack:** Existing stdlib Python/pytest; no dependencies.
**Spec:** docs/superpowers/specs/2026-11-11-switching-projection-copies-design.md

## Global Constraints

- Preserve the complete old JSON boundary including ignored fields, NaN/Infinity, invalid objects, cycles, tuple/key normalization and finite-number behavior.
- Preserve output byte/value identities and input/output mutation isolation in v1 and v2; never mutate borrowed nested inputs.
- Keep all evidence/schema/semantic validators, value/context fingerprints, gates and time/byte budgets unchanged.
- No private configs/vault/keys/logs/firmware/customer data, source HTTP, scheduling/permissions/source-pin or publication operations by workers.

### Task 1: Isolate switching input outside general clones

**Files:** infrastructure_impact/application/publication.py and current_views.py; focused projection compatibility tests (existing fixture conventions); small method documentation if helpful.

- [ ] RED regression proving switching_input is absent from the generic clone/rebuild tree while actual projected evidence/comparison/release outputs remain equivalent; use existing synthetic full publication fixture and both formats as appropriate.
- [ ] Add compatibility/isolation tests: unknown-field nonfinite/unsupported values still reject, noncanonical tuple/key containers normalize through old fallback, null/missing input unchanged, original nested claims/score-availability unaffected by output mutations and vice versa. Keep tests small and behavior-focused.
- [ ] Implement smallest streamed strict JSON compatibility check/native-tree guard+legacy fallback; shallow isolated header for score availability; remove input from generic research clone, consume saved header later. Do not change projector/reducer validators.
- [ ] Run meaningful focused tests, lint/format/diff; compare authored-shell cached4k diagnostic peakRSS/timing before/after if feasible without vendor fetch or full dataset reconstruction. Save exact evidence; do not infer hosted speed.
- [ ] Commit scoped files, report command/output/test coverage, limitations and readiness. Root owns independent review/fullCI/hosted acceptance/activation.

Task1 interface correction: current_views.rebuild consumes switching_input for provenance filtering and cached fallback. Preserve that consumer via an internal optional prepared-input parameter installed after its generic deepcopy; clone header and each mutable claim header before existing filtering assigns lists. The two-argument default is unchanged. public_projection must pop the resulting research.switching_input, including cached fallback, rather than retaining only its earlier saved variable. Add exact excluded-owner, ambiguous-ownership and cached-valid-evidence regressions. No duplicate provenance implementation or skipped filters.
