# Packed Analysis Preview Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development. Keep one implementer across tightly shared native/browser packing interfaces; the evidence-request document task is independent.

**Goal:** Reduce Cisco analysis loading cost while preserving every selected JSON/CSV result and trust boundary.
**Architecture:** An opt-in lossless packed full-analysis root, bounded decoder followed by unchanged compiled semantics, existing independent flight ownership and native regenerated publication verification.
**Tech Stack:** Existing Python/JavaScript JSON, fingerprints, codec and tests; no dependencies.
**Spec:** docs/superpowers/specs/2026-11-26-packed-analysis-design.md

## Global Constraints

No scientific or advisory schema changes, data inference, customer strings,
reader/site budget increases, dependency additions or hosted activation. Public
and synthetic inputs only; raw bodies remain outside Git. Preserve all fields,
order, numeric types, provenance, generation/observation bounds and existing
mutable selected-output ownership.

## Review Focus

Expansion bombs must fail before row allocation; source metadata must obey both
reader/caller limits; frozen pool sharing cannot leak into mutable selections;
recomputed hashes cannot replace fresh source authority; cached cold/warm reads
must retain independent cancellation and reliable retry.

### Task 1: Packed delivery and generation efficiency

Files: new application/analysis_packing.py and web/analysis-packing.js; publication.py,
publication_v2.py, analysis_delivery.py, web/publication-v2.js and necessary asset
registration; new tests/test_analysis_packing.py/.js; docs/ANALYSIS_PACKING.md and
existing delivery guide. Do not edit README/CHANGELOG (parent owns).

Interfaces: pack_report(source, max_bytes=MAX_SELECTED), private _pack_validated;
unpack_report(packed,max_bytes=MAX_SELECTED); browser
InfrastructureAnalysisPacking.prepare(packed,identity,{max_bytes}) -> selected-study
function. ROOT='switching-analysis-packed.json'. Keep old public APIs compatible.

- [ ] Write failing tests with literal expected layouts/rows, numeric/key-order
  roundtrip, alias isolation, safe IDs/pool/layout closure and expansion bounds.
- [ ] Implement packing/decoding and prove exact source/selection/two-CSV parity
  across vendors/scopes/windows/CVEs using rich existing fixtures.
- [ ] Add opt-in writer flag, independent native regeneration and browser root
  selection; preserve defaults and all legacy descriptors. Test rejected malformed
  advertised data, legacy fallback and cold/warm lifecycle/limit cases in CI.
- [ ] Prune before copying old vendor projections and reuse only the private
  writer's fresh source gate, retaining public/independent validation. Prove
  external mutation cannot alter source or another selected result.
- [ ] Run focused new/core suites, formatter/linter, self-review and small commits.
  Report exact RED/GREEN evidence, interfaces, limits and validation costs.

### Task 2: Vendor evidence request packet

Files: docs/research/2026-11-26-vendor-evidence-request.md plus optional empty CSV
headers under docs/examples/. Read existing 25/26 November research and current
train config. No network or contact required.

- [ ] List exact Cisco/Aruba/Arista missing inputs and public scope limitations.
- [ ] Supply a concise common export-field template with separate release,
  notice/action dates and explicit platforms/completeness. Compute fingerprints
  ourselves on receipt; request publisher URLs and public reuse/access terms.
- [ ] Keep research-only/human-review-pending, no customer references or invented
  data. Self-review each request against retained source evidence; commit docs.

### Task 3: Matched public proof and fresh preview (parent)

- [ ] Cache the current accepted public artifact once; verify its fingerprint.
  Inspect root sizes before decoding, use existing raw captures and budgets.
- [ ] Reconstruct the public analysis once and profile repeated table composition.
  Run matched sequential fresh-process baseline/packed JavaScript reads with exact
  selected JSON/two-CSV hashes and RSS/time/traffic receipts.
- [ ] Build and independently validate a fresh publication preview from public
  source data; account for retained archives/site size. If a DB-authority input is
  absent, document the precise limitation rather than fabricating certification.
- [ ] Run fresh task/final review, consolidated regression fixes, full CI and
  source-export checks. Publish reviewable PR/preview; request separate hosted
  activation approval only after concrete evidence is ready.
