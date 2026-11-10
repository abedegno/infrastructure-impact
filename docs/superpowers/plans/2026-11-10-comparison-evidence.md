# Comparison evidence implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Explain missing validation inventory accurately and provide a current customer answer.
**Architecture:** Extend the existing switching report with optional provenance context;
keep validation outcomes and selected evidence unchanged. Research documents reuse
hash-verified public bootstrap/overview inputs and existing blind review packets.
**Tech Stack:** Python, pytest, JSON and Markdown; existing dependencies only.
**Spec:** `docs/superpowers/specs/2026-11-10-comparison-evidence-design.md`

## Global Constraints

- No changes to selected assessments, frozen expectations, advisory schema v2,
  advisory normalizers, source defaults, schedules, hosted permissions, runtime pins or publication activation.
- Only official public evidence; no private configuration, vault, worker logs or customer data.
- Retained metadata is not extraction validation, model applicability, security quality or customer upgrade workload.
- Independent human review stays pending; unknown coverage and release dates stay unknown.
- Preserve output without context when the optional selection input is absent.

## Review Focus

- An unselected view cannot qualify unless its selected capture belongs to published records.
- A matching URL with different bytes cannot corroborate the reviewed source revision.
- Unavailable representations and wrong vendors must not acquire retained context.
- Rebuilt public outputs must discard stale or injected precomputed context.
- Provenance annotation must never expose raw bytes, private metadata or expected labels in a blind packet.

### Task 1: Annotate retained alternate availability

**Files:** `infrastructure_impact/application/switching_validation.py`,
`infrastructure_impact/cli.py`, `tests/test_switching_validation.py`,
`tests/test_switching_validation_delivery.py`, `docs/switching-comparison.md`.
Use existing `application/source_selections.py` public projection unchanged if possible.

**Interfaces:** Add optional keyword `source_selections=()` to switching `report`.
For a source_missing case whose exact vendor/URL/source_sha256 matches an unselected
view in validated `public_selections`, add only:
`source_context={state: retained_unselected_representation, source_url,
source_sha256, selected_source_url, selected_source_sha256}`.
No metadata-only validation pass. Existing failures and counters stay unchanged.
`rebuild(data)` consumes `data.source_audit.source_selections`; the CLI consumes the
existing storage selections. No new data source or fetch.

- [ ] Write and run failing tests for matching retained alternate; changed hash,
  wrong URL/vendor, unavailable alternate, unbound selected anchor, omitted input
  compatibility and stale context rebuilding. Check unchanged outcomes/counters
  and review flags, source-selection invariants and private-field exclusion.
- [ ] Implement the smallest shared report change and CLI/rebuild plumbing.
- [ ] Run switching validation/delivery/source-selection tests and lint changed files.
- [ ] Document the field's metadata-only meaning and commit the focused correction.

### Task 2: Recover the actual Cisco software model metadata layout

**Files:** `infrastructure_impact/adapters/cisco_history.py`,
`tests/test_software_release_sources.py`; relevant source-layout documentation.

**Interfaces:** Existing `model_release(raw, url)` and `parse_cisco_17_12_1(raw)`
retain output contract and exact-route restriction. Extend only this optional
reference parser, not advisory normalization or source defaults.

- [ ] Add a minimal project-authored fixture mirroring the actual software metadata
  tree. Verify expected release 17.12.1/date 2023-07-28; show unsupported before repair.
- [ ] Require exact title/h1, one support-birth-cert containing one
  software-data-wrapper, direct tables/rows, Series `Cisco IOS XE 17`, Product Type
  `Cisco IOS XE`, and exactly one directly owned Release Date. Duplicate labels,
  duplicate wrappers, hardware types, wrong titles, nested/document dates and
  malformed date values must fail closed. Lifecycle dates must not become release dates.
- [ ] Preserve supported legacy synthetic section layout and its negative tests.
- [ ] Replay cached `/tmp/impact-cisco-release-20261110.html` offline through the adapter,
  checking its known hash and literal date; keep raw vendor bytes outside Git.
- [ ] Run source and switching history tests, lint changed files; commit scoped repair.

### Task 3: Publish reviewable research outputs

Controller-owned documentation/evidence task, no additional product code.

- [ ] Record latest-run versus retained errors, study relevance and known/unknown
  per-vendor inventory denominators, distinguishing dated source observations.
- [ ] Write a dated brief answering observed CVE volume, competing explanations,
  patch-publication limitations, severity/KEV and model applicability.
- [ ] Export the existing blind switching review packet with generation/input hashes
  and reviewer instructions; preserve null adjudications and pending status.
- [ ] Check input hashes, publication identities, packet digest, count consistency,
  documentation links and current versus historical source dates. Update README links.
- [ ] Commit research artifacts after a fresh whole-branch review.
