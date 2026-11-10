# Switching fix expansion implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Attribute more retained Aruba/Arista affected statements to reviewed fix evidence.
**Architecture:** A finite internal registry supplies source-owned tuple rules to
adapters and generated Python/browser/native validation. Existing legacy guards
remain. Source replay measures changes without changing hosted collection.
**Tech Stack:** Existing Python/jsonschema/pytest, JavaScript/Node and publication codec.
**Spec:** `docs/superpowers/specs/2026-11-10-switching-fix-expansion-design.md`

## Global Constraints

- Advisory schema v2, public DTOs and frozen study/review definitions stay unchanged.
- No source defaults, schedules, permissions, runtime pins, limits or publication activation changes.
- No original/private operator config, vault/key, worker logs, customer artifacts or firmware access.
- Only official public sources; raw captures stay outside Git and are reused without refetching.
- Preserve affected CVE/product/status/configuration/model evidence; do not infer customer upgrades, security quality, equivalence or concealment.
- Human review stays pending. Missing/conflicting source evidence stays visible as unknown.

## Review Focus

- Structured fixed IDs disagreeing with prose: only reviewed consistent combinations qualify.
- Fixed siblings with different leaf labels: require separately pinned exact names and common source product parent.
- Reversed CVE/list order and hotfix/component sections: match exact owned markers, never position.
- Source changes affecting only fix statements: preserve valid affected evidence and expose unresolved fixes.
- Streaming validation and literal release projection: retain required siblings, reject forged copies and preserve unsupported expressions.

### Task 1: Shared registry, Aruba source ownership and complete guard parity

**Files:** create `infrastructure_impact/remediation_bindings.py`,
`infrastructure_impact/adapters/reviewed_fixes.py`,
`infrastructure_impact/resources/reviewed-remediation-bindings.json`,
`infrastructure_impact/schemas/reviewed-remediation-bindings-v1.json`;
modify `adapters/switching.py`, `application/switching_evidence.py`,
`application/publication_reader.py`, `plugins/fingerprints.py`,
`checks/generate_switching_contracts.py`, `web/switching-contracts.js`;
add `tests/test_reviewed_remediation_bindings.py` and focused Aruba expansion tests.

**Interfaces:** Registry exports `definition()`(validated ordinary JSON for generator),
`rule_for(claim)`(matching finite rule or None), `registered_source(claim)`(bool),
`validate_link(claim,remediation,binding,claims)`(raises on semantic mismatch).
Adapter helper exports `apply_csaf(data,claims,url,digest,as_of)` and
`attach_links(claims)`; mutate only approved fixed availability and copied affected
remediations. Functions consume trusted packaged definitions, never caller rule data.

Resource top-level `schema_version:1, sources:[...]`; each source includes vendor,
advisory_id,family,source_url,source_sha256(nullable only for section-pinned HTML),kind
(`csaf`/`arista_marker_list`), product_parent(nullable HTML), source_format(nullable
CSAF), expected_cve_ids, resolution_sha256(nullable CSAF), bindings. Each binding
carries exact cve_id,affected_product,affected_product_id(nullable),affected_locator,
affected_versions,fixed_product,fixed_product_id(nullable),fixed_locator,fixed_versions,
remediation_locator,remediation_details_sha256,availability_date(nullable),
availability_proof_literals; HTML additionally exact statement and clause_sha256.
Optional fields must be explicitly bounded/closed by the internal schema. No operator
paths, arbitrary claims or notes enter generated public guard data.

Use the exact source facts from `/tmp/impact-fix-expansion/aruba-recon.json` and
`05134-recon.json`: 286 finite candidate pairs across five sources. Do not generate
pairs at runtime from numeric/train similarity. Normalize resource structure once,
then use indexed rule lookup; fresh claim validation remains per invocation.

- [ ] Add failing authored tests for positive exact pairs, contradictory 012 negative,
  existing 004 event control,05134 different products/index 1, wrong hash/CVE/parent,
  duplicate/missing siblings, date/future/unknown/planned/truncated cases and jointly
  forged copied+fixed remediation values.
- [ ] Implement closed registry and source helper. Require raw pin, parent and
  literal proof/digest ownership. Preserve original fixed IDs/details/dates and
  unaffected statements; issue diagnostics for fix-only drift.
- [ ] Hook registered link validation ahead of unchanged legacy paths. Generate
  registry data into browser bundle; enforce equivalent full/stream guards. Extend
  native sibling retention using registered_source with unchanged budgets. Ensure
  new dependency files affect all actual consumers; the existing shared-module
  scheme may change all built-in fingerprints this time. Record that effect; future
  resource-only changes should affect Aruba/Arista only, with no global replay requested.
- [ ] Run existing and new Aruba/Python/browser/native tests, generator roundtrip,
  fingerprint checks, lint/format; replay five cached sources and record exact counts.
- [ ] Commit scoped Task1 changes and write report.

### Task 2: Arista CVE-owned marker lists and bindings

**Files:** modify `adapters/reviewed_fixes.py`, `adapters/switching.py`, registry JSON
and regenerated `web/switching-contracts.js`; tests in
`tests/test_switching_fix_expansion_arista.py` plus shared guard tests as needed.

**Interfaces:** Add `arista_assessments(tree,parsed,slug)` returning reviewed fixed
assessment templates and diagnostic codes. Existing `_arista_reviewed` builds typed
claims and calls shared attach_links; no publisher IDs are synthesized. Registry
and generic guard interfaces from Task1 remain stable; fixed_product_id is None.

Use the three accepted sources/four rules in
`/tmp/impact-fix-expansion/arista-recon.json`. Obtain literal affected expressions
from their existing typed extraction of the same cached bytes. Pin tracked CVE set,
source_format, Resolution digest, exact div marker/direct UL and ordered LI text.
Match 0099 by CVE, not sorted list order. Preserve 0103 typo/punctuation literally.
Require Arista EOS product/family, same source/revision/publisher and null dates.
Keep 0062/0061/0070/0081 outside these new rules; old reviewed fixes are unchanged.

- [ ] Write failing tests for four positive cases, reversed 0099 lists, foreign or
  duplicate markers/lists, merged LI, planned/negated/qualified clauses, changed
  Resolution with unchanged affected content, hotfix/TerminAttr/MOS contamination,
  wrong source/CVE/revision, missing fixed siblings and forged literal lists/dates.
- [ ] Implement one bounded clause parser and finite registry entries. On failed
  fix-only guards preserve valid affected output with diagnostic and no new fixes.
- [ ] Verify exact cached source replays, old fix regressions, Python/full/compiled,
  browser full/stream and native parity; compare affected evidence unchanged.
- [ ] Regenerate bundle, lint/format and commit scoped changes/report.

### Task 3: Literal release identities, staged comparison and documentation

**Files:** `application/switching_releases.py`, `web/customer-comparison.js` browser release selector, release/customer tests;
`docs/switching-comparison.md`, new dated research report and README link.

**Interfaces:** Existing literal identity selector accepts exact `AOS-CX ` prefix
for Aruba and terminal punctuation on otherwise supported Arista expressions.
The exact `HPE Networking AOS-CX` release-product label is eligible only with
existing canonical `aruba-aoscx` family; no extraction/study alias changes.
It may identify an explicitly stated `and onwards` literal without interpreting
later-version membership. Original claim/remediation expressions are unchanged.
Malformed 0103 `4.28.11Mand...` remains unresolved and visible. No new DTO fields.

- [ ] Add failing Python/JS tests for exact label/punctuation cases, unsupported
  ranges, typos, foreign product labels, later-version inference and date invention.
- [ ] Implement the smallest equivalent lexical extension and preserve unknowns.
- [ ] Replay cached primary sources through baseline and new extraction, validate
  typed claims and compare affected/status/configuration/model evidence unchanged.
  Record unique new fixed coverage, source publication deduplication and exclusions.
- [ ] Exercise Python/native/browser JSON/CSV selections on the bounded replay.
  Clearly distinguish replay scope from production counts; use current public
  baseline for comparison only, never a substitute for hosted private retention.
- [ ] Document method, source receipts/pins, disagreements, limits, extension
  procedure and required hosted preview/apply steps. No runtime activation here.
- [ ] Run appropriate broad tests/CI, lint/format, clean public export and fresh
  whole-branch review; open a reviewable PR under the existing execution choice.
