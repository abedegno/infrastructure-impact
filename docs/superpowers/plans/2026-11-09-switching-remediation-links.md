# Source-owned switching remediation links Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task.

**Goal:** Repair the reviewed Aruba and Arista affected-to-fix associations without inferred model exposure or software availability dates.
**Architecture:** Extend existing typed research adapters and exact reviewed-section semantic validation; keep fixed sibling claims and original publisher IDs. Reuse all existing reducers and publication contracts.
**Tech Stack:** Python, canonical JSON schemas/generated browser contracts, existing Node/Python tests.
**Spec:** docs/superpowers/specs/2026-11-09-switching-remediation-history-design.md

## Global Constraints

- No original operator sources configuration, private vault/key or private worker log reads. Test only with packaged sources and authored synthetic fixtures; real cached public captures stay outside Git.
- No automatic version arithmetic, family-wide joins, model inference, ranking, human-review assertion, frozen definition or advisory-v2 break.
- No schedule, permission, hosted source activation or capacity changes in this stage. Keep all existing candidate and publication gates.
- Preserve source URL/hash/capture/revision, original remediation IDs and separate affected/fixed statements. Missing/planned/negated/unowned evidence stays unknown.

## Review Focus

- A fixed sibling with foreign CVE, source revision/hash, product or locator cannot authorize a remediation.
- Streaming readers retain both sides of the exact reviewed association, including duplicates; no sibling omitted from semantic validation.
- Unmapped10.11/10.12 and unaffected/foreign products do not inherit Aruba fixes.
- EOS fixed versions and TerminAttr/other products never exchange values or dates.
- Synthetic projection/export/native/browser paths agree, and original SA0100 accepted/rejected cases are unchanged.

### Task 1: Aruba reviewed product-section linkage and common validators

**Files:** Modify infrastructure_impact/adapters/switching.py, application/switching_evidence.py, application/publication_reader.py, schemas/switching-evidence-v1.json, web/switching-contracts.js; add focused tests/test_switching_aruba_fix_links.py. A small dedicated shared Python helper is acceptable only if its fingerprint dependency is registered. Regenerate browser schema bundle with checks/generate_switching_contracts.py.
**Interfaces:** Continue scope_binding.basis=reviewed_source_sections. Extend fixed_product from Arista EOS to include AOS-CX. Add fixed_product_id as a required nonempty string for AOS-CX bindings, absent for existing Arista bindings. Attached product_ids=[]; original fixed sibling/remediation IDs remain intact. Semantics select exact rule by vendor/advisory/CVE/source.

- [ ] Write red tests using authored CSAF and typed claims for exactly three associations and two unresolved ranges; add ordinary/compiled/native-stream/browser forged-sibling negatives.
- [ ] Use only HPESBNW04669 / CVE-2024-6387 / official2024 hpe_aruba_networking_-_hpesbnw04669.json. Exact source IDs: >=10.14.0000|<=10.14.0006_aos-cx→10.14.0007_aos-cx; >=10.13.0000|<=10.13.1030_aos-cx→10.13.1031_aos-cx; >=10.10.0000|<=10.10.1130_aos-cx→10.10.1131_aos-cx. Require AOS-CX parent identity, fixed literal version and exact reviewed tree/status locators. Do not implement a generic prefix/range algorithm.
- [ ] Append only affirmative available vendor_fix copies backed by one matching fixed sibling of the same CVE/source/revision/publisher. Retain the source's own availability_date as advisory remediation context; do not call it software release availability. Guard reviewed resolution ownership against changed/negated/planned/truncated clauses; if necessary pin the reviewed source digest and cover the guard explicitly. No tuple can attach to10.11/10.12, legacy unaffected or foreign products.
- [ ] Extend Python/JS semantic dispatch and streamed sibling retention. Keep same-row/SA0100 guards unchanged, exact source/locator/fixed-ID/version/remediation equality mandatory. Add schema conditional requirements; regenerate contracts rather than hand-edit generated payload.
- [ ] Replay the cached public HPESBNW04669 bytes from operator investigation with current normalizer, checking source digest07e221b234c64d09ef18a2d291639e2bbca2d6f4bd511dbb6325fee088daa138 and three links/no model bindings. Store the receipt outside Git. Run focused existing+new tests, Ruff/format/generated-contract/diff checks and commit only implementation/tests.

### Task 2: Arista EOS resolution ownership for reviewed advisories

**Files:** Modify adapters/switching.py (or a focused arista_resolution.py with registered fingerprints), application/switching_evidence.py, web/switching-contracts.js; add tests/test_switching_arista_fix_links.py. Preserve canonical binding fields from Task1.
**Interfaces:** Fixed product Arista EOS, fixed_product_id absent; scope_binding reviewed_source_sections points to one fixed sibling with same identity/CVE/revision/source and copied version expressions. Existing SA0100 remains exact. Raw source fingerprints and structural sections, not global family labels, authorize parsing.

- [ ] Write red source-boundary and cross-runtime linkage tests for SA0128/CVE-2025-8872, SA0201/CVE-2026-111943, SA0075/CVE-2022-0778. Add negatives for SA0070/SA0081 EOS exclusions, TerminAttr and foreign fixed lists, multi-CVE ambiguity, plans/negation, duplicate siblings and changed sections.
- [ ] Parse literal fixed EOS lists only in the reviewed resolution sections: SA0128 versions4.34.2F,4.33.5M,4.32.8M,4.31.9M; SA0201 EOS versions4.37.0F,4.36.3.2M,4.35.7.2M,4.34.9.2M,4.33.11.2M (stop before TerminAttr); SA0075 EOS versions4.27.4,4.26.6,4.25.9,4.24.10,4.23.12 (MOS/hotfix sections remain separate). Preserve full source expressions including later-within-train wording; do not manufacture publisher product IDs or release dates. Reject unreviewed resolution structures visibly.
- [ ] Emit separate fixed claims, affirmative vendor_fix availability with null software availability_date and source locators. Attach exact reviewed links to eligible affected claims only. Extend Python/JS and streaming candidate recognition for both affected and fixed sides; do not introduce universal family/version joins.
- [ ] Reuse cached primary captures identified by the operator arista-evidence-index.json for outside-Git source replay. Record supported/unaffected/unresolved outcomes and preserve actual hashes/times. Run focused new+existing tests, generated-contract checks, Ruff/format/diff checks and commit.

### Task 3: Validate integration and document the measured repair

**Files:** Focused tests in tests/test_switching_comparison.py, test_switching_delivery.py or new integration test; docs/switching-comparison.md and dated research follow-up.
**Interfaces:** Same current source partition, typed evidence and existing select_report/readers/CSV; no new comparison denominator or bootstrap format in this stage.

- [ ] Compare the same public-only replay set before/after. Count supported links/events separately from affected CVEs and unchanged/unresolved scopes. Test source partition/exclusion behavior and native/static/JSON/CSV parity; never label a complete archive or actual upgrade count.
- [ ] Run relevant integration, public privacy/package/generated checks and full CI once after integration. Obtain whole-branch review. Commit concise method/results/remaining-history-gap documentation.
- [ ] Continue to the release-history/report stage from the same approved design; write that stage's exact interfaces/plan after source availability findings. No routine approval loop; hosted policy changes remain separately gated.
