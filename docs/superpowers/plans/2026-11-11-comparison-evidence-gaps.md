# Comparison Evidence Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two demonstrated source/projection omissions and give the customer an accurate, current comparison assessment.

**Architecture:** Reuse validated switching claims for Cisco release context and the existing exact-route Arista adapter/bridge pattern for a shared unaffected statement. No new data store or schema. Keep the public evidence audit independent of hosted activation.

**Tech Stack:** Python, existing HTML parser and JSON Schema, JavaScript browser contracts, pytest/Node tests.

**Spec:** [Comparison evidence gaps](../specs/2026-11-11-comparison-evidence-gaps-design.md).

## Global Constraints

- Existing advisory schema v2 and report schemas remain unchanged; no dependency or generated schema payload change is expected.
- Primary vendor/public project evidence only. No private configuration, vaults, keys, firmware, customer data or worker logs. Raw vendor captures stay outside Git; fixtures are authored reductions.
- No credential, schedule, permissions, collection-budget, runtime-pin or hosted publication changes in this implementation milestone. Existing incremental queues are not declared historically complete.
- No automatic version comparison, patch date, installed model applicability, silent-fix allegation or ranking. Missing remains unknown. Bulletin-shared unaffected context cannot increase affected CVEs or remediation events.

## Review Focus

- Numeric affected CSAF product leaves are not fixed releases: Task 1 rejects unsupported products and remediations.
- Release dates and family/model eligibility cannot be borrowed from sibling references: Task 1 checks unknown dates and model selection.
- Hardware or foreign tables must not contaminate EOS CVEs: Task 2 checks table ownership and distractors.
- Truncated/changed EOS exclusion and nested lists cannot turn into unaffectedness: Task 2 rejects broken boundaries and retains literal unresolved platforms.
- Collection success and queued totals are not complete history: Task 3 separates inventories and qualifies customer conclusions.

### Task 1: Existing Cisco same-row fix in release history

**Files:** Modify `infrastructure_impact/application/switching_releases.py`, `infrastructure_impact/web/customer-comparison.js`, `tests/test_switching_release_history.py`, `tests/test_customer_comparison.js`; add narrowly scoped publication/parity assertions to existing relevant tests if needed.

**Interfaces:** Consume validated evidence claims with vendor `cisco`, family `cisco-iosxe`, exact product `IOS XE Software with NETCONF enabled` and owned remediation version expression. Produce ordinary release nodes through existing `build`/writer and accept them through browser `validateHistory`; no new public interface.

- [ ] RED: authored same-row Cisco claim produces a `17.15.1` affected-scope reference, no fixed-only count, no software date or model qualification; current implementation omits it.
- [ ] Add the exact product and strict bare numeric three-component literal to Python and browser. Preserve every existing ownership, availability, draft, date and scope check; do not parse free remediation prose.
- [ ] Cover range/prose/punctuation/suffix/whitespace rejection; wrong product/family and missing/unowned fixes; unavailable/planned/future fixes; input immutability; model/CVE/window exclusion; unrelated 17.12.1 date remains unrelated. Reuse existing validation negatives rather than duplicate them.
- [ ] Extend Python-to-browser selected-history/envelope parity and relevant publication reader/writer integration; verify exact sources/nulls and unchanged affected/remediation study counts.
- [ ] Run focused affected tests plus required lint/format; report commands, RED/GREEN and scope. Commit only task files and write task report.

### Task 2: Arista SA-0226 unaffected EOS boundary

**Files:** Create `infrastructure_impact/adapters/arista_hardware_notice.py` and `tests/test_arista_hardware_notice.py`; modify `infrastructure_impact/plugins/arista.py` and the existing `_arista_reviewed` route/HTML-ID dispatch in `infrastructure_impact/adapters/switching.py`. Touch package probes only if required by current architecture.

**Interfaces:** Consume exact official SA-0226 HTML through normal plugin `parse`; produce advisory v2 assessments with `scope=bulletin_shared`, `product=Arista EOS`, status `unaffected`, literal platform list, owned CVEs and no remediation. Existing research bridge projects equivalent family-level claims with publisher history/provenance and unresolved platform bindings.

- [ ] RED: authored source-shaped hardware notice with owned CVA CVE tables, lowercase EOS exclusion marker, sibling/nested list and revision table must normalize without inventing affected/fixed rows. Current fallback fails.
- [ ] Implement exact route/title/table/revision/exclusion ownership using existing reviewed parser helpers where suitable. Keep the notice's 15 owned CVE identities, EOS platform literal boundaries and ambiguity warnings; reject unsupported variants visibly.
- [ ] Register plugin dispatch and normalizer dependency. Add route/source-format research bridge ownership and remove locally generated product IDs from public research claims.
- [ ] Test foreign/CVA/CVE bait, missing/changed/duplicate tables and exclusion, unbound/active/hidden content per existing helper policy, changed title/route/revision, nested list preservation, hardware scope isolation and no family/model/CVE affectedness inflation. Validate authored advisory v2, extraction and comparison summary; human review remains pending.
- [ ] Replay the captured official 113,647-byte source outside Git with recorded SHA and assert 15 shared EOS-unaffected claims, no EOS fixes/affected claims and visible ambiguity. Run focused tests, applicable architecture/fingerprint checks and lint; commit task files and report RED/GREEN.

### Task 3: Evidence audit and customer assessment

**Files:** Create `docs/research/2026-11-11-comparison-evidence-audit.md`, a compact evidence JSON under `docs/research/2026-11-11-comparison-evidence/`, and `docs/research/2026-11-11-customer-comparison-assessment.md`. Update `docs/switching-comparison.md` for the new bounded support and current limitations.

**Interfaces:** Consume pinned generation `c2115c35b1c84b7dbdb3134ccac98acd` metadata/overview and recorded primary-source receipts; produce reproducible dated findings with source/hash identities and a short customer answer. No report schema or hosted endpoint changes.

- [ ] Reconcile latest 14 failures by source group, retained error inventories and observed queue counts; distinguish each denominator.
- [ ] Record observed 199/104/70 affected CVEs, 170/16/55 affected advisories and 159/6/6 remediation publications as pre-implementation live evidence, never as complete vendor totals or customer upgrades. Retain separately dated historical year grouping when current grouping is unavailable.
- [ ] Explain Cisco one-link correction and SA-0226 no-affected-CVE control using actual replay receipts. Separate local implementation from live state.
- [ ] Answer the customer's three questions with bounded conclusions and testable explanations, no assumed Glasswing causality or concealment. Explain global 44/47 benchmark vs switching sample and link the pending blind human review packet.
- [ ] Verify every numerical statement against cached metadata/replay receipts; no low-impact prose tests. Commit audit/docs after task reviews, then one fresh whole-branch review and full exact-head CI before PR readiness.
