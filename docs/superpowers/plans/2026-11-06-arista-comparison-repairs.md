# Arista and Comparison Repairs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the reproduced Arista attribution defects and finish validated expanded-corpus switching exports.

**Architecture:** Exact-route Arista parsing/source policy using current plugin and source-selection contracts. Profile-driven local optimizations preserve validation and existing comparison APIs. Controller owns retained-source replay, full supported suites, packaging and real-data acceptance.

**Tech Stack:** Existing Python 3.11/3.13, standard library, jsonschema, SQLite and Node checks; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-06-arista-comparison-repairs-design.md`.

## Global Constraints

- Preserve advisory schema v2, report schemas, public API signatures and frozen study definitions.
- Primary source evidence only; all new tests use authored synthetic source content.
- No automatic model/version matching, ranking, concealment inference or human-review certification.
- No limits/dependencies/hosted configuration/release/activation changes; no private/native inputs.
- Preserve strict validation, call isolation and rejection of mutated/invalid reports.
- Implementers run focused tests; controller runs full suites once on final production code.

## Review Focus

- Reordered tracking paragraphs and foreign/navigation CVEs cannot rebind version lists (Task 1).
- Direct structured entry and changed/missing primary HTML cannot reinstate contradictory scope (Task 1).
- Missing, duplicated or unknown group markers fail visibly instead of carrying scope onward (Task 1).
- Mutated nested reports, equal-looking JSON scalars and duplicate sources retain stock rejection semantics (Task 2).
- An optimized selection cannot mutate/share caller-owned data or certify partial real-data output (Tasks 2/3).

## File Structure

- New focused Arista adapter/source-selection modules if needed; existing `plugins/arista.py` dispatch/fingerprint wiring.
- Synthetic regression tests for those routes and source-selection persistence.
- Existing `application/switching_evidence.py`, `switching_comparison.py` and tightly related helpers only where profiling proves costs.
- Focused scaling/contract tests; documentation, installed probe or CI quality path lists only as needed.
- No schema, frozen resource or hosted workflow behavior edits.

### Task 1: Repair Arista CVE grouping and contradictory representation selection

**Files:**
- Create focused `infrastructure_impact/adapters/arista_reconciliation.py` and/or `plugins/arista_selection.py` if separation is useful.
- Modify `infrastructure_impact/plugins/arista.py`; avoid broad generic-parser changes.
- Test `tests/test_arista_reconciliation.py` plus existing source-selection/fingerprint/Arista suites.

**Exact reviewed routes:**
- SA-0099 HTML: `https://www.arista.com/en/support/advisories-notices/security-advisory/19862-security-advisory-0099`.
- SA-0103 HTML: `https://www.arista.com/en/support/advisories-notices/security-advisory/19917-security-advisory-0103`.
- SA-0103 advertised CSAF: `https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_103.json`.
- Literal CSAF tracking ID: `Arista Networks Security Advisory 103`; its observed wrong CVE is `CVE-2023-5501`, not an alias for `CVE-2024-6858`.

**Interfaces:**
- Consume current `parse(raw,url,vendor)`, `resolve_document(db,url,vendor,fetcher=...)`, SourceSelection/SourceView/SourceViewIssue contracts.
- Produce normal advisory-v2 records and existing persisted source-selection metadata; no new public fields.

- [ ] Step 1: Author minimal RED fixtures for SA-0099 with two tracking paragraphs, EOS group markers and distinct six/eight lists. Assert exact CVE/list bindings, reversed header order, local locators and no unrelated-page attribution. Unknown/missing/foreign grouping and cross-heading state must fail closed.
- [ ] Step 2: Add RED SA-0103 HTML/advertised-CSAF fixtures: differing CVE scopes in draft/final alternates, four HTML ranges, matching representation controls, changed IDs/routes and alternate HTTP/JSON failure. Start from both exact URLs; assert selected HTML bytes/hash/identity, bounded alternate issue and no CVE/versions merge.
- [ ] Step 3: Add collection/persistence and direct-source replay regressions; prove the contradictory structured view cannot overwrite corrected HTML or create a fresh wrong primary identity. Include existing single/grouped parser compatibility and plugin fingerprint coverage.
- [ ] Step 4: Run focused tests RED, implement the narrow adapters/policy, then GREEN. Preserve existing source IDs; direct-CVE normalization must never rename 5501 into 6858. Fail visibly on unreviewed identity changes.
- [ ] Step 5: Run touched Ruff/format checks and relevant existing Arista/source-selection/fingerprint suites. Record commands/results and commit the complete focused repair.

### Task 2: Profile and optimize expanded switching comparison without weakening contracts

**Files:**
- Profile artifacts outside Git.
- Modify demonstrated hotspots in `infrastructure_impact/application/switching_evidence.py`, `switching_comparison.py` or focused helpers only.
- Test `tests/test_switching_scaling.py` plus existing switching contract/writer-scaling suites.

**Interfaces:**
- Existing `inputs`, `score_inputs`, `project`, `validate_evidence`, `validate_comparison`, `build_report`, `select_report` signatures and report shapes remain unchanged.
- Consume Task 1 corrected plugin behavior; produce equivalent fully validated JSON/CSV reductions.

- [ ] Step 1: Use explicit public-only backfill DB paths and phase/stack/operation profiling to separate extraction, score handling, projection, validation and reduction. Reproduce a bounded synthetic hotspot before selecting a fix. Report any architecture-changing need before implementation.
- [ ] Step 2: Add RED deterministic work/operation tests for the measured cost; compare accepted/rejected results with stock/reference behavior on malformed nested values, duplicate sources, changed generation/hashes, count/claim tampering and prior-success-then-mutation. Add input/output mutation-isolation controls.
- [ ] Step 3: Apply minimal local algorithm/index/materialization improvements, retaining all source evidence, strict validations and caller isolation. No unsafe long-lived cache, skipped validation, changed selection semantics, new prepared-report API or raised bounds.
- [ ] Step 4: Run focused scaling/contract/comparison/writer suites GREEN and touched quality checks. Document actual scope and phase measurements; commit.

### Task 3: Retained-source acceptance, real comparison, verification and PR

**Files:**
- Dated concise research observations under `docs/research/` and operator guide/CHANGELOG updates as appropriate.
- Distribution/CI quality path wiring for new modules/tests when needed; no hosted execution changes.

**Interfaces:**
- Consume corrected parsers/source policy and unchanged typed switching reducer from Tasks 1/2.
- Produce source-bound replay receipts and complete or explicitly failed JSON/CSV exports outside Git.

- [ ] Step 1: Controller replays original Arista captures offline into a new isolated public stage. Verify 27890→six,27892→eight,6858→four expressions and that mismatched 5501 remains alternate evidence only. Preserve older operational stages and pending human review.
- [ ] Step 2: Rerun the entire retained public corpus with phase logs and immutable input hashes. Export one all-vendor JSON/CSV pair for each of nine windows (all/pre/post/2021..2026) at each of two scopes (os_family/model_qualified): 18 pairs. Validate exact schemas/semantics, CSV counts/provenance, original input immutability and deterministic repeated representative selections. Do not use per-vendor repetitions as a benchmark.
- [ ] Step 3: Record method, timings, source gaps and any unresolved model/coverage caveats in dated observations. Known source defects are corrected-source evidence, not disclosure-quality claims. No full archive or patch burden conclusion without its evidence.
- [ ] Step 4: Controller runs full Python 3.13 and clean-export Python 3.11 suites, exact CI quality/Node checks, source privacy/fixture checks and installed wheel/plugin/resource probe. Dependency exports stay byte-identical.
- [ ] Step 5: Fresh task review and most-capable whole-branch review, fix/re-review if required, then push/create PR and check exact-head CI. Preserve operational evidence outside Git. No implementation merge/release/activation.
