# Bounded Publication V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement an explicitly opt-in v2 publication that preserves complete evidence and existing query semantics while meeting fixed archive, default-read and site budgets.

**Architecture:** Keep v1 as the default and reuse ordinary v1 cohort parts. Add one shared bounded token codec, an exact-snapshot self-contained archive, mandatory research roots, normalized claim routes, and bounded study readers. Python and browser owners work independently after the contract checkpoint.

**Tech Stack:** Existing Python >=3.11, stdlib codec/monitor, installed jsonschema, existing JavaScript/lossless JSON utilities and Node tests; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-07-publication-v2-design.md`.

## Global Constraints

- Limits: 128,000,000 expanded archive; 8,000,000 gzip; 20,000,000 default reads; 8,000,000 per part; 2,000,000 per index; 1,000,000,000 site bytes.
- Selected materialization <=128,000,000 bytes in the larger canonical/requested encoding; full-root streaming <=1,000,000,000 logical bytes and a 300-second deadline; depth <=64; at most six concurrent fetches; encoded cache <=16,000,000 bytes.
- Preserve all original snapshot fields and all mandatory research facts, IDs, order, literal context, provenance, definition hashes, review limitations and CSV semantics.
- V1 defaults/old generations remain supported; v2 is an explicit local argument/CLI option, never ambient configuration.
- No hosted wrapper/input/pin/schedule/permission/recovery changes, acquisition, merge or activation. No retained replay while implementation is mutable.
- No product implementation before the coordinator freezes this contract. The maintainer waived further user questions; the coordinator resolves interface conflicts directly.

## Review Focus

- A small encoded page can amplify through strings, array counts or alias traversal: reject before materializing output; Task 1/2 expansion tests.
- A valid-looking numeric value can corrupt an identity or ordered hash: preserve large logical integers and numeric lexemes, reject unsafe transport indices; shared vectors in Task 1/2.
- A bundle event may select provenance from a claim whose initial date is outside the selected window: Task 1/2 exact reducer parity fixtures.
- A late detail/query result may belong to an old generation or pending form selection: Task 2 accepted-selection/race tests.
- A passing reduced archive may omit research facts or replace original snapshot fields with references outside itself: Task 1 archive/root closure and candidate parity tests.

---

## Ownership and contract checkpoint

Owner A owns Python, schemas, CLI/staging, monitor, packaging and Python tests. Owner B owns browser modules, generated browser bundle and Node/browser tests. Neither edits the other's files. A owns `checks/generate_switching_contracts.py`; B runs it and owns the generated `web/switching-contracts.js` changes.

A first freezes the three public v2 schemas, v2 context/result schemas, and `tests/fixtures/publication-v2-codec-vectors.json` against the spec. Coordinator checks the small contract diff and supplies it to B; A continues its task while B implements against those files. Later contract changes require one coordinator ruling and matching vector/schema updates, not silent protocol divergence.

### Task 1: Python publication, readers and acceptance (Owner A)

**Create:** `infrastructure_impact/publication_codec.py`; `infrastructure_impact/application/publication_v2.py`; `infrastructure_impact/application/publication_reader.py`; the five v2 schemas specified above; `tests/fixtures/publication-v2-codec-vectors.json`; `tests/test_publication_v2_codec.py`, `tests/test_publication_v2.py`, `tests/test_publication_v2_reader.py`.

**Modify:** `application/publication.py`, `application/static_delivery.py`, `application/switching_comparison.py`, `application/switching_evidence.py`, `application/import_candidate.py`, `application/target_import_stage.py`, `application/target_import_contracts.py`, `http.py`, `cli.py`, `exports.py`, `checks/public_health.py`, `checks/switching_health.py`, `checks/generate_switching_contracts.py`, `checks/distribution.py`, `checks/package_probe.py`, `checks/release.py`, `pyproject.toml`; affected target-import/distribution/HTTP/switching Python tests. CI edits, if needed, only register new tests/lint files in existing jobs.

**Consumes:** The frozen spec and existing public projection, v1 schemas, pure switching semantics and unchanged limits.

**Produces:** `PublicationReader` and codec interfaces from the spec; `build/publish/write_bundle/stage(..., publication_format="v1")`; `verify/validate_result(..., publication_format="v1")`; closed v2 catalog/index/archive/overview; standalone byte-identical codec; local streaming export CLI. Runtime root derivation is exact and explicitly typed.

- [ ] Write shared vectors and failing codec tests: astral UTF-8; duplicate keys/layouts; null vs missing; 1 vs 1.0; negative zero/exponents; >2^53 logical identity; unsafe/Boolean indices; nonfinite or malformed numbers; missing/overlapping routes; forbidden alias/path/generation; tiny references exceeding decoded/selected bounds before allocation.
- [ ] Run `uv run pytest tests/test_publication_v2_codec.py -q`; demonstrate the intended missing-code/guard failures. Implement the pure-stdlib codec and freeze the schema/vector checkpoint for B.
- [ ] Write failing publisher/stage tests: v1 unchanged by default and hostile ambient settings; explicit v2 reaches a closed matching context/request/result; mismatches reject; producer never writes giant v1 sidecars before conversion; exact self-contained snapshot and all mandatory research roots survive; normalized routes recover every original interval; any archive/default/site limit fails closed.
- [ ] Implement direct v2 writing and ordinary-part reuse. Add runtime root, overview/detail bindings, catalog and scoped archive. Keep all full research roots mandatory and preserve CSV bytes. Add local format/export flags without editing hosted entrypoints.
- [ ] Write reader/reducer tests that compare v1 and v2 summary JSON and CSV for vendor/all vendors, both scopes, year/pre/post/undated/all windows, null/empty/custom CVEs, explicit evaluation clocks, stale/unavailable KEV, drafts, conditionality, score validation and conflicting bundle dates. Assert every selected nested source survives. Test the private projection as a distinct type, never a fake v1 claim. Add a >128 MB whole-runtime fixture where metadata/health and a small-CVE query still work without eager global reads; a product outside the selected cohort must still contribute the correct precomputed global context. Cover ASCII expansion and shared alias byte/deadline exhaustion.
- [ ] Extract shared pure reducer work and implement metadata-only store/open plus route/cohort-first bounded reader/HTTP paths. Keep full legacy JSON export/state fields through streamed reconstruction; do not expose an incomplete runtime projection under a promised full-v1 response. Add 25-item complete diagnostics/detail cursors and streaming full-root CLI export.
- [ ] Update default/archive monitors and complete-candidate verification to branch on explicit format. Verify all catalog roots, whole-snapshot parity, runtime derivation and exact native/static CSV; retain all existing pass conditions. Install the canonical codec beside the standalone monitor by force-include and check byte identity/missing-file failure.
- [ ] Run the new Python modules plus affected `test_static_delivery.py`, `test_target_import_candidate.py`, `test_target_import_stage.py`, `test_target_import_cli.py`, `test_target_import_contracts.py`, `test_target_import_distribution.py`, `test_switching_comparison.py`, `test_switching_monitor.py`, `test_current_evidence_delivery.py` and existing HTTP tests selected by actual changes. Run relevant Ruff/format and one installed standalone-monitor/codec smoke. Do not repeat the unrelated release matrix.
- [ ] Commit this reviewable task and request one fresh scoped review of codec bounds, archive scope, opt-in isolation, semantic parity and packaging. Resolve concrete findings before integration.

### Task 2: Browser bounded delivery and existing detail UI (Owner B)

**Create:** `infrastructure_impact/web/publication-v2.js`; `tests/test_publication_v2.js`.

**Modify:** `web/lossless-json.js`, `web/delivery.js`, `web/switching.js`, `web/switching-view.js`, `web/app.js`, `web/switching-contracts.js`; `tests/test_switching.js`, `tests/test_switching_ui.js`. Coordinate any newly required browser asset inclusion with A; A owns publisher/packaging edits.

**Consumes:** A's frozen schemas/shared vectors and the exact `InfrastructurePublicationV2.open`/loader method signatures in the spec. B must not modify schemas or Python code to accommodate a divergent browser representation.

**Produces:** Strict bounded v2 decoding, existing loader's v2 branch, overview/default KEV reevaluation, streamed query selection with exact v1 summary/CSV output, and generation-bound paged details. V1 loader behavior stays intact.

- [ ] Add failing Node vector tests consuming the same JSON fixtures as Python. Cover duplicate-key strict parsing, malformed Unicode, exact numeric identities/lexemes, nonfinite values, index types, route recovery, alias location, stream truncation, mixed generations and per-page/materialization overflow before object creation.
- [ ] Run `node tests/test_publication_v2.js`; implement bounded fetch/parser/table/token/range readers with six-request concurrency and 16 MB encoded-cache eviction. Add a strict mode/export to existing lossless JSON code rather than forking it or changing v1 number handling incidentally.
- [ ] Add failing v1/v2 query-parity vectors matching A's option/clock cases. Extract browser pure reducer entrypoints shared by legacy full input and validated private projection. Replace v2's full `switchingReport()` hydration with `switchingSelection()`; do not reconstruct 400 MB inputs to call the old API.
- [ ] Add default overview/KEV, ordinary cohort and explicit whole-archive runtime-root tests. Preserve all non-study fields and complete comparison denominators. Default overview must not trigger full claim/detail downloads. A >128 MB whole runtime must not break default/small-cohort views; only the explicit whole-view request may fail its bound or offer streamed export. Include requested-encoding expansion and stream timeout/cancellation tests.
- [ ] Add UI tests for existing 25-item pagination through all pages, full diagnostics via loader callback, old-generation rejection, stale async replies, changed controls during pending requests, and accepted-selection downloads. Keep pending selections from changing the displayed/exported accepted report.
- [ ] Update `app.js` and `switching-view.js` callbacks. Label summary/overview JSON accurately and expose the complete fact catalog/CLI export route; remove the false “complete inputs” label for summary exports. Preserve counts, source traceability and review language.
- [ ] Regenerate `web/switching-contracts.js` using A's generator/schema changes. Run `node tests/test_publication_v2.js`, `node tests/test_switching.js`, `node tests/test_switching_ui.js` and affected browser/delivery checks; run formatting on changed JS only.
- [ ] Commit this reviewable task and request one fresh scoped review of wire agreement, bounds, query parity and UI generation races. Resolve concrete findings before integration.

## Coordinator integration and completion

- [ ] Verify both owners' shared-vector results and reviews. Run one focused cross-language suite using the same generated v2 publication: default overview, exact archive export, complete root/claim/record preservation, all query JSON/CSV cases, details/diagnostics, v1 compatibility and tamper rejection. Check total default bytes with actual reads, not the private proof's estimated read set.
- [ ] Run one combined installed-package/standalone monitor check and byte-identity inventory check, including the new codec/browser assets. Have one fresh reviewer inspect cross-owner contracts and complete-candidate gates; do not repeat two full task reviews.
- [ ] Freeze final Python, schemas and browser bytes. Run the existing retained-evidence laboratory exactly once with explicit v2 format and no new acquisition. Require complete audit/native parity, default monitor, archive monitor, all physical/logical hashes and all size limits. Keep diagnostics and fail honestly if any gate fails.
- [ ] Record the exact input scope, generation, code/asset hashes, bytes, checks performed/unperformed and remaining hosted-union limitation. Prepare a separate reviewable PR stacked on PR38; no merge or hosted activation follows automatically.
