# Precomputed Analysis Preview Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development. One implementer owns the tightly coupled native/browser delivery; parent runs real-data measurements and integration. Standing user approval/opt-out permits continuous execution without another design gate.

**Goal:** Faster common selected views without scientific or export changes.
**Architecture:** A disabled writer flag emits independent gzip slices of exact native selected DTOs plus a small manifest, readable without global dictionaries; custom selections retain the compiled reader. Native source authority and independent regeneration remain mandatory.
**Tech Stack:** Existing Python, JavaScript, gzip and SHA-256 only.
**Spec:** docs/superpowers/specs/2026-11-26-precomputed-analysis-design.md

## Global Constraints

No dependencies, advisory schema changes, scientific inference, private data,
customer strings, budget increases, hosted activation, schedule/permission/secret
changes or PR #90 merge. Keep existing limits: 8,000,000 bytes per physical part,
128,000,000 decoded selected bytes, 16,000,000 raw cache bytes, 1,000,000,000 site
bytes. Raw slices are 4,000,000 bytes, except the last.

## Review Focus

- Advertised corrupt views fail instead of silently falling back; legacy and custom views retain their existing behavior.
- Gzip bombs, truncated members, wrong totals, wrong offsets, duplicate option keys and Unicode/token splits fail under fixed aggregate limits.
- A valid self-hash cannot replace freshly derived native source authority; legacy dictionary/root descriptors remain unchanged.
- Direct selected acceptance validates all children, ownership and requested output size; returned mutation cannot poison cached or concurrent results.
- Shared cold/warm work keeps independent caller caps, cancellation, last-waiter abort, deadline and reliable retry without an unbounded prepared-view cache.

### Task 1: Disabled precomputed delivery and reader

**Files:** new application/analysis_precomputed.py, web/analysis-precomputed.js,
tests/test_analysis_precomputed.py/.js, docs/ANALYSIS_PRECOMPUTED.md;
modify application/publication.py, publication_v2.py, publication_reader.py,
switching_analysis.py (private validated selection factoring only if needed),
web/publication-v2.js, switching-analysis.js, necessary asset registration.
README, changelog and research receipts belong to the parent.

**Interfaces:** `ROOT='switching-analysis-selected.json'`;
`write_views(destination, source, options=None)` validates source;
private `_write_views_validated(...)` is writer-only after its fresh authority
gate; codec/helper for encoding an already selected candidate for local tests.
`validate_manifest(manifest, identity)`; `read_selected(directory, manifest,
study, max_bytes=...)` for native parity. Browser module exports
`InfrastructureAnalysisPrecomputed` with closed manifest validation, bounded
chunk assembly/decode and selected acceptance. Both public bundle writers accept
`analysis_precomputed_delivery=False, analysis_precomputed_options=None`.
Use `PublicationReader.switching_analysis` / browser `switchingAnalysis` for
eligible views, with unchanged fallback.

- [ ] Write RED fixtures for literal chunk/manifest encoding, native selection/export equality, strict flag behavior and native authority regeneration. Preserve native map order and browser-specific outer facts order separately.
- [ ] Implement deterministic gzip chunks and manifest logical root plus content-addressed plain-manifest sidecar; ensure default roots/partitions identical. Add private source-validation reuse only where immediately dominated by the existing writer gate.
- [ ] Add check-only selected validation using current upgrade integrity checks, parent/child identity/cohort and all component schemas. Test exact browser JSON strings and both CSVs on rich fixtures, fractional CVSS, large IDs and omitted/unknown states.
- [ ] Add reader with no dictionaries/source fetch for eligible views. Prove forged descriptors/metadata/children, ZIP bombs, corrupt CRCs, concatenated/truncated gzip, Unicode boundaries and byte caps reject. Verify missing/unsupported-view fallback and advertised-view failure.
- [ ] Test one prepared-view cache, result mutation isolation, both waiter orders, lone-small cap, warm-small cap, deadline, last-waiter cancellation and retry. Wire the Node harness into normal pytest CI.
- [ ] Run focused tests, lint/format, self-review; commit and report RED/GREEN evidence and precise limitations. Parent may start a four-view candidate proof as soon as the browser interface is stable, before any expensive full writer run.

### Task 2: Real-data gate, documentation and review (parent)

- [ ] Use already verified public generation e05fc9e8e5ce404190173f4c3c037498; no vendor download. Initial native size feasibility and baseline selection checks precede transport implementation.
- [ ] Generate four local candidate views, compare native output and production browser fallback exact selected JSON/two CSVs, measure matched fresh-process cold/warm time, traffic and RSS. Keep diagnostic and benchmark work separate.
- [ ] If useful gain is absent, stop at a documented nonactivatable experiment. If present, reconstruct public projection and run the existing full writer/source gate plus independent native verification once, with the four explicit pilot choices; measure archive-inclusive current-preview size and mark unavailable historical inventory honestly.
- [ ] Task review, consolidated fixes, whole-branch review; full tests once after product fixes, public source export and standard checks. Publish a reviewable draft PR with measured results; hosted changes require a separate final decision. Preserve the old packing experiment unmerged.
