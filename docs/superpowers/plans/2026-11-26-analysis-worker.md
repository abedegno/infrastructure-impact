# Responsive Analysis Worker Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development. Standing user opt-out and preserved execution preference allow continuous execution.

**Goal:** Remove the precomputed analysis main-thread freeze and reduce temporary export allocations without changing selected bytes.
**Architecture:** One tightly coupled implementation task owns the immutable worker bundle, bounded bridge, reader lifecycle and async exports. Parent owns real-data browser/capacity verification and reporting.
**Tech Stack:** Existing Python/JavaScript, Worker, structured clone, transferable buffers, Node worker_threads; no dependencies.
**Spec:** docs/superpowers/specs/2026-11-26-analysis-worker-design.md

## Global Constraints

No scientific, advisory schema, source membership, native wire/format, inference,
dependency, budget, schedule, permissions, secrets or hosted activation changes.
Use public cached/synthetic inputs only; no .env, private artifacts or vendor
contact. PR90 stays unmerged. Physical parts stay <=8,000,000 bytes; selected and
export bytes <=128,000,000; raw cache <=16,000,000; site <=1,000,000,000. Existing
per-caller smaller limits, cancellation, deadlines and reliable retry apply.

## Review Focus

- Shared cold preparation survives a cancelled/small first caller; last-interest cancellation really stops worker and transport work.
- A queued read/export remains bound to its original prepared view despite a different view replacing the cache.
- Transfer never detaches cached raw bytes; received DTOs and download buffers never alias cache or each other.
- The worker asset is generation-bound under root/nested base paths; foreign/stale replies and configured failures reject rather than downgrade checks.
- Native and browser JSON/twoCSV remain exact across Unicode, BigInt IDs, fractional metrics, formula cells and tight output caps.

### Task 1: Bounded worker reader and exports

**Files:** Create web/analysis-worker.js (worker protocol), web/analysis-worker-client.js (bridge); modify web/analysis-precomputed.js only for safe worker access to its validated prepared value, web/publication-v2.js for eligible reads/exports/lifecycle, web/switching-analysis.js for lazy CSV rows, web/app.js for async accepted exports, application/publication.py for immutable opt-in worker assets. Add tests/test_analysis_worker.py/.js and amend relevant existing asset/UI tests. Canonical web files live under infrastructure_impact/web; root web is a symlink. Update operator guide with actual interfaces.

**Interfaces:** Existing `reader.switchingAnalysis(study, options={})` remains unchanged, returning independent mutable complete selected DTO. Add `reader.switchingAnalysisExport(study, format, options={})` returning encoded Uint8Array for json/csv/upgrades-csv. Return null only for an unsupported/unmatched export route so the UI can deliberately use its existing fallback; configured failures throw. Worker bridge exact internal signatures and lease protocol are implementer-owned, documented in its report. No external arbitrary worker URLs/functions. Preserve Python/native transport.

- [ ] Write failing real-worker and fault tests covering spec/review focus; run RED. Use worker_threads shim, no package installs.
- [ ] Build immutable self-contained classic-worker bytes from existing modules, load client only for the opt-in preview, and pin its worker URL in script metadata. Root/nested base tests, source export inclusion, worker syntax smoke.
- [ ] Implement bounded chunk proxy and owned lifecycle. Keep raw transport budgets/hash/cache/pool, caller caps/deadlines and shared cancellation. Maintain exactly one retained prepared view and safe read/export leases through cache eviction. Test disposed/crashed/retried/late replies and generation mismatch.
- [ ] Return structured-cloned independent DTOs, not serialized JSON to reparse on main. Worker validates every accepted caller's study/definition/cap. Unsupported Worker retains existing path; configured worker faults stay visible. Prove legacy/custom readers unchanged.
- [ ] Make CSV row expansion lazy and worker export encode/transfer exact bounded bytes. Async UI handler captures the clicked accepted study/loader, reports failure, and uses explicit fallback only when unmatched. Check all three download bytes and mutable-result isolation.
- [ ] Run focused RED/GREEN tests, Ruff/Prettier/whitespace and self-review; commit. Report early when the real-worker/asset path is ready so parent can perform a cheap real-browser gate before full native generation. Full suite belongs to parent after review fixes.

### Task 2: Browser gate, native capacity and final review (parent)

- [ ] Reuse pinned public generation e05fc9e8e5ce404190173f4c3c037498; no vendor downloads or private evidence. Refresh assets in an isolated derivative before the early browser proof; preserve the preceding verified preview/receipts.
- [ ] Measure actual Cisco/2025 cold/warm UI and worker byte-download route; other three accepted contexts through production reader. Observe long tasks and heap, separate observer/export overhead, compare all12 export hashes. If no useful responsiveness gain, document failed gate without spending full-generation time.
- [ ] After useful gain, run one complete eight-view native publication with explicit All/Cisco/Aruba/Arista x all/2025 options from cached source projection. Independently verify the same source and explicit options, inventory archive-inclusive size and accepted hosted historical inventory if retrievable. Mark unavailable coverage honestly.
- [ ] Complete task review/fixes and one whole-branch review; run full regression once after product fixes, normal checks and public source export. Update research/docs and draftPR91 with measured outcome/remaining gates; no merge or activation.
