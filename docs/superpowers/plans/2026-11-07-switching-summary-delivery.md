# Switching summary delivery repair implementation plan

> **For agentic workers:** Use subagent-driven-development for one cohesive implementation task and a fresh review. The user opted out of further questions and requested continued autonomous work.

**Goal:** Deliver oversized switching summaries losslessly within existing per-part limits.

**Architecture:** Legacy single-part output when it fits; optional ordered string fragments with whole-document byte/hash binding when it does not. Shared contract enforced by publisher, browser and standalone monitor.

**Tech Stack:** Existing Python, JSON Schema and browser JavaScript; no new dependencies.

**Spec:** docs/superpowers/specs/2026-11-07-switching-summary-delivery-design.md

## Global constraints

- Keep 8,000,000-byte parts, 2,000,000-byte index, 20,000,000-byte default monitor and 128,000,000-byte expanded archive limits unchanged.
- No evidence removal, source acquisition, recovery access, merge, hosted dispatch, scheduling, permission, source-pin or dependency change.
- Preserve advisory schema v2, full report/CSV semantics, original capture dates, old source state and unknown/review-pending status.

## Review focus

- Old single-part publications remain readable; both/neither summary forms are rejected.
- Fragment order, missing parts, repeated equal fragments, Unicode and full hash/size are exact.
- Hostile size declarations are bounded before accumulation; actual monitor reads retain their old limit.
- Mixed generation, wrong part type, tampered bytes and rehashed-but-wrong reconstruction fail closed.
- Installed standalone monitor and generated browser contracts ship updated logic without manual forks.

## Task 1: Repair transport and verify affected integration

- [ ] Write authored RED tests exercising the existing >8 MB failure, legacy compatibility and each review-focus case. Avoid adding vendor captures.
- [ ] Implement minimal publisher fragmentation, static-index schema one-of capability, browser lossless reconstruction and standalone monitor reconstruction. Reuse shared helpers only where responsibility is clear. Regenerate browser contracts from their canonical source.
- [ ] Verify affected Python delivery/monitor/contracts/candidate and installed monitor coverage, exact applicable Ruff/format and Node checks. No repeated whole release matrix without a new identified risk.
- [ ] Document the transport capability and actual validation; commit small source/tests/docs changes. Fresh review checks whole fix once.
- [ ] After focused success run one retained-evidence laboratory acceptance with no HTTP observations; keep cache/report diagnostics outside Git. Record actual gate and measurements even on failure; no weakened limits. Update a reviewable PR with the result. Do not merge or activate.
