# Analysis Loading Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Reuse the current isolated checkout; execute after Pages implementation to avoid shared commits.

**Goal:** Reduce measured decoder, validation and selection work without weakening evidence checks.
**Architecture:** Bounded codec reductions plus a privately cached immutable validated-selector capability and exact membership indexes.
**Tech Stack:** Existing JavaScript/Node, Python test wrappers, no new dependencies.
**Spec:** docs/superpowers/specs/2026-11-25-analysis-loading-performance-design.md

## Global Constraints

- No publication schema, budgets, schedule, permissions, source activation or secret changes.
- Preserve byte/digest/generation/ownership validation, exact numbers, logical/ASCII serialization, cancellation and output ordering.
- Public one-shot selection still validates arbitrary mutable inputs; no trusted boolean option.
- Prepared input is immutable and private; selected outputs remain independently mutable.
- Use cached public data only, outside Git; no customer/private inputs. One heavy benchmark process at a time.

## Review Focus

ASCII escaping still fingerprints canonical Unicode; hash length is actual encoded bytes. Wrong-generation or forged effective cohorts fail on every cached selection. Returned output mutation never changes cached input. Tuple keys never merge vendors, advisories or CVEs through delimiter collisions.

### Task 1: Optimize codec and validated selection

**Own files:** infrastructure_impact/web/publication-v2.js, infrastructure_impact/web/switching-analysis.js; tests/test_publication_v2.js, tests/test_switching_analysis.js, tests/test_switching_analysis_delivery.js and focused Python wrappers if needed. Document measured results in docs/research/2026-11-25-analysis-loading-performance.md. No workflow or collector edits.

- [x] Write failing regressions for prepared immutable selector validation-once, wrong generation and effective-selection rejection on repeated calls, independently mutable outputs, tuple-index isolation, and relevant codec accounting/observer parity.
- [x] Optimize private ASCII punctuation emission, repeated string cost/quote work and hash-update byte accounting; keep incremental digest and all checks, no root-sized new hash buffer.
- [x] Factor selection into private validated implementation and existing public validate-then-select. Add explicit preparation API which validates and deep-freezes input once, captures identity safely and returns a closure rechecking each study. Keep null/unavailable behavior and output ownership. v2 caches that capability instead of performing duplicate whole-root validation.
- [x] Index selected members by exact vendor/advisory/CVE and inference group IDs; preserve original array iteration order, schema/ownership checks and all values.
- [x] Run focused codec, compiled analysis, delivery and reliability tests plus Prettier. Self-review, commit and report. Root performs exact public before/after benchmark sequentially with identical inputs; do not run heavyweight repeated benchmarks while other implementation/tests run.

Report exact red/green results, changes, commits, spec compliance and concerns to
this plan's SDD task report. No subagents, live workflows or deployment changes.
