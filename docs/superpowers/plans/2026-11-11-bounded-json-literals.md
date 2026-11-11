# Bounded JSON literals implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Reduce proven repeated string serialization CPU while preserving exact v2 byte identities and every gate.
**Architecture:** One small bounded pure-literal cache per stream/writer invocation; aliases share the invocation budget-owned cache. Validation and byte/deadline accounting remain per occurrence.
**Tech Stack:** Existing stdlib Python/pytest; no dependencies.
**Spec:** docs/superpowers/specs/2026-11-11-bounded-json-literals-design.md

## Global Constraints

- At most4096entries and1048576 retained encoded payload bytes; no global cache or per-alias multiplied cache; oversized entries not retained.
- Exact UTF8/ASCII/DEL/control/Unicode output, observer calls/bytes, tokens, ranges, hashes and numeric lexemes unchanged.
- Every validation, cost/deadline/budget check and observer invocation remains effective on cache hits; no schema/DTO/source/gate/deadline/budget changes.
- Exact built-in strings only; subclasses/nonstrings preserve old serialization. No private configs/vault/keys/raw worker logs/sourceHTTP/rollout by workers.

### Task 1: Bounded literal cache and writer/reader integration

**Files:** infrastructure_impact/publication_codec.py, application/publication_v2.py, focused codec/publication tests (existing fixture conventions). No workflow or web schema changes.

- [ ] RED tests for repeated string encodings using call counters (not timing assertions), byte-identical logical/ASCII streams, observer bytes and invocation counts, aliases and hit deadline/byte rejection.
- [ ] Prototype a bounded authored repeated-string stream benchmark; compare unchanged/reference output digest and CPU/calls, <=110second owned processes. Report benefit before proceeding if absent.
- [ ] Implement smallest bounded cache; count bytes/entries under eviction, oversized passthrough, one context shared across aliases. Preserve existing Budget/NodeBudget positional/caller compatibility.
- [ ] Integrate reader quoted values only AFTER existing peroccurrence charge; integrate writer string keys/leaf strings while leaving other primitives/numeric lexemes unchanged. Preserve existing output hashes and observers.
- [ ] Tests: eviction/count caps, oversized strings, no global retention, alternate modes, Unicode/DEL/control/escaping, aliased budgets, cached-string deadline exhaustion and unchanged fixture digests; run adjacent meaningful codec/v2/hash/reader suites and lint/format/diff.
- [ ] Save bounded authored and cached PUBLIC diagnostic measurements, commit scoped code/tests; no fullsuite repeat. Root owns independent review/fullCI/retained acceptance. No assertion timeoutfixed until actualfullreceipt.
