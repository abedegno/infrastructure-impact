# Client cancellation lifecycle implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Make custom client selections complete without retaining cancellation subscriptions for completed token reads.
**Architecture:** Per-operation active-waiter registry with eager settlement cleanup; one abort handler, no ever-growing shared-promise reactions.
**Tech Stack:** Existing JavaScript, Node VM tests, owned headless Chrome QA; no dependencies.
**Spec:** docs/superpowers/specs/2026-11-11-client-cancellation-design.md

## Global Constraints

- Preserve existing300000ms operation ceiling and every byte/depth/working/request/validation limit, results/error identities, cancellation and observer behavior.
- Retain only currently in-flight cancellation waiters; clean success, failure, abort, close and already-aborted paths; no public test-only API or global retention.
- No schema/DTO/normalization/backend/dependency/workflow/scheduling/permission/upload-root changes, private data/log accesses or worker rollout.

### Task 1: Bound client operation cancellation registrations

**Files:** infrastructure_impact/web/publication-v2.js; existing tests/test_publication_v2.js and focused browser-operation tests if necessary.

- [ ] RED bounded resource reproduction through publicstreamTokens: instrument unresolved promise subscriptions in isolatedVM and show growth with completedreads; no timing-only assertion or privateoperationexport.
- [ ] Implement smallest active-waiter lifecycle; every fulfilled/rejected input unregisters, abort rejects only activewaiters, close clears timer/listeners, externalalready-aborted safe. Preserve deadline checks before/after awaited reads and source/stream validation.
- [ ] Tests for bounded subscriptions across many successful reads, failed and pending reads, abort propagation/idempotentclose, expireddeadline and concurrent/nested alias operations. Reuse existing fixture conventions.
- [ ] Run meaningful JS codec/publication/switching/customer tests, formatter/lint/diff; no fullPython suite (rootCI owns).
- [ ] Report exact RED/GREEN evidence, bounded diagnostic benefit, commands/results and limitations, commit scoped files. No live sourcepin/publication operation by worker. Root owns fresh review, fullCI, local actualdata browser regression and ordinary rollout.


### Task 2: Avoid Error allocation for speculative schema mismatches

**Files:** infrastructure_impact/web/switching-contracts.js runtime code only (generated line/bundle unchanged); existing switching contract/publication tests.

- [ ] Reproduce expected Error-constructor growth on valid token/alternative validation through the public contracts API in an isolated VM. Use existing actual schemas and a counter; do not export internal probes.
- [ ] Implement private nonallocating mismatch sentinel/failure handler for matches() probes. Keep public/defaultcheck Error behavior and existing catch/boolean semantics; propagate failure handler through all recursive check calls. No changed validation branches, ordering, constraints, schemas, formats or source semantics.
- [ ] RED/GREEN counter, plus valid/invalid alternative/ref/if/then/else/not/allOf/nestedarray/property and erroridentity/message regressions. Public invalid inputs must throw Error, never sentinel. Keep bigints/Unicode/numeric/format behavior.
- [ ] Run meaningful existing contracts/transport/selection/customer and cross-runtime fixture tests, generated-bundle check, Prettier/syntax/diff. No fullPython suite by worker; rootCI owns.
- [ ] Commit scoped runtimeJS/tests and report .superpowers/sdd/2026-11-11-client-cancellation/task-2-report.md. Root owns fresh review, new two-script localfixture actual0140/0103 QA, fullCI and ordinarydeployment. No production/credentials/private data/network operations.
