# Architecture remediation implementation plan

> **For agentic workers:** Use subagent-driven-development task by task. The user approved the architecture review's recommended fixes and order; do not reopen design approval.

**Goal:** Make imports reusable after failure, fix real startup, and reduce measured redundant work before another deployment.

**Architecture:** Retain the existing Python/SQLite/static stack. Separate acquisition from candidate acceptance, bootstrap only selected browser data, and certify reproducible output before promotion. Evaluate representation changes using measured results rather than a new arbitrary size target.

**Spec:** `docs/research/2026-11-08-architecture-review.md` (user-approved recommendations).

## Global constraints

- Preserve source provenance, capture timestamps, hash validation, official-source restrictions and fail-closed candidate/promotion gates.
- Do not read the original local sources configuration, vault or keys; synthetic tests and public saved artifacts only.
- Do not change hosted schedules, permissions, publication controls or activate a deployment without separate authorization.
- Do not publish unaccepted acquisition or private diagnostics. No new dependencies/services without demonstrated need.
- Work in the existing isolated worktree; preserve prior uncommitted fixes. Small commits; do not reset unrelated changes.

## Review focus

- Actual app startup, including static facade, must not load the complete archive before choosing the benchmark.
- Failed candidates preserve downloads without moving accepted recovery/public pointers.
- Retained captures with wrong hashes, URLs or identities never satisfy pinned replay.
- Worker diagnostics must never disclose raw publisher content, credentials or private paths.
- Comparison counts and public API semantics remain unchanged by efficiency changes.

## Tasks

### 1. Correct browser bootstrap

Files: `web/app.js`, `web/snapshot.js`, existing browser test helpers and UI tests, `web/server` metadata route if required. Inspect the existing metadata interfaces before choosing the smallest shared contract.

- [ ] Add a failing actual-app startup regression: first request obtains small benchmark metadata, state request supplies its CVEs, no full-archive state load occurs. Cover metadata failure/retry and normal native behavior.
- [ ] Implement metadata bootstrap using existing catalogue information; preserve unspecified-CVE API defaults and request-race protections.
- [ ] Run relevant JS/UI/native route tests and report red/green evidence; commit only task-owned files.

### 2. Finish bounded worker diagnostics

Files: existing `application/import_candidate.py` and candidate tests changes.

- [ ] Verify pending implementation against timeout/nonzero/launch/success cases and hostile/truncated logs, without raw log forwarding. Preserve receipt shape and gates.
- [ ] Run candidate/transport/phase tests, record results and commit diagnostics separately. Keep the existing minor root-hash experiment separate; do not treat it as the performance fix.

### 3. Durable acquisition and exact replay

Files: focused collection capture-cache module, `application/target_import_stage.py`, target-import CLI/operator integration and tests.

- [ ] Introduce optional acquisition storage outside disposable stages. Store only source bytes plus URL/hash/capture metadata; reuse existing encryption for hosted persistence. Never accept a candidate merely because captures exist.
- [ ] Add failing restart test: acquire targets, reject candidate, resume with network disabled; matching captures replay without HTTP. Test corrupt/hash/URL mismatch, atomic interrupted write and source drift.
- [ ] Use matching retained baseline evidence before HTTP as well. Re-normalize on parser changes; do not invent a new retrieval timestamp for replay.
- [ ] Implement local durable storage and separately test encrypted hosted checkpoint integration without live activation. Preserve accepted-pointer semantics.
- [ ] Run focused transport/stage/hosted/CLI tests and commit.

### 4. Reduce redundant work with measurements

- [ ] Measure acquisition, normalization, projection, verification and resource use from public/synthetic retained inputs; do not rerun a blind hosted publish.
- [ ] Remove proven duplicate traversals while retaining independent semantic checks. Compare shared-fact JSON sharding with the codec before replacement; preserve all public contracts.
- [ ] Run semantic parity and representative real-startup checks; record measured differences and remaining full-hosted certification limitation.

### 5. CI and completion

- [ ] Split frontend/shared packaging from Python compatibility matrix; avoid duplicate push/PR runs while keeping required check contexts. Do not change collector schedules, hosted permissions or publication activation.
- [ ] Run project tests once after all implementation changes, relevant browser tests, lint and distribution checks. Review whole branch, fix material findings, document exact remaining limits.
- [ ] Prepare reviewable commits/PR. No live deployment as part of this plan.

### 6. Prepare opt-in hosted cache wiring (no activation)

- [ ] Add a default-false manual workflow input for acquisition caching and pass the helper flag only for explicit apply opt-in. Scheduled runs remain unchanged.
- [ ] Retain authenticated encrypted acquisition checkpoints on rejected candidates using acquisition_ready, independently of recovery_ready. Validate each separate encrypted acquisition pointer before git retention. Keep every public publication condition, schedule and permission unchanged; mirrored workflow stays identical.
- [ ] Test failed-apply retention, missing/invalid effects, flag restrictions and that acquisition alone never authorizes public upload/deployment. Document opt-in activation and remaining hard-termination limitation. No hosted dispatch or source pin change.

### 7. Prepare full-hosted certification without publication
+
+- [ ] Add an inactive manual workflow template under deploy/ using an explicitly supplied full source commit, contents/actions read permissions, restored hosted evidence and the existing preview/stage CLI. Do not install it under .github/workflows or run it.
+- [ ] Keep accepted recovery/public pointers immutable; no backup promotion, git writes, Pages deploy or runtime-pin changes. Retain only bounded sanitized result metadata and authenticated encrypted acquisition captures; support optional reuse of a previous run's encrypted capture artifact.
+- [ ] Test template guards, read-only permissions, exact profile and isolated paths; document activation as the next separately approved step. This prepares a concrete full-hosted measurement rather than treating local samples as hosted certification.

## Execution disposition

Tasks 1–3 and 5–7 were implemented and independently reviewed. Task 4 retained checkpoint transfer, root verification cleanup, phase instrumentation and measured alternatives; its cloning experiment was reverted after the corrected version measured worse. Duplicate representations and full-state cloning remain limitations. The complete local suite passed 3,711 tests and 12 subtests; installed-wheel, JavaScript, formatting and release checks passed. The inactive full-hosted certification template was neither installed nor run. PR creation/final whole-branch review complete this implementation phase; live activation remains separate.
