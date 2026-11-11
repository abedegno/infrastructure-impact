# Retained-preview diagnostics implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Locate the timed-out preview work without reading private logs or weakening a gate.
**Architecture:** Fixed subprocess driver plus closed safe progress projection and optional code-location sampler; original helper controls acceptance.
**Tech Stack:** Existing Python stdlib/pytest/GitHubActions; no dependency additions.
**Spec:** docs/superpowers/specs/2026-11-10-retained-preview-diagnostics-design.md

## Global Constraints

- No source HTTP, ingest/reparse, private local vault/key/log access, firmware/customer data, source-pin or Pages operations.
- No permission, schedule, upload-root, deadline, byte-budget, schema/DTO, normalizer or source/gate acceptance changes.
- No arbitrary command dispatch, raw logs/exception text, absolute paths, frame locals/globals or function-name exports.
- Partial/failed progress never grants acceptance. Tests synthetic; production runner remains controller-only.

## Review Focus

- Worker emits private stdout/stderr or fake JSON: capture privately; strict allowlist before any notice/artifact.
- Code location outside trusted public files: fixed external sentinel, no path leakage or source/locals access.
- Timeout/cancellation: child cleanup and bounded valid partial diagnostics; never false passed receipt.
- Malformed/oversized/repeated events: reject/drop safely with bounded counts/bytes and no raw echo.
- Existing import/default path and retained acceptance: unchanged, mirrored workflows and40/60minute bounds.

### Task 1: Safe progress driver and retained instrumentation

**Files:** create ops/retained_preview_progress.py and tests/test_retained_preview_progress.py; modify ops/switching_fix_preview.py, both candidate-certification workflow copies, tests/test_candidate_certification_workflow.py, checks/release.py; update rollout method doc.

**Interfaces:** driver runs only the fixed sibling switching_fix_preview.py with existing database/public/output/source-commit args. Worker diagnostic sampling is explicit opt-in only under driver, not a new workflow user input. Expose progress_bytes(value) for fresh <=16384-byte closed progress validation; sanitizer embeds validated retained_progress from private temp progress.json into existing result artifact. Preserve existing receipt_bytes acceptance and CLI behavior when not instrumented. Phase/projector/sample metadata fields must be enumerated, numeric-bounded, trusted-relative module path + line only; keep at most80samples, top3counts and32events. Parent notices and files use the same validated form. Existing helper result file is authoritative; progress never creates or modifies it.

- [ ] RED tests: private stdout/stderr sentinel plus fake events never leaks; known phases/public locations retained; unknown fields/paths/NaN/overflow reject; bounded dedup/aggregation; unsafe/stale/symlink progress paths reject.
- [ ] Implement worker source/audit markers and optional lightweight own-main-thread sampler with no locals/globals/source text. Use trusted public file map/line bounds, external sentinel and fixed total sample bound.
- [ ] Implement fixed driver process, private output redirection, polling/projection/validated notices/atomic progress file, child cancel/kill cleanup and exit status propagation. Preserve source/gate behavior.
- [ ] Integrate retained-only workflow command and sanitizer; no extra upload root or credentials. Tests execute workflow sanitization and input/default guards, both mirrors,40minute step/60minutejob. Add exact release allowlist driver.
- [ ] Run focused progress/helper/workflow/release tests, lint/format/export; commit scoped files and report. No full suite repetition; root CI/review/dispatch owns external gates.

Root also runs an independent read-only public-data performance diagnosis; no concurrent product editor. Merge/dispatch only after tests and fresh review, then diagnose before any functional performance fix.
