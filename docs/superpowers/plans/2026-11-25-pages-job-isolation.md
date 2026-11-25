# Pages Job Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Reuse the isolated feature branch.

**Goal:** Preserve accepted-artifact publication while removing immediate same-job Pages discovery.
**Architecture:** Upload in the producer/verification job; deploy and verify health in a separate dependent job guarded by successful accepted upload and pinned identity outputs.
**Tech Stack:** GitHub Actions YAML and existing Python workflow simulation tests.
**Spec:** docs/superpowers/specs/2026-11-25-pages-job-isolation-design.md

## Global Constraints

- No schedules, permission declarations, secrets, source activation, recovery limits or producer acceptance policy change.
- Use existing pinned official actions and artifact name; no third-party action, dependency or private runtime API.
- Keep preview unable to publish, authenticated failure cleanup and legacy/helper compatibility.
- Workflow concurrency spans both jobs. Preserve all previous receipts and verifier code.
- No customer data, private captures or credentials in repository, reports or logs.

## Review Focus

Failed collection, preview, failed cleanup or missing upload output must not enable deployment. Health source/generation must be pinned to the accepted producer rather than mutable variables. Tests evaluate the job dependency as well as producer step gates.

### Task 1: Separate accepted upload from Pages deployment

**Own files:** .github/workflows/collect.yaml, .github/workflows/pages-redeploy.yaml, relevant tests/test_hosted_maintenance.py, tests/test_hosted_workflow_protocol.py, tests/test_pages_redeploy_workflow.py; new tests/test_pages_job_isolation.py and short operations documentation if needed. Do not edit product JS or collectors.

- [ ] Read both workflows and acceptance/compatibility tests. Write failing regressions for dependent deployment and output guards first.
- [ ] Ordinary workflow: capture validated source commit from the source-pin check; give accepted upload a stable step ID. Export readiness only for successful upload and a nonempty artifact ID. Require successful producer and readiness for deployment. Preserve upload's entire accepted-publication condition. Check out captured source without credentials in deployment job; configure, deploy and run existing health there. Keep protected environment on both jobs, URL on actual deployment job.
- [ ] Recovery workflow: retain receipt verification and upload together; export upload readiness and verified generation. Move configure/deploy/default+archive health into a dependent job. Health uses workflow revision and verifier generation. No receipt pins change.
- [ ] Adapt test helpers for producer steps versus deployment job conditions; do not weaken failure, preview, cleanup or mixed-revision safeguards. Test missing/empty ID, failed producer, preview, accepted upload and exact source/generation propagation.
- [ ] Run focused workflow/protocol/recovery suites, formatting and source privacy checks. Document evidence and limits, commit small changes and self-review.

Report spec compliance, changed files, exact commands/results, red/green evidence,
commits and concerns. Do not spawn subagents or dispatch collection/change live variables.
