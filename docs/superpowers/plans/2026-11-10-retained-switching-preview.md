# Retained switching publication preview implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Verify actual retained switching fix evidence and a full rebuilt publication without fetching or rewriting history.
**Architecture:** A single offline ops helper behind a default-off certification workflow input; reuse the existing full-publication gates.
**Tech Stack:** Existing Python/pytest/GitHub Actions/v2 reader and monitor.
**Spec:** docs/superpowers/specs/2026-11-10-retained-switching-preview-design.md

## Global Constraints

- No source HTTP, ingestion/reparse, recovery promotion, Pages publication or variable changes in preview.
- No original operator config, private local vault/key/logs, firmware or customer data access. Tests use synthetic bytes and keys only; production restore stays on runner.
- Existing permissions, schedule, byte limits, default certification behavior, schemas/DTOs and frozen studies stay unchanged.
- Only bounded closed metadata leaves the preview step; source bodies, raw exceptions, paths and normalized records remain private.
- Human evidence review stays pending. Runtime activation is a separate controller operation after successful preview.

## Review Focus

- Absent/latest mismatched representation: fail without fetching or choosing unrelated evidence.
- Fix-only drift/truncation/conflict: preserve affected fields and make unresolved states visible.
- Preview database writes or accidental collection: fail database preservation/network/ingestion tests.
- Forged/oversized/unknown-field metadata: sanitizer rejects, never dumps the file.
- Default workflow import and new retained mode isolation: mirrored files, old inputs and permissions unchanged.

### Task 1: Offline helper, certification mode and operational documentation

**Files:** create ops/switching_fix_preview.py, tests/test_switching_fix_preview.py; modify .github/workflows/candidate-certification.yaml and deploy/github-candidate-certification.yaml, tests/test_candidate_certification_workflow.py; add docs/rollouts/2026-11-10-switching-fix-activation.md.

**Interfaces:** helper preview(database,public,source_commit) returns a closed ordinary dict; receipt_bytes(value) validates/encodes <=65536bytes; CLI --database --public --output --source-commit writes a new metadata file, returns nonzero for failure. Database/home/settings must be established before imports. Source list is trusted packaged registry only; no caller manifest/URL. Source metadata includes vendor/advisory/source URL/SHA/retrieval and bounded old/new counts plus affected_fields_unchanged. Include network_requests0, revisions_written0, database_unchanged, outcome/failure_code, source_commit, candidate gate facts and compact full-cohort vendor counts. No raw fields. Use existing actual retained-source chronology and source-format matching; no assumed current raw hash from local recon. Hash actual bytes and require registry-owned fix acceptance, or report drift/missing failure. Feature baseline disables only apply_csaf and arista_assessments; document this is not a whole historical runtime reproduction.

- [ ] Add failing authored tests for source positives, missing source, wrong identity/hash,accepted known0140 fixed-only/preserved truncation plus rejected copied links/changed scope/other truncation, source-only drift and unchanged affected fields; use small synthetic inputs/monkeypatch trusted registry where needed, do not refetch real sources.
- [ ] Implement helper with fresh per-invocation validation; reuse publication.build(read-only), audit, publication_v2.inspect_bundle/native_parity and existing import_candidate._monitors. Freeze evaluation clock as worker does; preserve database hash. Fail closed on any gate failure. Use loopback only for existing monitor, no vendor transport. Tests guard collection/ingest/reparse/network calls.
- [ ] Add retained_only boolean defaultfalse. Validate prior captures conflict before restore. Guard old import/capture steps with !retained_only; retained step receives no GH_TOKEN/IMPACT_STATE_KEY. Sanitize new receipt with helper receipt_bytes before embedding in candidate-certification-result; unsafe metadata yields bounded invalid status. No new upload roots or permissions.
- [ ] Add executed workflow tests for true/false/default modes, malformed/oversized receipt/private sentinel rejection, no captures/promotion/publication steps and mirrored equality. Keep existing certification tests green.
- [ ] Document corrected no-reparse rollout, exact input/commands/metadata contract and pending activation steps. Run focused helper/workflow/hosted/v2 tests, lint/format/diff, commit/report.

Controller owns fresh whole-branch review, broad gates, PR/merge, hosted dispatch, bounded artifact inspection, source-pin activation only after idle/pass and final live verification. No helper implementer may access production state or dispatch workflows.
