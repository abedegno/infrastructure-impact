# One-off switching activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Activate exactly the approved switching evidence without changing main workflows or disclosing the private vault.
**Architecture:** Operational source branch, one package helper and a narrow hosted-job entry hook; reuse all stock staging/validation/backup/deployment gates.
**Tech Stack:** Existing Python/pytest, encrypted GitHub draft recovery, main collect workflow and publication v2.
**Spec:** docs/superpowers/specs/2026-11-09-switching-activation-design.md

## Global Constraints

- No original operator sources configuration, private local vault or key reads. Tests use packaged public sources and authored synthetic fixtures.
- Real restored vault/key remain runner-only; no raw worker logs or plaintext artifacts downloaded/uploaded.
- No workflow, schedule, permissions, frozen study, capacity, validator or from_manifest relaxation.
- Keep ordinary hosted_job.main behavior unchanged. Operations source branch is not merged into main.
- Existing full candidate validation and remote backup/readback precede publish_ready.

## Review Focus

- Unknown/duplicate profile controls fail before any mutation.
- Stale accepted recovery, record content or operations source changes invalidate preview.
- Wrong source hash/CVE or missing expected record cannot promote recovery.
- Source-only bundle never becomes an advisory; existing record/capture history stays intact.
- A failed candidate, oversized result or failed backup cannot emit publish_ready.

### Task 1: Closed preview/apply activation helper

**Files:** Create infrastructure_impact/application/switching_activation.py and tests/test_switching_activation.py; modify ops/hosted_job.py entry dispatch only. Controller owns spec/plan/ledger.
**Interfaces:** PROFILE_ID = `switching-readiness-2026-11-09-v1`. Existing collect workflow supplies --state-dir, --output, --base-path, --encrypted-state, --schedule-utc, --recovery-storage, --recovery-repository, --vault-profile, --publication-format, --maintenance-profile, --maintenance-mode and --maintenance-preview-fingerprint. Require encrypted github-draft, v2, exact profile and explicit preview/apply; honor configured existing vault bound. No new workflow inputs.

- [ ] Write red tests for preview nonmutation and finite metadata, stale binding, unknown/duplicate controls, wrong source hash/CVE, absence of expected Arista HTML, candidate/backup failures and source-only evidence semantics. Use synthetic storage and injected I/O boundaries; include at least one real stock preview/stage integration with authored data rather than only mocked success.
- [ ] Bind preview to stock current-record inventory, accepted recovery manifest bytes, normalizers for cisco/aruba/arista, operations source commit and closed source definitions. Emit format `impact-switching-activation-preview`, schema_version 1, fingerprint and public counts/target metadata only, at output/maintenance-preview.json. Never expose arbitrary record/vendor text or raw keys. Preview performs restore/read only; no vendor requests or accepted-state mutations.
- [ ] Add entry dispatch for this exact profile (both spaced and = flags), rejecting duplicate profile flags before restore. All other invocations call existing main, including stock encrypted-state validation. Do not edit main workflows or protocol constants.
- [ ] For apply, validate preview fingerprint before source preparation. Restore current accepted vault privately, scope environment to temporary home/database/public packaged sources before query imports. Require canonical private database path. Reparse retained Arista `23115-security-advisory-0128` / CVE-2025-8872 and `24847-security-advisory-0201` / CVE-2026-111943 via existing normalized_record/ingest; exact official HTML URLs and stable identity/CVE sets required. Retain original evidence timestamps/history. No other normalization batch.
- [ ] Retrieve Cisco `https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056` once through existing transport (bounded; no redirects beyond existing policy), require SHA256 `3ca993c5411757fe2567f966978c329f54c138b8139231b4d8161201e6563cb2`, validate existing research bundle identity/member evidence, retain source bytes through standard evidence/HTTP observation writer, and create no normalized advisory for it.
- [ ] Construct validated custom TargetImportProfile containing Aruba `ARUBA-PSA-2021-019`, URL `https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-019.txt`, SHA256 `8d1abe635fbabc246c475f22e8ea6ee05c5a09501be1ef9a8b2384aa553b6199`, CVEs sorted CVE-2021-4104, CVE-2021-44228, CVE-2021-44832, CVE-2021-45046, CVE-2021-45105. Capture provenance date is the real acquisition/retained observation; never invent an HTTP observation from replay processing. Obtain original public capture timestamp from controller receipt metadata or use genuine acquisition time if stock stage requires live metadata, documenting distinction. Existing profile constants unchanged (including schema-constant max_http_attempts348), target_count2 including one mandatory retained Cisco anchor, with hard transport attempts2 for the only newly fetched Aruba URL; assert observed target HTTP attempts<=2 before promotion. ERP separately has the same hard2 limit, actual total<=4. No budget/validator monkeypatch and no 174-document reimport.
- [ ] Add the exact already-retained `cisco-sa-dhcp-dos-T3CXPO9z` target from the installed174 manifest as a cache-only anchor (CVE-2024-20259, SHA25612b27df5cfedde1fc0c3f1359c26304e61a5ad8683ab594d5b1a441815fb09d7). Stock preview/result schemas require both vendor fingerprints. Require its identity/capture to exist before staging and its normalized factual content to remain unchanged apart from adapter-version bookkeeping; no network fallback, new exposure or bundle advisory. Both targets sorted; semantic from_manifest/preview validation stays unchanged. Test absent anchor and factual drift fail closed.
- [ ] Use stock target_import.preview (a scoped exact lookup adapter may supply the custom profile) and target_import_stage.stage with accepted internal preview, v2 and existing base path. Stage alone retrieves Aruba once. Keep fresh worker validation/from_manifest unchanged; validate result_bytes with selected profile. Check vault bound. No backup or publication if any gate fails.
- [ ] Use stock hosted.backup_verified on the completed staged database (github-draft store), then copy only its validated public tree to --output, emit mode=apply and publish_ready after recovery_ready. Preview emits mode=preview and preview_ready only. Validate incoming path/output disjointness/size controls like existing helper; sanitize any failure to a closed stage/error code without exception repr or traceback in workflow logs. Preserve failed candidate/acquisition artifacts runner-only; only bounded metadata may enter public stdout/artifact.
- [ ] Run focused hosted protocol/candidate/transport/maintenance tests, new helper tests, CI-scope lint/format, and public release privacy check. Commit only helper/hook/tests; no captures, source state, keys or raw logs. Report commands/results, concerns and commits in the assigned ignored report.
