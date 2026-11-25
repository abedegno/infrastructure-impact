# Switching release signals implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Collect public release-signal evidence into a separate research dataset, report train/year observations and annotate existing upgrade targets without implying vendor reliability.

**Architecture:** A standalone versioned JSON evidence store keeps complete document revision metadata and normalized facts; raw documents remain operator-local. Pure analysis produces JSON/CSV and conservative staircase annotations. An optional static research page reads generated reports locally; hosted sources and publication activation remain unchanged.

**Tech stack:** Python standard library, existing jsonschema and release-order helpers; plain JavaScript/HTML; pytest and Node tests.

**Spec:** docs/research/2026-11-25-release-signals-feasibility.md (approved by “Proceed”).

## Global constraints

- Public sources only; no login scraping, challenge bypass, credentials or customer data.
- No full vendor documents in Git. Fingerprints must identify actual retained bytes or explicitly labelled rendered captures.
- Source URL, locator, SHA-256, retrieval timestamp and document revision history survive normalization.
- Explicit withdrawals/deferments, confirmed corrective respins and candidate pairs remain distinct.
- Bug counts are disclosure counts, separate from withdrawal/respin metrics.
- Missing coverage is unknown, never zero vendor events; independent human review pending.
- No schedules, hosted permissions, secrets or source activation changes.

## Review focus

- Missing or contradictory chronology cannot assert “later”.
- Unknown model scope cannot match every device; 750 and 7500 never alias.
- Revisions and duplicate feed entries cannot inflate release counts.
- Access-denied/challenge HTML cannot become evidence; untrusted URLs remain inert.
- Current recommendation or stale feed window cannot establish historical completeness.

## Shared interfaces

`application/release_signals.py` owns `new_dataset(generated_at)`,
`add_document(dataset, raw, source_url, retrieved_at, events, *, capture_method='http_response')`,
`validate_dataset(dataset)`, `build_report(dataset, *, start, end, upgrades=None)`,
`to_csv(report)` and `validate_report(report)`.

Dataset: `{schema_version:1, generated_at, documents:[], coverage:[]}`.
Each document: `{revision_id, previous_revision_id:null|string, source_url,
source_sha256, retrieved_at, capture_method, events:[]}`. Revision ID hashes the
whole document excluding itself. Repeated latest bytes are a cache hit. Earlier
revisions stay retained; only latest revision per source contributes current facts.
Event input (all keys required): `{kind, vendor, train, release:null|string,
related_release:null|string, date:null|YYYY-MM-DD, platforms:[], statement,
bug_ids:[], source_locator}`. Kinds: release, withdrawn, deferred,
corrective_respin, field_notice, recommended, bug_list. Empty platforms means
unknown model scope. Corrective respin requires related_release and publisher
statement; no parser derives it merely from a suffix. Source routes are official
Cisco/HPE/Aruba/Arista HTTPS hosts, no credentials or nonstandard ports.
Coverage rows: `{vendor, train, start, end, status, expected_releases:null|int,
reason}`; statuses partial, blocked, not_collected. No complete claim in this milestone.

Report: `{schema_version:1, generated_at, window:{start,end}, dataset_sha256,
events:[], date_conflict_evidence:[], metrics:[], candidate_pairs:[], upgrade_links:[], coverage:[], caveats:[],
review_status:'independent_human_review_pending'}`.
Normalized report events add `event_id` and `source` (document receipt excluding
raw events and adding locator). Out-of-window records that conflict with dates
from retained in-window observations appear in `date_conflict_evidence`.
Metrics fields: vendor, train, year, partial_year,
observed_releases, explicit_withdrawals, explicit_deferred, confirmed_corrective_respins,
field_notices, recommendations, published_bug_ids, undated_events,
withdrawal_rate:null, coverage:'not_established'. All are observed sample counts.
Candidate pairs: vendor, train, earlier_release, later_release, earlier_date,
later_date, calendar_days, within_14_days, within_30_days, corrective_respin_confirmed:false,
event_ids. Use dated chronological adjacent release announcements with identical
platform scope; exclude F/M changes and unsupported version identities.
Upgrade links: vendor, train, year, scenario, policy, date, target, claim_ids,
event_id:null|string, signal, relation, chronology, model_applicability, reason. Exact target/train only;
unknown model binding yields relation `model_unresolved` and model_applicability
`unresolved`; chronology separately records `later`, `not_later` or `unknown`.
Undated/earlier events never claim later. Candidate pairs use a
separate `candidate_follow_up` signal. Parse existing upgrade `rows[].events[]`,
without changing original counts, scenario, policy or claim evidence.

### Task 1: evidence contract and pure analysis

Files: create `application/release_signals.py`, two `schemas/release-signals-*-v1.json`,
`tests/test_release_signals.py` and a packaged empty `resources/release-signals.json`.

- [x] Write failing tests for duplicate revision reuse, revision updates/reversion,
      invalid provenance, unknown scope, exact chronology, candidate thresholds and
      source-window gaps; run pytest and observe failure.
- [x] Implement strict bounded validation, revision chain, pure metrics, exact target
      annotations and CSV with formula-safe cells. Existing schemas remain unchanged.
- [x] Run tests, lint and commit the focused evidence/analysis change.

### Task 2: optional public-source collectors and CLI

Files: create `collection/release_signals.py`, `release_signals_cli.py`,
`tests/test_release_signals_collection.py`.

- [x] Write failing tests for real-layout synthetic Arista XML, Cisco caveat HTML,
      Aruba version-history HTML, failure/challenge detection and offline CLI operation.
- [x] Implement `parse_arista_releases(raw)`, `parse_cisco_caveats(raw)`,
      `parse_aruba_history(raw)` producing Shared-interface events. Keep parsers narrowly
      scoped to reviewed layouts. These readers cover Arista announcements, Aruba
      release history and Cisco bug disclosures. Collectors for formal withdrawals,
      deferments, corrective respins, field notices and recommendations are deferred
      pending verification of public source layouts. The schema supports those future
      observations. Preserve announcements across rolling RSS snapshots, using the
      newest retained observation for recurring items.
- [x] Add `python -m infrastructure_impact.release_signals_cli` commands init,
      import-document (explicit parser/source/bytes/time), collect-arista (fixed public
      RSS URL, opt-in, bounded response, no redirects/auth, cache and failure receipt),
      report (explicit dataset/window/output paths, optional upgrades JSON).
- [x] Keep disabled sources/gaps explicit; never access application default vault.
      Run tests and commit only owned files; no network use in tests.

### Task 3: optional research reader and documentation

Files: create `web/release-signals.html`, `web/release-signals.js`, packaged mirrors,
`tests/test_release_signals_ui.js`, `docs/RELEASE_SIGNALS.md`; README short link.

- [x] Write failing Node tests for report shape, unknown scope/rates, HTML injection,
      unsafe source links, malformed reports and candidate versus confirmed rendering.
- [x] Build standalone local-import reader, no network or persistence. Validate all
      consumed fields; DOM text/safe links, bounded file input. Render metrics,
      candidates, upgrade links, source receipts and coverage warnings distinctly.
- [x] Document commands, interpretation, source-access restrictions, revision/cache
      handling, candidate thresholds (14/30 sensitivities), and human-review status.
- [x] Keep hosted asset publication unchanged; reader may be served explicitly by
      an operator, with integration/activation separately approved. Run Node tests,
      formatting, verify mirrors and commit owned files.

### Task 4: integration, sample run and review

- [x] Generate a report from retained usable public Arista RSS bytes outside Git;
      do not promote rendered-only Phase 1 excerpts to origin documents. Seed packaged
      dataset remains empty with all three vendors' coverage gaps, not false history.
- [x] Run targeted Python/Node tests plus relevant existing release/upgrades tests;
      verify CLI end-to-end JSON/CSV and malformed input handling.
- [x] Fresh whole-branch review; fix substantive findings and rerun affected tests.
- [x] Record run summary and limitations; push feature branch and open/update PR.
      Do not merge, activate sources or publish the site without approval.

## Execution ruling

Proceed under the user's existing autonomous execution and subagent-driven
preferences. This approval authorizes implementation, not lifting source access
restrictions or hosted activation. The reader is built as a separately served
local-import page so publication behavior is unchanged.

## Completion record

Implemented the available-source milestone. Verified imports for formal publisher
actions remain deferred as stated in Task 2; hosted activation remains gated.
Final focused/adjacent checks: 341 Python tests, 129 loopback-enabled integration
tests, and 16 selected Node results passed (including ten new reader tests).
Fresh scoped re-review approved all fixes. See the initial run summary in
`docs/research/2026-11-25-release-signals-run.md`.
