# Incremental Reliability Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Execute after the other implementation tasks in the current isolated checkout.

**Goal:** Prepare incremental, provenance-backed release catalogue candidates from cached public sources without automatic publication.
**Architecture:** Standalone explicit-path CLI, exact source registry, bounded credential-free conditional transport, immutable outside-Git cache and deterministic candidate/review preparation.
**Tech Stack:** Existing Python standard library, JSON schema catalogue validation and release-signal parsers; no new dependencies.
**Spec:** docs/superpowers/specs/2026-11-25-reliability-refresh-design.md

## Global Constraints

- No schedule, hosted configuration, source default activation, permissions, secrets, packaged catalogue or existing studies change.
- Public anonymous exact URLs only; no redirects, login/challenge bypass, third-party mirrors or environment proxy. No private vault, env secret file, licensed raw feed or customer data.
- Cache original bytes outside Git, never alter first retrieval on identical bytes/304; preserve revisions and last good state on every failure.
- Source URL/locator/quote/SHA/retrieval on facts. Announcements are not release dates, Cisco version identities are undated, missing model scope stays empty.
- Unknown coverage remains unknown; no complete denominators, human review or withdrawal from source disappearance.

## Review Focus

Policy acknowledgement cannot permit a disallowed/unknown robots route. Fixed registry prevents arbitrary URLs/SSRF. Corrupt or missing 304 cache fails closed. Atomic cache pointer and output changes cannot destroy baseline or accepted observations. Conflict reports cannot silently promote dates or applicability.

### Task 1: Standalone cache, readers and candidate preparation

**Own files:** new infrastructure_impact/collection/reliability_refresh.py, application/reliability_refresh.py, reliability_refresh_cli.py, resources/reliability-refresh-sources.json and focused tests/test_reliability_refresh.py plus docs/RELIABILITY_REFRESH.md, README/CHANGELOG entries. Existing catalogue/signal APIs and schemas remain compatible. No workflow, product JS, frozen research packets or packaged catalogue edits.

- [ ] Read the spec and inventory /private/tmp/reliability-refresh-inventory.md, existing release_catalogue normalization and release_signals parsers/cache patterns. Write meaningful failing synthetic tests before implementation.
- [ ] Fixed registry IDs: cisco-c9200-rommon, cisco-c9300-rommon, arista-eos-rss; use exact URLs from inventory. Cisco reader requires exact platform/train/title/table headings and Release column. Model scope comes from the document, not registry alone. Arista reuses strict RSS parser, retains announcement date and literal pubDate/title locator, null release date and empty models. Unsupported shape is unavailable.
- [ ] CLI subcommands import-capture, collect, prepare with explicit source, outside-Git cache, baseline and separate output/report paths. Network only for the Cisco routes after a local policy receipt explicitly identifies allowed source IDs and reviewed timestamp (within30 days, not future); reviewed terms URL/locator/fingerprint belongs to that receipt. Current robots must allow the exact route, with unavailable/denied/challenged policy failing closed. Arista network remains disabled, offline import allowed. This receipt acknowledges policy review; it never supplies a fetch URL or bypass flag.
- [ ] Transport: exact HTTPS allowlist, no auth/cookies/proxy/redirects, 4 MiB body bound, bounded timeout/deadline and at least one-second per-vendor spacing or larger robots delay. Conditional validators must be bounded/control-free;304 requires cached verified substantive bytes. Record sanitized access/policy/HTTP/parse outcomes, preserve last good pointer. Cache immutable bodies by digest, first retrieval and original/operator origin, revision links/HTTP validators separately; atomically update under lock, reject symlink/path collisions and inside-Git caches.
- [ ] Preparation: default baseline may be packaged catalogue but never write it. Retain all prior observations, validate each cached body and normalize new facts with source receipts. Semantic duplicate replay is idempotent; preserve original existing evidence when facts unchanged. Conflicting dates or model scope stay pending in separate report rather than overwriting baseline. No omission withdrawal. Advance catalogue generated_at only for newly retained evidence, not a check-only run. Preserve all coverage flags/review status. Run existing catalogue validator and preview report builder against candidate.
- [ ] Tests:200→304→changed200, missing/corrupt304 cache, reused olddigest, rolled RSS, wrongmodel/table, futuredates, quote/locator preservation, nullrelease/model fields, policy/robots/access rejection without forbidden requests, redirects/401/403/429/challenge, malformed XML, write failure/pointer preservation, conflicting facts held, idempotence and unchanged packaged/live defaults.
- [ ] Run focused new and existing catalogue/signal suites, Ruff and source export privacy checks. Document invocation, policy/cache contracts and activation limits. Self-review, commit and report; do not execute live collection or add fabricated policy approval.

Report exact red/green commands/results, files, commits, spec compliance and concerns
to this plan's SDD task report. No subagents or live deployment/activation changes.
