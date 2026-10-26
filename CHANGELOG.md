# Changelog

Changes are recorded here for release preparation. Version 0.3.0 is the current
source version; this file does not imply a package or GitHub release was published.

## Vendor gap visibility and Arista review — 2026-10-26

- Add whole-publication vendor gap reports, filters, schema and read-only endpoint.
- Support three reviewed Arista exceptional layouts, keeping a no-CVE notice and informational index separate from product/CVE claims.
- A successful pinned-document ingestion can acknowledge matching archive queue items without resetting unrelated failures.
- Add metadata-only backup history accounting and manifest size receipts; retain recovery history and flag budget pressure without deleting data.

## Cohort delivery and review follow-up — 2026-10-26

- Load selected CVE evidence in content-addressed parts with bounded concurrency and explicit generation/hash checks. Keep full archive downloads available.
- Preserve complete vendor/product selection context and Python/static comparison parity; defer source-change history.
- Pin unchanged Fortinet release-article evidence despite surrounding byte changes.
- Add a curated Check Point vendor-blog source and three source-led assertions; detailed blocked SK checks remain gaps.
- Expand the review packet to 25 assertions and document maintainer conflicts and partial adjudication.

## Review and infrastructure coverage — 2026-10-26

- Add identity-checked Juniper CNA collection and bounded RSS follow-ups, retaining platform/configuration prerequisites.
- Expand curated HPE coverage to iLO and ProLiant, preserving explicit per-CVE product exceptions.
- Expand source-led review to 22 assertions; separate reviewed section matches from raw-byte passes.
- Add hash-bound private review proposals without automatic human certification or eligibility changes.
- Add a disclosed Juniper security-rebuild case and record an authenticated backup recovery drill.

## 0.3.0 — Unreleased

- Add versioned source-linked product roles, comparison group filtering and mapping gaps.
- Add source-fingerprint-pinned extraction validation and blind independent-review packets.
- Retain reviewed Arista aggregate-notice references without inferring product impact.
- Recover reviewed Fortinet investigation statements from HTML when its CSAF envelope is empty.
- Add publisher documentation histories and earlier-advisory counter-evidence to research case files.
- Increase bounded daily archive document budgets to 16 for Aruba and 8 for each other configured archive.

- Package the collector, normalization, storage, application and reader separately.
- Add external vendor entry points and schema v2 validation.
- Publish sanitized immutable generations for a separate read-only API/dashboard.
- Add checksummed migrations, evidence audits and online SQLite backups.
- Provide Docker/Compose, API documentation and deployment/recovery guidance.
- Add synthetic parser fixtures, contribution/security policies and public-source
  release preparation tooling.
