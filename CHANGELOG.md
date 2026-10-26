# Changelog

Changes are recorded here for release preparation. Version 0.3.0 is the current
source version; this file does not imply a package or GitHub release was published.

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
