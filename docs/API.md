# Read-only API

The production reader uses Waitress. OpenAPI 3.1 is at `/openapi.json`, and the
record schema is at `/schemas/advisory-v2.json`. Only GET/HEAD are supported;
there are no collection-trigger, correction-apply or raw-vault HTTP endpoints.

```text
GET /api/v1/advisories?cves=CVE-2024-6387&vendor=checkpoint&limit=50&offset=0
GET /api/v1/assessments?cves=CVE-2023-38545,CVE-2023-38546
GET /api/v1/health
```

List responses contain `schema_version`, `publication`, `total`, `offset`, `limit`
and `items`. Advisories follow schema v2. Assessments are flattened with vendor,
advisory ID, source URL and hash. Omitted cohorts select all published CVEs;
explicit cohorts allow up to 200 IDs. Page size defaults to 100, maximum 500.
Invalid filters return 400; non-read methods return 405.

Every response identifies its immutable generation. Data can change between page
requests. Consumers needing a consistent complete export should fetch
`/snapshot.json` once and retain its publication ID.

| Compatibility/bulk route | Result |
| --- | --- |
| `/api/state?cves=...` | Dataset and selected comparison/coverage. |
| `/api/export.json?cves=...` | Cohort-filtered advisories and assessments. |
| `/api/export.csv?cves=...` | Same assessment scope; formula-prefixed cells escaped. |
| `/snapshot.json`, `/impact.csv` | Complete current public export. |
| `/api/evidence/<id>` | Source URL, times and fingerprint, never raw text. |
| `/api/changes/<id>` | Summarized observed change. |
| `/manifest.json` | Generated artifact checksums. |

`/health/live` checks process responsiveness. `/health/ready` checks publication
availability and age; the default stale threshold is 36 hours. Stale readiness
returns 503 while old data remains readable. `/api/v1/health` also reports the
latest minimal collection receipt, current failures and a separate count of
historical source URLs whose last attempt failed. A partial collection is not a
whole-vendor outage; inspect source-level coverage.

The pilot's old loopback raw-evidence response is intentionally not part of the
production reader. Operators inspect the private vault through local tooling.

`/api/v1/catalogue` returns operational vendor coverage and freshness profiles.
`catalogue.json` and `benchmark.json` are also included in static publications.
The public GitHub Pages service supports static exports and browser filtering;
the query-string REST routes require the Python reader.

`release-assets.json` exposes configured, schema-validated release-listing metadata.
Publisher artifact checksums differ from source-page fingerprints. No firmware is
downloaded and no CVE applicability is inferred from a listing. The corresponding
contract is `schemas/release-asset-v1.json`. Source health includes an `error_code`
when a failure is classified (for example, `access_verification_required`).

`/api/v1/scorecards` and `/api/v1/timeline` accept the same optional `cves` and
`vendor` filters. Their version 1 derived metadata and static Pages equivalents
are described in [SCORECARDS.md](SCORECARDS.md). These endpoints never read the
vault and do not assign vendor security scores.

`/api/v1/source-audit` returns the configured-source/retained-response audit.
`/api/v1/casefiles` accepts optional `cves` and `vendor` filters; the static
equivalents are `source-audit.json` and `casefiles.json`. See
[SOURCE_AUDIT.md](SOURCE_AUDIT.md) and [CASE_FILES.md](CASE_FILES.md).

The source audit includes per-vendor `archives` progress: page/document state
counts, discovery gaps, exhausted retries, retained page fingerprints and the
publisher date range of current matched records. `known_queue_exhausted` does not
establish portfolio completeness or historical document availability. See
[Archive collection](ARCHIVE_COLLECTION.md).

Each vendor source-audit row may include `archive_source_review`, a dated bundled
review of the official endpoint, primary-response hashes and limits. Its
`configured` flag describes this deployment. Archive rows also include
`observed_scopes`, retained from the actual visited listing pages. Static review
counts and historical bounds are not live totals or complete coverage claims.

`/api/v1/comparison-eligibility` accepts `cves`, `vendor`, inclusive `start`/`end`
dates and a URL-encoded JSON `products` mapping of vendor IDs to exact retained
product-label arrays. It returns qualified sample counts, source/backfill limits
and explicit timing/rate suppression under
`/schemas/comparison-eligibility-v1.json`. The static default-window counterpart
is `comparison-eligibility.json`; Pages provides equivalent local filtering.
See [Comparison eligibility](COMPARISON_ELIGIBILITY.md) for date precision, scope,
limits and export semantics. The deprecated `delays` array is empty. Legacy
`comparison` counts and global record exports retain their cohort-only scope.

The comparison also accepts `group=firewalls` (or another declared product-role
ID), intersecting any exact product selectors. It returns `product_group` and
`taxonomy_version`. Unknown/duplicate groups return 400. The additive group fields
are included in the current v1 report schema; strict consumers should retain that
schema with their publication. See [Product groups](PRODUCT_GROUPS.md).

| Evidence-quality route | Static publication | Scope |
| --- | --- | --- |
| `/api/v1/product-groups` | `product-groups.json` | Role rules, mapping coverage and unresolved labels; optional vendor filter on the Python reader. |
| `/api/v1/extraction-validation` | `extraction-validation.json` | Whole pinned source-led review sample; human review remains pending. |
| `/api/v1/review-packet` | `review-packet.json` | Blind packet with source fingerprints and blank adjudication fields. |
| `/api/v1/publisher-history` | `publisher-history.json` | Publisher-reported documentation chronology, not firmware availability. |

Pages serves the static files and runs comparison filtering in the browser; it
does not host these REST routes. [Extraction validation](EXTRACTION_VALIDATION.md)
and [disclosure pilot](research/disclosure-pilot-20261026.md) describe the limits.

The Product cohorts pilot optionally includes blank `inventory_proposal_template`
objects and separate `source_check` metadata for each exact firmware target. These
additive fields are independent of the private proposal audit; no submission API
is exposed. The input schema is available at
`/schemas/build-inventory-submission-v1.json`. See [Build inventory](BUILD_INVENTORY.md).
