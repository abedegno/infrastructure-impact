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
