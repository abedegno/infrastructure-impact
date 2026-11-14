# Infrastructure Impact

**Trace a CVE from an upstream component to the infrastructure products that vendors say it affects.**

Infrastructure Impact collects official advisories and release notes for appliances,
routers, switches and security products. It preserves the source evidence, normalizes
vendor statements into a shared schema, and provides a dashboard and read-only API
for product impact, vendor comparisons, coverage gaps and disclosure research.

Early-stage software: the pipeline works end to end, but source coverage is bounded.
The opt-in [source coverage inventory](docs/source-coverage.md) separates discovery,
retrieval, supported parsing and informational notices. The
[2026-11-05 public-stage observations](docs/research/2026-11-05-coverage-repair-observations.md)
record the remaining gaps and pending human review; the v0.10.0 repairs do
not establish complete vendor history or change the frozen benchmark.

The [local CVE reconciliation workflow](docs/CVE_RECONCILIATION.md)
compares a verified official snapshot with an explicit collection baseline,
including partial scans and missing reference evidence. It has no hosted activation.

The [v0.12.0 release](docs/releases/0.12.0.md) adds exact-target refresh and
visible current-evidence dispositions while preserving labelled historical records.
The [v0.12.1 candidate](docs/releases/0.12.1.md) corrects monitoring of retained-only
KEV context. Source release and hosted activation remain separate review steps.
The [v0.13.0 candidate](docs/releases/0.13.0.md) adds customer switching comparison
and reviewed public release/bundle references. Its
[bounded replay result](docs/research/2026-11-09-customer-comparison-replay.md)
is a local integration check; hosted acceptance remains pending. The
[10 November fix-attribution replay](docs/research/2026-11-10-switching-fix-expansion-replay.md)
records finite Aruba/Arista coverage gains and unresolved source evidence.

Missing evidence means **unknown**, never automatically **unaffected**. Comparisons
measure documented exposure in a declared CVE cohort, not overall vendor security.

![Infrastructure Impact web app showing coverage-aware comparisons across nine vendors for a 24-CVE benchmark cohort](docs/images/vendor-comparison.jpg)

_Vendor comparison view, captured 27 October 2026 from the bounded 24-CVE benchmark dataset.
The selected publication window is 28 October 2025 through 27 October 2026;
source coverage and timing limits are visible, and vendor rates remain suppressed.
The screenshot shows a dated research snapshot, not a live or comprehensive vendor ranking._

## What it does

- Collects structured CSAF/CVE JSON, feeds and reviewed HTML/PDF layouts.
- Adds [CISA KEV membership](docs/cisa-kev.md) with source freshness, retained history,
  and an optional listed-only CVE filter; it does not infer product exposure.
- Adds [family evidence, comparison readiness and dated fix leads](docs/RESEARCH_FOUNDATIONS.md) with explicit coverage gaps and alternative explanations.
- Supports bounded historical collection, offline parser recovery and
  [archive layout triage](docs/ARCHIVE_TRIAGE.md) before ingestion.
- Shows a [vendor coverage matrix](docs/COVERAGE_MATRIX.md) with source routes, archive progress, retained formats and collection gaps.
- Keeps product, platform, version and configuration scope attached to each claim.
- Separates affectedness from planned fixes, partial mitigation and reported fixes.
- Retains raw bytes, source URLs, hashes, capture times and normalized revisions.
- Distinguishes parser reinterpretation from changes to publisher content.
- Preserves [reviewed HTML and structured source choices](docs/SOURCE_SELECTION.md)
  when publisher representations have different product scope.
- Logs [retrieval checks separately from source revisions](docs/SOURCE_OBSERVATIONS.md), including unchanged checks and HTTP 304 cache validation.
- Supports external vendor plugins without core, database or frontend changes.
- Publishes immutable, sanitized datasets for a separate read-only reader.
- Groups comparable product roles while exposing unmapped labels and coverage gaps.
- Adds a [campus/branch switching disclosure study](docs/switching-comparison.md) under
  Vendor comparison, with independent full-study controls, model-qualified context,
  source-window gaps and generation-bound JSON/CSV downloads. Counts measure disclosure,
  not vendor security quality; higher disclosure can reflect more scrutiny. The separate
  16-case switching checks remain independent-human-review pending; 2026 is partial.
  The study view includes per-vendor validation results, evidence limits and
  downloads of the validation report and blind review packet.
- Publishes source-led extraction checks and blind independent-review packets.
- Investigates disclosure leads with publisher histories and counter-evidence.
- Prepares and audits private exact-build inventory evidence with a [vendor-neutral contract](docs/BUILD_INVENTORY.md), without certifying CVE exposure.
- Watches reviewed OSS component references with explicit patch/deployment limits;
  exposes comparison protocols and source provenance for each common-CVE cell.

Bundled vendor plugins cover **Cisco, HPE Aruba Networking, Arista, Palo Alto
Networks, Juniper, Check Point, Fortinet, other HPE products and F5**. F5 starts
with two reviewed PHP/OpenSSH article PDFs; it has no automatic feed or archive
coverage. Juniper also verifies vendor-authored CNA records; HPE coverage includes
curated iLO and ProLiant bulletins. These remain bounded sources, not whole-portfolio
coverage. Each plugin has specific source/layout limits; this is not a complete inventory of those vendors.
The benchmark spans multiple components, including PHP, OpenSSL, OpenSSH, curl,
Log4j and Linux. Custom CVE cohorts are supported.

[Product grouping](docs/PRODUCT_GROUPS.md) · [Extraction validation](docs/EXTRACTION_VALIDATION.md) · [Disclosure pilot](docs/research/disclosure-pilot-20261026.md)

**[Open the public dashboard](https://abedegno.github.io/infrastructure-impact/)** · [Source releases](https://github.com/abedegno/infrastructure-impact/releases) · [Coverage catalogue](docs/COVERAGE.md) · [Benchmark methodology](docs/BENCHMARK.md)

The [OpenSSH service study](docs/COMPONENT_STUDIES.md) uses a frozen CVE cohort
across six selected firewall families. Unknown cells remain unknown; rates and
rankings are suppressed pending defensible coverage and independent review.

The **[Customer switching comparison](https://abedegno.github.io/infrastructure-impact/#customer-comparison)** in the Comparison view combines the
Cisco IOS XE, Aruba AOS-CX and Arista EOS study with severity/KEV, explicit fixed
releases, dated public release/bundle evidence and coverage/model limits.
Publication counts describe vendor disclosures; they do not count customer
upgrades or rank vendor security. Fixed-only statements remain separate from
fixes linked to an affected scope. Missing release dates and incomplete archives
stay visible. The compact overview reuses selected study counts, with provider
severity and detailed audit evidence below. See the [method and API](docs/switching-comparison.md).

Historical collection resumes in bounded batches for Aruba, Arista, Palo Alto
and Fortinet. [Archive source reviews](docs/research/vendor-archives.md) document
product filters, access gaps and why Cisco archive backfill remains disabled.

The hosted static reader runs on GitHub Pages. Manual collection and encrypted
recovery have been verified; scheduled delivery remains under observation. See
[scheduled reliability](docs/SCHEDULE_RELIABILITY.md) and
[hosting and recovery](docs/HOSTED_SERVICE.md) for results, cadence and limits.

## Quick start with Docker

Requirements: Docker Engine/Desktop and Docker Compose v2.

```sh
docker compose up --build -d
docker compose logs -f collector
```

Open **http://127.0.0.1:8080** after the first collection, which can take several
minutes and requires outbound HTTPS. The reader returns 503 until a dataset is
published. Collection starts immediately, then runs daily at 08:15 Europe/London.
Source failures remain visible in Collection health.

The private evidence vault and public publications use separate named volumes.
The reader mounts only public data, read-only. The default port binds to loopback.
Stop services with `docker compose down`; volumes remain. Avoid running another
scheduled writer against the same vault. See [operations](docs/OPERATIONS.md) for
HTTPS, custom configuration, backups, recovery and single-host deployment limits.

## Run from source

Requirements: Python 3.11+, [uv](https://docs.astral.sh/uv/), and Poppler's
`pdftotext` for PDF sources. Node.js/npm are needed for frontend development checks.

From a checkout:

```sh
uv sync --frozen --group build --group hosted
uv run impact plugins
uv run impact migrate
uv run impact collect
uv run impact serve
```

Open **http://127.0.0.1:8765**. `impact collect` performs one pass; use the container
worker for an independent scheduled service. `impact --help` lists the supported
commands. No credentials or vendor accounts are bundled.

## Architecture and extension points

```mermaid
flowchart LR
  Sources[Official sources] --> Plugins[Vendor plugins]
  Plugins --> Validation[Schema validation]
  Validation --> Vault[(Private evidence vault)]
  Vault --> Publication[Sanitized immutable publication]
  Publication --> Reader[Read-only API and dashboard]
```

The static browser loads selected CVE evidence in verified parts. Snapshot
archives retain the complete snapshot scope, independent of the selected cohort.
See [static delivery](docs/STATIC_DELIVERY.md) for integrity checks and transfer
budgets. Local publication v2 is opt-in: it uses bounded parts and a self-contained
snapshot archive, while full research inputs remain separate mandatory logical
roots. Optional gzip transport reduces shared-table downloads while verifying both
compressed and decoded fingerprints and sizes; raw assets remain available.
Study JSON downloads are summaries; the local streaming export command
retrieves complete roots. See [target import and v2 export](docs/target-import.md). Local target-import
stages retain verified raw captures under the collector home by default
(`--capture-cache` overrides the path). Hosted persistence across runners requires
the separately gated encrypted `--acquisition-cache` helper option; it is not
enabled by the collector workflow.
The [174-document local retained replay](docs/research/2026-11-08-runtime-and-paging-verification.md#accepted-local-retained-replay)
passed audit, capacity, native parity and both HTTP monitors; hosted activation
remains a separate step.
Hosted publication remains on the existing format unless separately activated.

The supported topology is one writer with SQLite/WAL and one or more readers on
shared POSIX storage. Data publication does not require reader restart or code
redeployment. This is not a distributed or high-availability database.

The normalized [JSON Schema v2](infrastructure_impact/schemas/advisory-v2.json)
covers advisory identity, CVE scope, product identity, platforms, version
expressions, assessments, remediations and provenance. Dates retain publisher
precision; capture and normalization times are separate. Appliance versions are
not compared with generic semantic-version rules.
Component references use a separate
[versioned schema](infrastructure_impact/schemas/component-inventory-v1.json),
validated before baseline storage or research analysis; component presence and
version references do not establish appliance affectedness.

Vendor extensions register through the `infrastructure_impact.vendors` Python
entry-point group. See the [plugin guide](docs/PLUGINS.md) and
[standalone example](examples/vendor-plugin). The installed-wheel check exercises
a separately packaged ninth vendor outside the source checkout.

## API

```sh
curl 'http://127.0.0.1:8765/api/v1/advisories?limit=10'
curl 'http://127.0.0.1:8765/api/v1/assessments?cve=CVE-2024-6387&vendor=cisco'
curl 'http://127.0.0.1:8765/health/ready'
```

Responses identify their publication generation. The service also supplies JSON/CSV
exports, evidence fingerprints, the schema and an OpenAPI specification. There are
no public write, raw-evidence or collection-trigger endpoints.
[API reference](docs/API.md) · [OpenAPI 3.1](infrastructure_impact/resources/openapi.json)

## Development

```sh
uv sync --frozen --group build --group hosted
npm ci --ignore-scripts
uv run pytest -q
uv run ruff check infrastructure_impact checks tests/test_architecture.py tests/test_expansion.py tests/test_release_sources.py ops
uv run ruff format --check infrastructure_impact checks tests/test_architecture.py tests/test_expansion.py tests/test_release_sources.py ops
npm run format:check
uv run --group build python -m build --wheel --no-isolation
uv run python checks/distribution.py
```

Tests use small [synthetic fixtures](tests/fixtures/README.md), run offline and do
not require the maintainer's database. Poppler-dependent tests skip when the tool
is unavailable. Network collection and real HTTP/container checks are separate
integrations. `verify_pilot.py` is an optional check against a populated local
research vault, not a clean-checkout requirement.

The installed-wheel integration check may download its locked dependencies and
the example plugin's build requirements. Use `checks/distribution.py --offline`
only after those dependencies have been cached.

## Documentation

| Guide                                                                                        | Contents                                                                                           |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| [Architecture](docs/ARCHITECTURE.md)                                                         | Modules, evidence flow, publication and trust boundaries                                           |
| [Plugins](docs/PLUGINS.md)                                                                   | Add a vendor and package an extension                                                              |
| [Schema](docs/SCHEMA.md)                                                                     | Normalization semantics and invariants                                                             |
| [Operations](docs/OPERATIONS.md)                                                             | Configuration, deployment, monitoring and recovery                                                 |
| [Exact target import](docs/target-import.md)                                                 | Preview, isolated staging, durable local captures and opt-in v2 root export                        |
| [Customer comparison assessment](docs/research/2026-11-11-customer-comparison-assessment.md) | What observed CVE volume can establish, alternative explanations and patching limits               |
| [11 November evidence audit](docs/research/2026-11-11-comparison-evidence-audit.md)          | Current source errors, partial archive inventories, scoped corrections and validation distinctions |
| [10 November comparison brief](docs/research/2026-11-10-vendor-comparison-brief.md)          | Earlier dated Cisco/Aruba/Arista observations and disclosure context                               |
| [Coverage audit and review packet](docs/research/2026-11-10-comparison-evidence/README.md)   | Source gaps, yearly observed inventory, provenance and blank human review submission               |
| [Published switching results](docs/research/2026-11-09-switching-activation-results.md)      | Dated counts, yearly/cutoff views and evidence limits                                              |
| [Methodology](docs/METHODOLOGY.md)                                                           | Comparison bias, evidence standards and disclosure research                                        |
| [Contributing](CONTRIBUTING.md)                                                              | Changes, regression tests and review expectations                                                  |
| [Security](SECURITY.md)                                                                      | Reporting vulnerabilities in this project                                                          |
| [SBOM observations](docs/SBOM_OBSERVATIONS.md)                                               | Private SPDX/CycloneDX field normalization and provenance                                          |
| [Build inventory](docs/BUILD_INVENTORY.md)                                                   | Private evidence proposals, byte checks and review boundaries                                      |
| [Product cohorts](docs/PRODUCT_COHORTS.md)                                                   | Product/build scope and denominator gaps                                                           |
| [Source access](docs/SOURCE_ACCESS.md)                                                       | Runner checks for reviewed source alternatives                                                     |
| [Disclosure research](docs/DISCLOSURE_RESEARCH.md)                                           | Evidence gates and investigation queue                                                             |
| [CVE research dossiers](docs/RESEARCH_DOSSIERS.md)                                           | Selected source-bound comparisons, chronology and JSON downloads                                   |
| [Releasing](docs/RELEASING.md)                                                               | Prepare a clean public source tree and release                                                     |
| [Capacity](docs/CAPACITY.md)                                                                 | Storage profiling and explicit bounded recovery profiles                                           |
| [Scheduled reliability](docs/SCHEDULE_RELIABILITY.md)                                        | Actual scheduled-run observations and missing-trigger checks                                       |
| [Hosted service](docs/HOSTED_SERVICE.md)                                                     | Public deployment, monitoring and private backups                                                  |
| [Source audit](docs/SOURCE_AUDIT.md)                                                         | Source scopes, fingerprints and unresolved collection limits                                       |
| [Source choices](docs/SOURCE_SELECTION.md)                                                   | Reviewed differences between HTML and structured representations                                   |
| [Archive collection](docs/ARCHIVE_COLLECTION.md)                                             | Bounded queues, retry policy and retained-capture parser recovery                                  |
| [Retrieval history](docs/SOURCE_OBSERVATIONS.md)                                             | Unchanged checks, cache validation and content revisions                                           |
| [Browser evidence](docs/BROWSER_CAPTURE.md)                                                  | Private browser-assisted capture and completeness checks                                           |
| [Static delivery](docs/STATIC_DELIVERY.md)                                                   | Verified cohort parts and full public archive downloads                                            |
| [Vendor gaps](docs/VENDOR_GAPS.md)                                                           | Collection, archive and source-review gaps                                                         |
| [Scorecards](docs/SCORECARDS.md)                                                             | Evidence counts and dated revision timelines                                                       |
| [Comparison eligibility](docs/COMPARISON_ELIGIBILITY.md)                                     | Shared periods, exact product scopes and suppression rules                                         |
| [Component studies](docs/COMPONENT_STUDIES.md)                                               | Frozen enrollment, reference drift and per-cell evidence                                           |
| [Research foundations](docs/RESEARCH_FOUNDATIONS.md)                                         | Product families, readiness and alternative fix explanations                                       |
| [Case files](docs/CASE_FILES.md)                                                             | Source-linked disclosure questions and counter-evidence                                            |
| [Roadmap](docs/ROADMAP.md)                                                                   | Current boundaries and planned capabilities                                                        |

## License and data

Original project code, documentation and synthetic fixtures are licensed under
[Apache-2.0](LICENSE). See [NOTICE](NOTICE) and [third-party/data policy](THIRD_PARTY.md).
Vendor documents, names and trademarks remain subject to their respective rights
and terms. Collecting or normalizing material does not relicense it. Full captured
vendor documents, private reviews, local databases and generated research outputs
are excluded from the public source distribution.

This is an independent project; the named vendors do not endorse it. Consult the
linked primary advisory before taking operational action.

Optional upgrade estimates and disclosure context are available through the
Comparison view's **Load optional analysis** button after an explicit local
`--include-switching-analysis` export. See [local commands, API/static semantics,
methods and verification](docs/research/2026-11-14-switching-analysis-delivery.md). The default publication and hosted workflow stay
unchanged. Annual unknowns remain unknown; supported partial steps are not reliable
bounds, retrospective KEV is not historical exposure, and per-model counts overlap.
Independent human review remains pending.

See the [retained-source switching analysis run](docs/research/2026-11-14-switching-source-run.md)
for measured target coverage, unknown annual estimates, the separate complete-feed
KEV audit and native/browser export parity.
