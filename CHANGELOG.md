# Changelog

## Unreleased — source gaps and model scope

- Preserve the two exact reviewed Palo Alto informational HTML bulletins: a no-CVE NAT notice and 78 explicit MOVEit non-impact product/CVE statements. Block structured representation overrides of those policies and the existing reviewed configuration notice; preserve unrelated PAN advisory behavior.
- Add a Cisco-only, exact-source fast-reload platform bridge for explicit 9300/9300L scope under each of two CVEs. Preserve all 89 original software branches, their CVE ownership, dates, versions, statuses and remediation boundaries; leave frozen studies and other platform gaps unchanged.
- Reconcile the 15 hosted source failures and three missing-source benchmark cases, record the live two-advisory Arista preview and identify the separate exact-target maintenance/current-catalogue policy work needed before hosted application. No deployment or hosted maintenance is included.

## 0.11.0 research preview candidate — 2026-11-06

- Add explicit `impact cve-reconcile` verification, bounded offline scan/resume, immutable baseline and strict JSON/CSV reporting for official CVE snapshots. Preserve source/container evidence, current versus historical presence, missing references and unestablished coverage completeness. See the [local operator guide](docs/CVE_RECONCILIATION.md). No hosted activation, default-source change or publication is included; the website source pin remains released 0.10.1.
- Correct the exact reviewed Arista SA-0099 CVE/version groups and select SA-0103 HTML from either reviewed entry URL while retaining its contradictory CSAF evidence and visible alternate issue. Existing wrong-scope historical revisions remain retained and cannot supply fresh research claims.
- Reduce repeated switching comparison validation and copying while preserving fresh public validation, exact returned-input checks and independent publication snapshots. See the [repair observations](docs/research/2026-11-06-arista-comparison-repair-observations.md) for replay evidence, bounded measurements and outstanding acceptance limits; no release or hosted activation is included.
- Update development tools to Ruff 0.17.3 and pytest 9.2.0, and the reader container to Python 3.15. Hosted collection retains its existing Python 3.13 workflow. Verify example plugin 0.1.10 against the candidate and extend its declared compatibility through the 0.11 series.

## 0.10.1 research preview candidate — 2026-11-06

- Support the reviewed current F5 PHP PDF profile alongside its original revision, retaining paired engineering hotfix/base versions and source-bound backport context. Mixed or unreviewed sections still fail visibly. See the [profile review](docs/research/2026-11-05-f5-php-profile-revision.md).
- Restore the exact HPE-hosted canonical transport route for the reviewed Juniper OpenSSH reference, preserving its original source binding and release/platform scope without creating CVE assessments. See the [source observations](docs/research/2026-11-05-juniper-canonical-reference.md).

## 0.10.0 research preview candidate — 2026-11-05

- Parse the reviewed Aruba 2021 directory and two signed-text advisory structures, retaining shared product scope, per-CVE metrics and unresolved model/remediation bindings.
- Preserve literal Arista affected, unaffected and triage groups with their configuration qualifications. Recognize reviewed Arista/Cisco advance notices without creating CVE assessments, and revisit later retained revisions.
- Add an explicit, read-only `coverage-gaps` operator inventory with separate enumeration, retrieval, parsing, notice, error and bounded preview accounting; package its closed schema.
- Verify source-to-publication/native/browser/JSON/CSV integration and an isolated public-only acceptance stage. See the [dated observations](docs/research/2026-11-05-coverage-repair-observations.md): Aruba parsed 2 of 19 listed documents; complete vendor history and authenticated Cisco coverage remain unestablished.
- Track the actual requested and selected retained inputs during archive replay, recovering when missing linked documents arrive while skipping unchanged wrapped notices without consuming the document budget. Preserve immutable parser receipts, HTTP backoff and page-scope reporting.
- Verify example vendor plugin 0.1.9 against the 0.10 release and extend its declared compatibility through the 0.10 series. Published v0.9.1 artifacts, frozen results, dependency pins, default sources, limits and hosted activation remain unchanged. See the [release notes](docs/releases/0.10.0.md) and [activation proposal](docs/rollouts/2026-11-05-coverage-010-activation-proposal.md).

## 0.9.1 research preview candidate — 2026-11-05

- Bound explicitly product-scoped CSAF scores and remediations to each claim's exact product ID after source/CVE/representation membership and score preference resolution. Retain every claim, including unresolved families, original source bytes/provenance and full valid score scope in ordinary advisory metrics.
- Index original score candidates, cache exact ordered candidate groups within one extraction, and resolve remediation scopes once. Preserve empty/unbound and reviewed HTML scope, invalid/incomplete diagnostics and all non-scope facts.
- Validate closed four-string source uniqueness with an index while preserving the schema's `uniqueItems` contract, strict independent writer validation and stock JSON equality for other shapes.
- Emit flushed metadata-only timings at collection, benchmark coverage, report, query, projection, writing and backup boundaries, including failed phases without serializing errors or payloads.
- Preserve all existing delivery/storage/monitor budgets, pinned dependencies, default sources and recovery settings. Example plugin 0.1.8 already admits 0.9.1. This is a replacement candidate for the published but rolled-back 0.9.0 source release; no new activation is claimed. See the [failed activation receipt](docs/rollouts/2026-11-05-switching-activation-failed.md) and [replacement proposal](docs/rollouts/2026-11-05-switching-091-proposal.md).

## 0.9.0 research preview — 2026-11-04

- Add a closed, generation-bound comparison-eligibility monitor summary with exact full-report fingerprints, complete vendor membership and unchanged suppression gates. Preserve full case evidence as an explicit download and bounded full-report checks for older publications.
- Count all default monitor metadata, reports, parts and schemas against the unchanged 20,000,000-byte aggregate budget; retain existing per-asset limits and separate explicit archive verification. The unpublished replacement candidate requires renewed exact-commit approval before release or activation.
- Add a separate campus/branch switching disclosure study for Cisco IOS XE, Aruba AOS-CX and Arista EOS, with explicit OS-family and model-qualified scopes, independent vendor/period controls and generation-bound JSON/CSV exports.
- Add opt-in, bounded and resumable Cisco OpenVuln OAuth collection, retained Aruba/Arista archive enumeration and per-source coverage/error manifests. Credentials, hosted backfill and runtime activation remain separate operator actions.
- Preserve source-linked platforms, versions, conditions, publisher identifiers, explicit bundles and remediation-publication events without automatic model/version matching or inferred fix dates.
- Retain vendor-reported CVSS, separate advisory severity, official CVE/NVD fallback and full-study KEV status with explicit missingness and provider provenance. Reported scores are structurally checked, not independently rescored.
- Validate study evidence and derived results consistently in Python and static delivery, including deterministic numeric claim fingerprints, source attribution and model/bundle/remediation scope. Unusable study dates remain unknown without blocking supported advisory-v2 publications.
- Cache owned immutable study inputs and load detail in bounded pages. Real staged repeated selections improved from about nine seconds to tens of milliseconds; initial complete-study loading remains substantial.
- Package strict study schemas/resources and extend compact monitoring, external-plugin and clean-export verification. Document actual partial backfill, drafts, unresolved models and automated validation separately from pending human review.
- Verify example vendor plugin 0.1.8 against the 0.9 release and extend its declared compatibility through the 0.9 series. Keep advisory schema v2, frozen studies, default sources, schedules, permissions and hosted runtime pin unchanged.

## 0.8.0 research preview — 2026-11-03

- Add retained CISA Known Exploited Vulnerabilities enrichment from CISA's official mirror, with bounded strict parsing, source provenance, last-good revisions and verified-check freshness.
- Publish a strict generation-bound KEV schema/report, complete CVE membership index and scoped publisher details. Missing, disabled, failed, stale and future checks remain explicit unknown states.
- Add attributed KEV badges, outside-advisory membership context and a KEV-listed-only cohort filter. Preserve requested versus effective scope, vendor affectedness and frozen research contracts.
- Align native/static selection and JSON/CSV/report exports, including legitimate empty intersections, same-generation downloads and rejection of unavailable filters. Keep accepted evidence and downloads coherent after stale, invalid or out-of-order requests.
- Validate KEV identities, policy limits, source fingerprints and report scope in the standalone monitor and installed-wheel acceptance checks. Vendor rates, first disclosure and intentional concealment remain unestablished.
- Separate scheduled service-operations evidence from public health; expose overdue collection/monitor cadence and storage-budget failures without turning missing receipts into success.
- Verify example vendor plugin 0.1.7 against the 0.8 release and extend its declared compatibility through the 0.8 series.

## 0.7.0 research preview — 2026-11-02

- Add generation-bound CVE research dossiers inside Case files, combining exact-build publisher statements, source fingerprints, qualified chronology, disclosure context and explicit evidence gaps.
- Curate an OpenSSH switching comparison for Arista EOS 4.32.2F and Aruba AOS-CX 10.13.1031, plus separate FortiProxy dossiers for CVE-2023-38545 and CVE-2023-38546. HPE Cray remains disclosure context only.
- Preserve distinct assessment branches and their own locators, per-CVE product associations and exact source/build binding. Fixed-only statements do not establish prior affectedness.
- Add strict dossier schemas, native report/API routes, static publication delivery, vendor/CVE selection and same-generation single-dossier JSON downloads. Older generations remain readable.
- Validate dossier identity, fingerprints and fixed research limits in the standalone public monitor and installed-wheel acceptance probes. Vendor rates, verified fix delays, earliest disclosure and intentional concealment remain unestablished.
- Verify example vendor plugin 0.1.6 against the 0.7 release and extend its declared compatibility through the 0.7 series.
- Synchronize the generated build requirements with the reviewed Hatchling 1.33.0 update.

## 0.6.0 research preview — 2026-10-27

- Add a ninth vendor plugin for two exact reviewed F5 PHP/OpenSSH article PDFs. Preserve shared-CVE tables, BIG-IP / BIG-IP Next distinctions, authentication, lifecycle limits and literal fix-column states; reject changed semantic scope and retain earlier evidence.
- Validate F5 normalization on the Ubuntu source-access runner without a vault or response-body artifact. Treat PDF responses as documents, without scanning embedded bytes for HTML links.
- Map only the two explicit F5 central-management labels into the existing role taxonomy; broad multi-role product labels remain unmapped.
- Add vendor-scoped hosted normalization maintenance, with early scope validation, a bounded attempt budget, single-run workflow inputs and preserved default behavior.
- Preserve F5 publisher dates as date-only claims; do not manufacture midnight timestamps or numeric publication offsets.
- Keep F5 outside the frozen extraction-review sample. Document the advertised RSS failure and differing HTML/PDF date claims without inferring concealment or feed completeness.

## 0.5.0 research preview — 2026-10-27

- Add private bounded SPDX/CycloneDX JSON component observations with a common schema, literal versions, exact locators, scope and package-hash provenance. Open no vault, fetch no external references and create no CVE or image-inventory claims.
- Share strict duplicate-key and finite-number JSON input checks across inventory proposals and SBOM inspection, including numeric overflow rejection.
- Label the dashboard schedule as configured timing and link GitHub Pages deployments to actual scheduled-run history; fresh manual publication is not evidence that scheduling works.
- Preserve two reviewed Fortinet single-CVE range lists, separate affected/unaffected branches and authentication/service prerequisites. Keep the contradictory FortiOS 6.4 solution text unresolved, without certifying either upgrade candidate.
- Classify retrieved Fortinet envelopes without explicit CVE/product scope as visible publisher-scope gaps; do not invent CVEs or affected products.
- Add read-only aggregate vault profiling and record the breakdown with hosted recovery metadata, without exposing source or review contents.
- Add explicit standard (512 MiB) and large (1 GiB) recovery profiles. Preserve archive, decoder-memory and repository budgets, atomic recovery and all historical evidence.
- Bound public-monitor manifest reads and reject publication timestamps beyond a five-minute clock tolerance; retain the 36-hour freshness limit.
- Detect missing successful scheduled runs independently of fresh manual publications, with a separate cadence activation anchor, bounded history timestamps and a declared grace period.

## 0.4.1 research preview — 2026-10-27

- Serve the inventory proposal schema through the Python reader, matching static publication. Check every exported schema route in source and installed-wheel acceptance tests.
- Link pilot proposal downloads to evidence-preparation instructions and update the architecture guide to describe the public Pages deployment and offline proposal boundary.

## 0.4.0 research preview — 2026-10-27

- Add a vendor-neutral private build-inventory proposal contract and offline template/audit commands, with exact-byte checks, scoped evidence references, bounded input and no automatic certification or publication.
- Compare the two firmware pilot targets side by side, show source checks separately, expose blank proposal downloads and track exact build-to-component binding as an explicit gap.
- Document official EOS source archive and AOS-CX source-request leads, preserving access and historical-availability limits.

- Add a two-vendor exact-firmware evidence pilot with field-level provenance and explicit unverified package, image, hardware, configuration and lifecycle fields.
- Preserve reviewed Arista 0100 EOS fix boundaries and backport context without inferring patch state from OpenSSH version strings.
- Add three dated assistant disclosure dispositions, exact-source freshness guards and bounded official-source research, including restricted Cisco SBOM terms.

- Add three product-scope cohorts with 15 targets, build/service/lifecycle gaps, exact component-source bindings and suppressed denominators.
- Add a disclosure review queue with five evidence gates, CVE-specific counter-evidence and alternative explanations.
- Serve both reports through generation-bound API, static files and dashboard views, with strict schemas and privacy-boundary rebuilding.
- Add a manual metadata-only runner probe for four reviewed Cisco/Aruba alternatives; all four first-run requests returned 403 and remain access gaps.

## 0.3.0 research preview — 2026-10-27

First tagged source preview. Source coverage remains bounded, independent human
review is pending, and vendor rates and rankings remain suppressed.

- Pin direct workflow actions to verified upstream commits, review action updates weekly, synchronize the deployment template, update Pages actions to Node 24, and verify that the declared static marker is actually published.

- Preserve all explicit CVE rows sharing a Check Point SK identity, retaining row-specific product branches and conflicting-date unknowns; reject duplicate document identities at the common feed writer before any advisory write.

- Add three reviewed CloudVision management-appliance advisories, preserving TACACS+ shell-login prerequisites, custom-role-only mitigation, a publisher release-cutoff discrepancy, and CVX server fixes distinct from excluded client switches.

- Reject non-finite numeric values at advisory/component validation and publication boundaries, preserving the last valid public generation if malformed source or report data is supplied.

- Show retained publisher family context beside exact product labels, flag shared labels without changing filter identities, and give comparison counts room to remain readable.

- Add bounded offline normalization maintenance with a read-only preview, shared writer exclusion, per-record failure reports, stable-identity guards and opt-in hosted replay; preserve source capture times and distinguish parser reinterpretations from publisher changes.

- Add append-only encrypted recovery in unpublished draft release assets, with bounded authenticated readback before pointer updates, preserved legacy Git copies, metadata-only monitoring and compatible Git-mode rollback.

- Validate component-reference hooks through a shared versioned schema and registry boundary before baseline storage or research analysis; add CLI validation, typed plugin contracts and an installed external component-hook example.

- Add reviewed Cisco UCS firmware security-fix statements for regreSSHion and Terrapin, preserving separate releases, fixed-only scope and unknown CVE-specific disclosure dates.

- Classify dated remediation claims against publisher dates rather than the replay clock; keep contradictory or imprecise date context unknown and record corrections as parser reinterpretations.

- Scope built-in normalizer identities to declared code dependencies and shared validation/resources; preserve legacy extension behavior, avoid unrelated vendor revision/replay churn, and verify source/wheel fingerprint parity.

- Add a scoped Apstra 4.2.0 OpenSSH statement and component reference; strengthen the existing planned-fix PDF boundary, separate document identities, and prevent adjacent Terrapin/Python fixes or document-title versions from broadening scope.

- Compress new hosted backups with XZ while retaining gzip recovery compatibility, unchanged authenticated encryption and size bounds. Make restore atomic, keep plaintext staging outside tracked state, authenticate recovery copies before commits, and monitor uncompressed capacity.

- Retain a reviewed Palo Alto Clientless VPN configuration notice without inventing a CVE from its malformed CSAF identifier; keep notice-level product scope separate from CVE assessments.

- Preserve three older Arista routing advisories with IS-IS/VxLAN/VLAN prerequisites, separate 7170 and X-Series version/fix branches, explicit model exclusions and distinct special-release fixes.

- Make collection-health attention items visible first, with vendor/result filters, retained-total counts and explicit empty states; consolidate README research and operations links.

- Add a deterministic compressed full public JSON archive with manifest fingerprints, an explicit whole-publication download and bounded monitoring of exact decompressed-byte equality.

- Preserve Fortinet regreSSHion version rows and explicit not-impacted/investigation lists; keep disjoint ranges, planned upgrades and fixed-only statements distinct. Apply reviewed Cisco/Fortinet source policies to direct structured entry points to prevent later scope replacement.

- Recover unsupported retained archive captures after parser changes without new HTTP requests, preserving backoff and shared processing budgets; publish distinct replay provenance through additive migration 010.

- Add reviewed older Arista software/model boundaries and a local FragAttacks CVE/model matrix, preserving nested exclusions, DNS/TLS prerequisites, reference-only CVEs and dated lifecycle limits.
- Keep retained-source triage read-only; collection writers persist source choices only after validated ingestion.

- Add a frozen OpenSSH service study with explicit role exclusions, downstream variants, reference-source drift and unknown vendor cells; suppress rates and rankings.
- Keep upstream reference collection separate from infrastructure vendor advisories through an exact-route registry and additive migration 008.
- Preserve the reviewed Cisco regreSSHion HTML product scope while retaining its advertised CSAF separately; expose source-choice fingerprints and alternate failures in collection health through additive migration 009.
- Keep dated planned fixes distinct from verified release availability, and expose family matcher version/scope fingerprints alongside the frozen CVE cohort.

- Record successful HTTP checks separately from evidence revisions, including
  cache validations, unchanged bodies and content reversions; expose bounded
  check history and analyzed-source alignment without reconstructing earlier dates.

- Add release-scoped Juniper OpenSSH and HPE iLO OpenSSL references, with explicit
  product/platform limits and destination-version extraction.
- Recognize HPE browser session-check shells as access gaps rather than content.

- Preserve older Arista RADIUS prerequisites, local HTTP/2 CVE groups, explicit xz
  exclusions and restricted-cloud non-CVE scope found by bounded archive preflight.

- Support Arista 0105 nested NGFW scope without promoting acknowledgment-only CVEs.
- Schedule three reviewed PAN-OS/Panorama OSS reference sources through an optional
  component parser hook; retain patch/deployment qualifications and source hashes.
- Add comparison protocols and per-cell provenance, including excluded evidence;
  distinguish fixed-only unresolved assessments from shared statements.

Source releases and evidence publications have separate identities. Consult the
GitHub release assets and live publication manifest for their exact versions.

## Research foundations — 2026-10-26

- Add 33 curated product families, selected release-line reference checks, source fingerprints and explicit inventory gaps.
- Add predeclared comparison cohorts with common CVE cells, readiness requirements and suppressed rates.
- Add dated fix leads from scoped release sections, component-version observations and publisher chronology, retaining alternative explanations and counter-evidence.
- Publish strict schemas, JSON reports, read-only endpoints and three dashboard views; keep private intermediate evidence outside the public projection.

## Historical batches and infrastructure expansion — 2026-10-26

- Add bounded retained-evidence/network triage with explicit layout groups, sampling bounds and no queue ingestion.
- Support reviewed Arista NGFW, DMF/CCF/CVA/MCD, reposted VeloCloud and on-premises CloudVision layouts while preserving nested prerequisites.
- Share publisher-verified CNA delivery across Cisco, Juniper, HPE and Check Point; exclude upstream-authored follow-ups without inventing vendor impact.
- Add curated infrastructure records, bounded Cisco/Check Point feed follow-ups and source-linked role aliases.
- Describe Aruba product families observed in retained structured advisories.

## Shared layouts and coverage matrix — 2026-10-26

- Add configured routes, archive progress, observed formats, publisher-date ranges and classified source gaps to the vendor coverage view and report.
- Extend reviewed Arista section parsing while preserving repost provenance, per-CVE configuration context and physical appliance scope.
- Preserve repeated CNA release branches with compatible metadata, version change points, CPEs and source indices; refuse conflicting scope.
- Normalize the reviewed Fortinet affected-product list without claiming unconditional configuration-dependent fixes.

## Scoped advisory parser follow-up — 2026-10-26

- Support three further reviewed Arista software layouts with platform and configuration context.
- Retain the no-CVE AirSnitch advisory as a notice with prerequisites and mitigation context.
- Normalize exact repeated CSAF vulnerability entries once with explicit source-index warnings; differing entries still fail closed.
- Pin the five reviewed sources and add synthetic scope and conflicting-repeat regression tests.

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
