# Switching release history and customer view Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task.

**Goal:** Publish source-owned release/bundle history and a customer comparison combining existing study CVEs, CVSS/KEV, fix releases, coverage and model limits.
**Architecture:** Exact public ReferenceSource parsers use existing capture/revision storage. A pure release report associates literal fixed references from validated current claims. A customer envelope reuses existing study selectors and lazily selected release facts across native/static JSON/CSV.
**Tech Stack:** Existing Python/JSON schemas, ReferenceSource, v1/v2 publications and plain browser JS.
**Spec:** docs/superpowers/specs/2026-11-09-switching-remediation-history-design.md

## Global Constraints

- No original operator configuration, private vault/key, private worker logs or authenticated vendor portal access. Cached public captures stay outside Git; authored synthetic fixtures only in Git.
- No frozen-study/advisory-v2 breaking change, automatic version arithmetic/model inference, software date from advisory/capture/update metadata, concealment/ranking/causal or human-review claims.
- Existing candidate/byte/storage/privacy gates remain. No schedule or permission change. Exact source enablement and runtime publication are reviewed as part of the final concrete rollout.
- Browser captures/private fix review evidence remain private. Only registered official release source normalized fields may enter the public report.

## Review Focus

- Missing posting wording, future dates and conflicting dates cannot become verified release availability.
- Same version on another vendor/product/platform is not a cohort fix; model minima remain literal context.
- Released-but-unlinked, undated fixed references and missing sources remain distinct unknowns, not zero workload.
- Old publications and mixed generations behave safely without silently using unrelated history.
- Summary/JSON/CSV/native/browser agree and do not fetch the giant runtime root or repeat all claim decoding per view.

### Task 1: Public release evidence adapters and reference registration

**Files:** Create references/software_releases.py, schemas/software-release-evidence-v1.json, tests/test_software_release_sources.py; extend references/registry.py, collection/service.py; extend adapters/aruba_history.py and arista_history.py and create adapters/cisco_history.py as needed. Do not change legacy browser history output. Add examples/software-release-sources.json; default enablement is controller integration.
**Interfaces:** Pure parse_aruba_10_14(raw), parse_aruba_10_16(raw), parse_aruba_support_10_14(raw), parse_cisco_17_12_1(raw), parse_arista_0148(raw) in references/software_releases.py delegate vendor-specific parsing and validate_document(value). inputs(db,config) returns sources with configured/enabled, retained normalized/source fingerprints/capture/parser times and sanitized latest_attempt. Reuse ReferenceSource purpose=release_history; no new tables/kinds/vendor plugin contract needed.

- [ ] Red tests for exact route/title/columns/product boundaries, dates/remarks, unknown posting, branch mismatch, missing/duplicate/conflicting rows and malicious HTML; real raw captures outside Git for positive acceptance.
- [ ] Canonical document fields: schema_version1,vendor,family,product,platforms,source_url,parser_fingerprint,releases,bundles,platform_support,issues. Release row: version,branch,reported_release_date(date|null),publisher_reports_posted(bool|null),date_basis(publisher_release_history|publisher_release_date),source_locator,statement. Bundle row: publisher_id,title,initial_published_at(date/date-time|null),member_publication_date(date|null),member_advisory_ids,source_locator,statement. Support row: sku,model_literal,minimum_version,source_locator. Closed keys, bounded strings/rows, no inferred fields.
- [ ] Register five exact sources: aruba-aos-cx-6300-6400-10-14-history (official version-history-4.html under aos-cx-10-14-xx); aruba-aos-cx-6300-6400-10-16-history (version-history.html under10-16); aruba-aos-cx-6300-6400-10-14-models (products-supported-3.html under10-14); cisco-iosxe-17-12-1-release (official ios-xe-dublin-17-12-1/model.html); arista-eos-advisory-bundle-0148 (24535-security-advisory-0148). Exact URLs are in the task brief/operator receipts, never guessed from numbers. Registry configuration cannot load code or arbitrary URLs.
- [ ] Enforce2,000,000-byte HTTP bound for release_history reference purpose, retaining current KEV/NVD behavior. inputs uses existing reference storage and collection metadata, never browser_captures. Parser fingerprint/capture time remain separate. Missing configured source stays visible; Cisco optional disabled because403; no retry/login bypass.
- [ ] Parse Aruba10.14 date12 July2024 for10.14.0007 with posting true; initial-release-only10.14.0001 retains posting null. Other supported dates accept only source's explicit formats, not neighbouring rows or footer Published October2026. Support table minima are literal SKU context and do not qualify affected claims.
- [ ] Parse Arista0148 linked member identities with exact table ownership; retain2September2026 initial versus9September2026 member-publication date separately. No firmware release date or exposure from membership. Cisco model Release Date belongs only to the explicitly named software version, not linked documentation update dates or hardware series dates.
- [ ] Focused tests, cached-byte acceptance receipts, lint/format/diff and commit.

### Task 2: Pure release/fix association report and public projection

**Files:** Create application/switching_releases.py, schemas/switching-release-history-v1.json, tests/test_switching_release_history.py; extend query.py/publication.py and publication_v2.py/reader as required.
**Interfaces:** build(evidence,release_input,*,publication,generated_at,observation_end)->dict; select_report(history,study_selection)->dict; csv_export(selected)->str. data key switching_release_history, public root switching-release-history.json, optional for old generations. Sources and release nodes retain real provenance; links reference validated current claim IDs, not copied full claims.

- [ ] Red tests for explicit same-source fixed lists, absent/unowned remediations, wrong vendor/product, exact literal version only, unknown dates, conflicting dates, planned/future source rows, source enablement/health and private field projection.
- [ ] Extract literal fixed release identities only from reviewed Arista fixed expressions and exact Aruba fixed IDs/expressions. Preserve full expressions and link basis. Cisco generic software-updates statements are not version IDs. Unknown expressions remain unresolved diagnostics. Explicit fixed-claim version expressions may supply literal release context without affected-scope linkage; ambiguous ranges remain unresolved. No generic regex across arbitrary remediation prose.
- [ ] Build two distinct reference classes: explicit CVE-specific fixed claims supply publisher-reported fixed-release context, and eligible affected claims with validated available fixes supply affected-scope-linked references. Fixed-only context never authorizes affectedness or an upgrade event. Merge known history rows by exact vendor/family/version identity while preserving platform/source contexts, conflicting dates and unknown posting. No date/availability change to core affectedness. History without fix links remains context, not zero CVEs fixed. Per-release vendor-reported fixed CVEs and affected-scope-linked cohort CVEs have separate fields/counts; never substitute one for the other. Include bundle context from existing typed Cisco bundles and registered Arista source; keep member/notice/release dates separate.
- [ ] Select using the same current study vendor/scope/window/CVE criteria. Compact references retain original advisory date and scope qualification so the browser need not materialize all claim IDs; shared Python/JS vectors must prove parity. Fixed-only context stays contextual and cannot gain model qualification from another claim. Label history as evidence for the selected advisory CVE cohort, not necessarily releases published in that window. Model-qualified views must not inherit family-only applicability. Preserve source diagnostics and coverage denominators unknown.
- [ ] Query supplies existing release reference inputs; public_projection rebuilds from closed registered source input/current evidence, strips private frames/extra fields and does not trust supplied reports. Add bounded root/metadata-first selected-field reading; old assets return unavailable with matching generation.
- [ ] Test v1/v2/native projection, source exclusions, wrong-generation/forged reports, privacy and byte limits. Focused checks and commit.

### Task 3: Customer envelope, native API and exports

**Files:** Create application/customer_comparison.py, schemas/customer-comparison-v1.json, tests/test_customer_comparison.py; extend http.py, exports.py/openapi.json and publication reader helpers.
**Interfaces:** build(study_summary,selected_history)->dict, csv_export(envelope)->str. Native GET /api/v1/customer-comparison uses existing vendor/scope/window/cves validation and optional format=json|csv; no extra collector/vault access. Envelope contains schema_version/publication/generated_at,study,release_history,limitations. Reuse existing selected study facts; do not recompute a new denominator.

- [ ] Red contract/query tests including duplicate/unknown parameters, old history asset, mixed identities, sparse sources, source-specific severity/KEV and scope selection, and fixed-only context that cannot increase affected/event counts.
- [ ] Use existing switching selection once and selected release report; enforce identical generation. Unknown history does not discard available study data. CSV distinguishes study_summary/release_reference/bundle_context/source_coverage rows, escapes spreadsheet controls and marks nonadditive repeated totals.
- [ ] Document native endpoint and static Pages limitation in OpenAPI/method. Test JSON/CSV and native/static-compatible semantics; focused checks and commit.

### Task 4: Customer comparison browser mode

**Files:** Create web/customer-comparison.js, tests/test_customer_comparison.js; extend web/app.js/index.html/delivery.js/publication-v2.js and style.css as required; regenerate schema contracts using existing generator.
**Interfaces:** InfrastructureCustomerComparison.build(studySummary,selectedHistory),selectHistory(history,studySelection),csvExport(envelope),render(envelope). Mirror Python source-selection semantics using shared fixtures. Add Comparison view option Customer switching comparison, beside existing benchmark/study modes. Same existing study controls; load history lazily via selected field/root API, never entire runtime snapshot.

- [ ] Red Python/JS shared vectors and loading/old-generation/failure tests. Match counts, unknowns, dates and scope qualifiers exactly.
- [ ] Display vendor CVEs, CVSS severity/provider context and on-demand individual score/vector details using existing lazy claim reads (no score average/ranking), plus KEV, explicit fixed releases with dates/unknowns, separate bundle context, source coverage and model/SKU limits. Label publication counts versus upgrades and cohort versus event dates. No ranking or misleading zero-history metric.
- [ ] Add JSON/CSV buttons from accepted envelope; trace source links and current claims. Maintain old modes and independent study filters. No private/operator controls in product UI.
- [ ] Test bounded lazy transport, errors/mixed generation, new view labels/actions, HTML escaping and source diagnostics; focused tests/lint/format and commit.

### Task 5: Integrated acceptance and publication

**Files:** Docs/README/method/research result and exact source configuration entries; integration tests as needed.

- [ ] Enable reviewed public Aruba history/model and Arista bundle reference URLs through existing collection only after all parser/report tests and source replay pass. Keep Cisco blocked source disabled; retain explicit not-collected state. No schedules/permissions/credential changes.
- [ ] Replay cached primary sources outside Git against current normalizers, validate fix-release/date associations without model inference, generate customer JSON/CSV and browser parity. Use actual capture times; no raw captures/private evidence in Git.
- [ ] Whole-milestone review, full Python/Node/CI once, generated schemas, public privacy/package checks and full existing candidate gates before rollout. Publish through existing trusted workflow; verify live identity/default+archive/browser and update customer brief with measured outcomes and source blockers. Do not end at code preparation if publication is authorized and feasible.
