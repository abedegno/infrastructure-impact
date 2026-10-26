# Family evidence, comparison readiness and fix leads

Three whole-publication research views build on each other. They are separate from
the browser's selected CVE cohort and from independent human adjudication.

The [comparison protocol](research/comparison-protocol.md) explains adjudication
and denominator requirements. Each cell now includes bounded publisher provenance,
including excluded undated/out-of-period statements. Fixed-only evidence remains
unresolved. [Source follow-up](research/source-and-component-followup-20261026.md)
documents the Arista 0105 adapter, remaining access gaps and three scheduled OSS
reference tables. Component references carry explicit patch/deployment limits;
different branches never form a before/after pair.

[Retrieval checks](SOURCE_OBSERVATIONS.md) are now logged separately from content
revisions, including unchanged HTTP 200 and cached HTTP 304 observations. Earlier
unlogged checks remain unknown. The component view displays the logging window,
bounded check history and alignment with the analyzed source fingerprint.

## 1. Product families

The versioned `product-families.json` catalogue selects 33 infrastructure families
across eight vendors. Each entry has publisher labels, optional all-platform
constraints, a source reference and selected release-line references to inspect.
This is a curated research scope, not an exhaustive vendor inventory or support
lifecycle catalogue. External vendors remain visible through unmapped statements
until a reviewed family definition is supplied.

`family-completeness.json` reports matching non-draft statements, CVE-specific and
shared scope, status counts, retained source fingerprints, missing version scope
and selected train-reference gaps. An unknown family is not unaffected. One matching
statement is evidence present, not evidence that every model or release is covered.
Mixed EX/SRX/QFX or SRX/MX platform statements are not split into family claims.

Train checks search literal publisher version fields and encoded version ancestry,
not hardware model names. They do not compare versions or establish an entire
train's affectedness. Unlisted trains have no curated expectation; they are not
implicitly covered. No model inventory, complete train list or cross-vendor product
normalization is claimed.

## 2. Comparison readiness

`comparison-plans.json` predeclares security-gateway, switching and management
family cohorts. Every member receives the same 24-CVE reference dependency cohort
and date period. The inherited benchmark is purposive and not statistically
representative. It is not filtered to each vendor's observed affected CVEs.

`comparison-readiness.json` shows each family/CVE cell and its gaps. Shared-only,
missing, undated, conflicting and fixed-only evidence does not establish a comparable
exposure assessment. Initial advisory dates group the latest retained statements;
this is not an as-of reconstruction or a date of individual CVE disclosure.

Requirements remain visible: complete scoped assessments, inventory denominators,
product/deployment equivalence, appropriate independent cohort design and independent
human review. Rates remain null and eligible comparisons remain empty. Full cells
alone cannot unlock statistical comparisons. No vendor ranking is produced.

## 3. Potential security-fix leads

`fix-leads.json` contains dated source hashes, alternative explanations and missing
evidence for investigation. It can detect:

- Literal component-version changes between two retained snapshots of the same
  product/release-note source. Version ordering and security purpose are not inferred.
- Security-related statements without an explicit CVE in the local reviewed block.
  Generic CVE/scanner notes and navigation text do not supply these leads.
- CVE associations added to release sections or publisher advisories between local
  observations. Parser reinterpretations do not supply advisory-addition events.
- Registered publisher chronology questions, including earlier-advisory counter-evidence.

Only named release sections are parsed; component table headings or explicit
update/bundling language are required. Multiple versions for one component remain
ambiguous. A first snapshot supplies a baseline, not an observed change. PDF release
section analysis is currently unsupported and remains a gap. The current configured
release sources do not necessarily contain explicit component manifests; a missing
component baseline is not evidence that no component update occurred.

Dates in a currently retained change log are publisher claims, not historical
captures. Local observations are not release dates. Lead records never establish a
hidden security fix, prior exposure, first disclosure, fix availability or intent.
The FortiProxy chronology question carries the retained earlier advisory as explicit
counter-evidence to inferring nondisclosure from a later documentation edit.

## Public contracts and extensions

Each report has a strict version-1 JSON schema, generation-bound JSON download and
read-only `/api/v1/` endpoint with the same hyphenated report name. GitHub Pages
serves the JSON files directly. Earlier generations without a report return 404
through the Python reader. Schemas are distributed in the wheel and publication.

The publication boundary recomputes reports, whitelists configured public release
URLs, removes intermediate release-analysis inputs, and excludes raw captures,
private review notes and arbitrary extra fields. Unsupported section layouts,
missing snapshots, component ambiguity and observation-scan truncation stay visible.
No database migration is required: inputs come from retained evidence, document
observations, advisory revisions and existing case files.

To extend coverage, review a family's publisher labels and platform restrictions,
add synthetic boundary tests, then update its catalogue entry. To watch an explicit
component manifest, register its official URL as a release document, review its
named section and retain a baseline. A later observation is needed to establish a
change. Do not replace missing source evidence with guessed component/product links.
