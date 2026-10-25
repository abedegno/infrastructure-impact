# Normalized advisory schema v2

`infrastructure_impact/schemas/advisory-v2.json` is the canonical JSON Schema Draft
2020-12 contract. It is served at `/schemas/advisory-v2.json`.
`impact validate advisory.json` performs local validation. Runtime checks also
enforce CVE scope, source/vendor identity and unique CVE/product identities.

## Record fields

| Fields | Meaning |
| --- | --- |
| `schema_version` | Data-contract major, currently integer `2`. Unsupported majors fail. |
| `vendor`, `advisory_id` | Registered vendor ID and stable publisher advisory identity. |
| `title`, `source_url`, `source_format` | Source title and captured representation. |
| `advisory_url` | Optional human-facing article when capture used an API or index. |
| `adapter_version` | Code/parser fingerprint, distinct from publisher revisions. |
| `published_at`, `updated_at` | Nullable publisher dates/times; never local collection time. |
| `document_status` | Draft/interim/final/published/unknown/rejected source state. |
| `cves` | Explicit advisory scope, excluding incidental/background references. |
| `assessments` | Product assertions described below. |
| `notes`, `metrics`, `timeline`, `warnings` | Scoped context and extraction limitations. |
| `evidence_id`, `sha256`, `source_observed_at` | Storage-attached snapshot identity, raw-source hash and first capture time. |
| `revision_id`, `observed_at` | Normalized revision identity and local creation time. |
| `reported_fix_date` | Bulletin-reported date, not verified public availability. |
| `extensions` | Optional plugin data; excluded from public projection by default. |

The core envelope rejects unknown fields. Storage metadata is attached by the
repository. All assessment CVEs must be in `cves`; duplicate CVE/product identities
are rejected rather than silently overwriting a platform-specific assertion.

## Assessments and scope

Each assessment has `cve_id`, `product_id`, `product`, `status`, `scope`, `versions`,
`remediations`, `exposure` and `evidence_locator`. Optional platforms, CPE/PURL
identifiers, families, relationships and product context preserve qualifications.
Product IDs are vendor-native identities, not a universal cross-vendor ontology.

States are `affected`, `unaffected`, `fixed`, `partially_mitigated`,
`investigating`, `unknown`, `recommended` and `conflicting`. Unaffected can mean
the vulnerable package is present but an exploitation prerequisite is unavailable;
retain the rationale rather than implying absence or a patch.

`cve_specific` means the source separately encodes that CVE's assertion.
`bulletin_shared` means a common table or statement spans multiple CVEs; it is not
separately established per-CVE applicability. Platform-specific rows remain
distinct, including when product labels are identical.

Versions retain original expressions, custom bounds and version schemes. IOS,
Junos and appliance take numbers are not ordered by generic semantic-version
logic. Remediation availability distinguishes planned, vendor-reported fixed,
partial mitigation, unavailable, no-fix-planned, not-a-fix and unknown. A claimed
fixed version does not independently establish download availability.

## Time, provenance and compatibility

Publisher values may be dates, offset-aware timestamps, or local timestamps with
an unspecified timezone. The latter use the explicit `local-date-time` format,
are warned about, and are excluded from UTC timing calculations. Capture/revision
timestamps are offset-aware. The UI does not silently convert unknown local times.

Source-view switches, parser reinterpretation and source revisions remain distinct.
The raw source hash refers to retained bytes, not the normalized JSON. The public
reader exposes fingerprints and locators, never raw source text.

The data major is independent of package and HTTP API versions. Additive optional
fields require schema/documentation updates and consumer checks. Breaking meaning,
renames or required-field changes need a new major and explicit migration.
Publisher layout changes need regression fixtures, a parser version/code change,
replay and audit. Never silently rewrite historical evidence.
