# Normalized advisory schema v2

`infrastructure_impact/schemas/advisory-v2.json` is the canonical JSON Schema Draft
2020-12 contract. It is served at `/schemas/advisory-v2.json`.
`impact validate advisory.json` performs local validation. Runtime checks also
enforce CVE scope, source/vendor identity and unique CVE/product identities.

## Record fields

| Fields                                        | Meaning                                                                     |
| --------------------------------------------- | --------------------------------------------------------------------------- |
| `schema_version`                              | Data-contract major, currently integer `2`. Unsupported majors fail.        |
| `vendor`, `advisory_id`                       | Registered vendor ID and stable publisher advisory identity.                |
| `title`, `source_url`, `source_format`        | Source title and captured representation.                                   |
| `advisory_url`                                | Optional human-facing article when capture used an API or index.            |
| `adapter_version`                             | Code/parser fingerprint, distinct from publisher revisions.                 |
| `published_at`, `updated_at`                  | Nullable publisher dates/times; never local collection time.                |
| `document_status`                             | Draft/interim/final/published/unknown/rejected source state.                |
| `cves`                                        | Explicit advisory scope, excluding incidental/background references.        |
| `assessments`                                 | Product assertions described below.                                         |
| `notes`, `metrics`, `timeline`, `warnings`    | Scoped context and extraction limitations.                                  |
| `evidence_id`, `sha256`, `source_observed_at` | Storage-attached snapshot identity, raw-source hash and first capture time. |
| `revision_id`, `observed_at`                  | Normalized revision identity and local creation time.                       |
| `reported_fix_date`                           | Bulletin-reported date, not verified public availability.                   |
| `extensions`                                  | Optional plugin data; excluded from public projection by default.           |

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

Remediation date classification is deterministic. The standards, HPE bulletin
and legacy HTML adapters compare dated targets with the document's publisher
update date, falling back to its initial date only when no update date is supplied.
They never compare with the collection or replay clock. An invalid update date,
or one preceding the initial date, cannot supply that context. A future target
remains `planned` as of the document; missing date context and a month-only target
overlapping the document month remain `unknown`. Existing explicit ETA, TBD,
upcoming, scheduled and future-tense plan expressions remain planned even after
their dates pass. Shared remediation text can contain several release options;
consult those expressions rather than treating one availability label as a
complete release inventory. Date comparisons use publisher calendar days, not
inferred UTC instants or verified download timestamps.

Older normalization revisions retain their original interpretation and parser
identity until reprocessed. A correction based on the same retained bytes is a
parser reinterpretation, not a publisher change or new disclosure. See the
[retained-source review](research/remediation-date-replay-20261027.md).

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

## Component-reference normalization

`schemas/component-inventory-v1.json` is a separate strict writer contract, served
at `/schemas/component-inventory-v1.json`. Validate a normalized result with:

```sh
impact validate component.json --schema component-inventory
```

The envelope contains `schema_version: 1`, `state: scoped`, `component_scope`,
`components` and `blocks`. Components map lowercase names to nonempty, unique lists
of literal version expressions. Every block has a nonempty `locator`, source
`text` and a list of explicit CVE references. These references do not establish
component or appliance affectedness. The contract does not compare version
schemes, verify a shipped binary, resolve backports or represent an unversioned
presence claim by inventing a version.

The registry copies hook output, supplies the v1 major when omitted by an existing
hook, rejects unsupported majors/unknown fields/non-JSON values, and validates
before a configured component baseline is stored or research analysis consumes
it. A failed new collection preserves the previous baseline. A rejected retained
analysis becomes a scope-review gap. `None` retains its distinct meaning: the
plugin does not recognize this route, so existing generic release-section
analysis may apply.

Optional `extensions` and raw block text remain writer data. Public fix-lead
reports use their separate projection and schema; they expose configured source
fingerprints, scope and the six reviewed component names rather than the raw
normalization envelope. Additional component names can be retained by a trusted
plugin but need projection review before public reporting. No database migration
is needed: normalized component analysis is derived from retained document bytes,
whose original fingerprints and capture dates remain authoritative.

## Release listing metadata

`schemas/release-asset-v1.json` is a separate strict contract for public firmware
metadata. It preserves vendor/product/build, platforms, publisher date, filename,
publisher artifact checksum and adapter fingerprint. It has no CVE-assessment
fields. Captured source fingerprints and local evidence IDs are attached by the
repository, separately from publisher artifact checksums. Evidence IDs are local
to a vault; use the source fingerprint when resolving a record across vaults.

Listing metadata does not prove file entitlement, historical public availability
or a CVE/product association. Repeating a state is idempotent; returning to an
earlier metadata state creates a new observation rather than leaving the newer
state current.

## Browser-assisted evidence and release histories

`schemas/browser-capture-v1.json` describes an operator-supplied browser DOM
capture envelope, including source URL, observed time, browser name, scope and
rendered HTML hash. It is stored as capture-envelope evidence, never as an HTTP
response. `schemas/release-history-v1.json` describes normalized dated publisher
statements without CVE applicability or invented firmware checksums. Browser
summaries remain private and separate from the release-asset/publication path.
See [BROWSER_CAPTURE.md](BROWSER_CAPTURE.md) for provenance and completeness limits.
