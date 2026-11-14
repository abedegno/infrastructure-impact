# Optional switching analysis delivery

This local, default-off export composes source-owned disclosure, KEV reconciliation,
model coverage, release chronology, and immediate-remediation scenarios. It does
not measure deployed exposure, observed upgrades, first CVE disclosure, or the
historical availability of a latest-known fixed target. Current CVE membership
may have been added after the advisory's initial date. Missing evidence remains
unknown. Human review is pending.

## Local opt-in

Use the packaged source configuration and an explicitly selected local evidence
home. Existing hosted commands and defaults are unchanged.

```sh
PYTHONPATH="$PWD" IMPACT_SOURCES="$PWD/infrastructure_impact/resources/sources.json" \
  IMPACT_HOME=/tmp/impact-analysis-local .venv/bin/python -m infrastructure_impact \
  snapshot --publication-format v2 --include-switching-analysis \
  --switching-analysis-input /tmp/switching-analysis-input.json --output /tmp/switching-public
```

The flag does not acquire sources. The selected home must already contain the
intended normalized public evidence. Python callers can pass
`include_switching_analysis=True` to `publication.public_projection`, `publish`,
or `build`. Supplied public analysis is discarded and rebuilt at the newly
allocated publication identity, rather than restamped.

Optional native inputs belong in `research.switching_analysis_input`:

```python
{"api_results": [], "policy_source": None, "calibration_records": []}
```

The CLI reads this JSON only from an explicit `--switching-analysis-input` path and
requires `--include-switching-analysis`. Python `publication.build` accepts the
same object as `switching_analysis_input=`; direct `publish`/`public_projection`
callers attach it to `research.switching_analysis_input`. The frame is private
input and removed before public cloning. Omission means
unknown. Malformed frames and unknown keys fail closed. `api_results` uses the
existing first-fixed receipt-bound acquisition contract; it cannot substitute
credentials or an unacknowledged API response. `policy_source`, when present,
uses the disclosure module's exact verified `{url, sha256, retrieved_at}` receipt
contract. Map an already-verified cached policy receipt into those three fields;
never substitute the local path for its official URL. `calibration_records` is an
optional list of schema-validated normalized advisories carrying their original
URL/hash/capture time. These extend only the native first-fixed catalogue/heldout
source inputs; they cannot add current affected claims, model coverage, disclosure
pairs or KEV vendor observations. The native first-fixed module recalculates its
heldout evaluation at the new publication identity using current records plus
these explicit records. It does not restamp a prior calibration report. With no
extra records, only already-owned current records contribute; absent support is
unknown. API results are absent unless explicitly supplied. No new fetching,
source interpretation, credentials, or calibration inference engine is added.

## Native and portable contracts

`application.switching_analysis` exposes:

- `compile_requirements(evidence, first_fixed_report, release_history, kev_selection, *, publication, generated_at, max_bytes=128_000_000)`.
- `build_report(records, retained, study, *, release_history=None, source_frame=None)`.
- `validate_requirements(report, *, evidence=None)` and `validate_report(report, *, evidence=None, records=None, retained=None, publication=None, generated_at=None)`.
- `selection_context(compiled, options)`, `select_report(compiled_or_none, context, *, max_bytes=128_000_000)`, and `select_upgrades(requirements_or_none, context, *, max_bytes=128_000_000)`.
- `project_native(native_upgrade_report, full_native_study_selection)` is an offline oracle; it checks actual native contributing ownership, risk, methods and proofs before the same public projection.
- `csv_export(selected_upgrades, *, max_bytes=128_000_000)` and `analysis_csv_export(selected_analysis, *, max_bytes=128_000_000)`.

The closed `switching-analysis-v1.json` schema contains `compiled`, `compact`,
`selected`, `selected_upgrades`, and `model_coverage` definitions. Its canonical
fingerprints use the existing switching definition hash; list-valued shared facts
are hashed as `{"items": value}`. Content hashes omit only `content_sha256` itself.

The immutable `switching-analysis.json` root contains:

- `requirements.members`: exact per-claim ownership/hash, vendor/family/CVE/advisory,
  model-qualified scope, initial UTC day, tri-state risk and KEV membership.
- `requirements.facts`: content-addressed source receipts, proof arrays, severity
  facets and affected-train bindings; requirements refer to these tables.
- `requirements.requirements`: every native requirement, including unknown and
  nonadvancing requirements, alternatives, targets, issues, scenario and inference.
- Complete source-owned inference groups and migration/source groups, plus an
  explicit membership count/digest and complete evidence digest.
- A slim `claims` projection for disclosure/KEV/model selection. It contains only
  public selection facets, bindings, bundle proof and derived disclosure severity;
  it contains no full claims, source bodies, private notes, remediation catalogue,
  native upgrade matrix, or first-fixed catalogue.
- Source-bound disclosure and KEV facts and optional release history at the same
  publication identity. Filtered aggregates are recomputed from owned members.

The shared native `switching_upgrades.prepare_report` validates complete inference
groups and yields requirements. The compiler deduplicates incrementally before
any global upgrade matrix. Vendor, requested CVEs and model-qualified scope filter
requirements **before** the shared full-history walk. Window slicing follows the
walk; state never resets in January. `requested_cve_ids=null` means the full
cohort, independently of effective window CVEs. Same-day targets count once and
unknown risk/targets remain partial. Native catalogue reconciliation retains
mapped entries absent from vendor sources and marks explicit-filter exclusion.

The selected upgrade DTO retains native rows plus the selected compact ownership
and proof tables, rather than repeating detailed native constraints. Comparison
against the offline oracle covers membership and source proofs, not merely totals.
`tests/fixtures/switching-analysis-vectors.json` supplies exact JSON and CSV vectors
for pre-window state, a previously redundant requirement becoming decisive under
CVE filtering, model-qualified scope and unknown dates.

## Delivery and bounds

V1 writes an optional sidecar; v2 writes a bounded logical root. The static index
has an optional `switching_analysis` summary/fragment descriptor. The root is
excluded from snapshot/bootstrap/runtime defaults and never requires full study
claim hydration. Existing 128 MB selected, 512 MB working, 8 MB part and 2 MB index
limits are unchanged; oversized results fail rather than discard facts.

`PublicationReader.switching_analysis(study_selection=None, *, options=None)`
authenticates identity before reading arrays. Missing optional roots return an
unavailable envelope; malformed present roots and current-reference mismatches
fail closed. Disclosure child pairs must have complete, exact claim/source
ownership in the compact current membership; KEV current-claim references must
equal their native projections. The builder and common writer pass both
`records` and `retained` to validate child record references against the
authoritative current/retained partition. When validating with complete
`evidence`, record-bearing children require both record authorities; omitting
them cannot silently skip that proof. V1 HTTP also checks against its accepted
current/retained records and strictly reads at most the selected-byte limit plus
one byte before decoding the optional sidecar. A present JSON null is malformed.
`publication-export --root switching-analysis.json` uses the existing
v2 streaming exporter.

Both native formats expose `/api/v1/switching-analysis` and
`/api/v1/switching-upgrades`, accepting the existing strict `vendor`, `scope`,
`window`, `cves`, and `format=json|csv` queries. Unknown, blank, repeated and
noncanonical values are rejected. Analysis CSV uses
`row_type,vendor,cve_id,year,event_count,payload`; the payload is the exact typed
section row as JSON. Upgrade CSV preserves the native row columns. Unknown
scalar cells are blank; both use the shared spreadsheet-safe UTF-8 byte-bounded
writer. OpenAPI points to the exact selected schema definitions.

Portable JS selection, browser controls, the full known-source measurement and
final human review belong to the subsequent delivery task. They must use these
compact facets and parity vectors, without hydrating the full claim catalogue or
performing vendor parsing/inference in JavaScript.
