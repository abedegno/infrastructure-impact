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
  IMPACT_HOME=/tmp/impact-analysis-local IMPACT_DATABASE=/tmp/impact-analysis-local/public.sqlite \
  .venv/bin/python -m infrastructure_impact.cli \
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

The Comparison view offers an explicit **Load optional analysis** button. Neither
bootstrap nor the default study loads this root. Accepted study vendor/family,
model-qualified scope, CVEs and window select compiled ownership before the walk.
The additional family/train/year/policy/scenario controls filter displayed matrix
rows; exports retain the entire accepted study selection and all scenario axes.
JSON, typed analysis CSV and upgrade CSV use the same accepted object. Async
selection changes and publication changes cannot replace it with a stale result.
Missing optional roots display unavailable; present malformed roots reject.

Static Pages supplies this browser adapter and downloadable exports, not a
persistent REST service. Native `/api/v1/switching-analysis` and
`/api/v1/switching-upgrades` retain their strict vendor/scope/window/cves/format
contract. No new endpoint train/scenario parameters are implied by display controls.

Nested CSV JSON uses exact binary64 decimal tokens (including `9.0` as `9`)
without changing numeric values. Fractional tokens may be longer than ordinary
report JSON; both runtimes reuse the canonical numeric identity convention. Regenerate/check the authored native-oracle vectors with:

```sh
PYTHONPATH="$PWD:$PWD/tests" IMPACT_SOURCES="$PWD/infrastructure_impact/resources/sources.json" \
  IMPACT_HOME=/tmp/impact-analysis-check .venv/bin/python \
  checks/generate_switching_analysis_vectors.py --check
node tests/test_switching_analysis.js
node tests/test_switching_analysis_delivery.js
```

The generator checks each selected upgrade DTO against the detailed offline
native oracle before writing exact JSON and both CSV expectations. Numeric tests
include integral/fractional CVSS, signed zero and a calibration rate. Browser code
never parses vendor documents, infers fixes, or hydrates the full claim catalogue.

Supplementary typed source checks have an explicit offline command. They augment
claim extraction checks and keep independent human review pending:

```sh
PYTHONPATH="$PWD" IMPACT_SOURCES="$PWD/infrastructure_impact/resources/sources.json" \
  IMPACT_HOME=/tmp/impact-analysis-check .venv/bin/python \
  -m infrastructure_impact.application.switching_source_validation \
  --records-input /tmp/public-current-evidence.json \
  --analysis /tmp/compiled-analysis.json --chronology /tmp/chronology-repair.json \
  --output /tmp/switching-source-validation.json
```

This reads only the supplied normalized public inputs and writes computation time
and SHA-256 receipts. Checks cover pinned hardening metadata/stated targets,
SA137 family-versus-model/KEV semantics, and three pinned chronology cases.
Unavailable sources stay outside evaluated denominators; Aruba has no pinned
supplementary case and is explicitly unavailable, not a zero-error success.
No source acquisition or default database is opened by this command.

The local source frame does not configure credentials. If acknowledged official
API acquisitions are available, supply their native receipt-bound frames through
`api_results`; otherwise leave it empty. Keep any collection credentials in the
collector's documented environment outside the exported JSON. This feature adds
no secret mapping, new API client, hosted activation, schedule or deployment.

The optional claim-facet table contains every claim within the frozen study's
exact vendor/family pairs, including unknown statuses, missing/future dates,
drafts and unresolved model scope. It omits only unclassified or other-family
facets that no supported study selection can admit. This is not a zero-exposure
claim. The complete native evidence and its digest remain authoritative; upgrade
requirements, advisory current/retained inventories and all CISA candidates are
unchanged. Full-source run receipts separately record excluded-facet count and
identity digest. `study_claim_facets(evidence)` exposes this exact projection to
reproducible measurement code.

Compact claim facets store `source_ref`, a content-addressed receipt in
`requirements.facts`, instead of repeating source objects. Native
`claim_facets(report)` and browser `claimFacets(report)` inflate only that receipt;
they never load full claims. References must resolve to the closed source type.
Affected members already own these source facts; only missing receipts for other
study-family statuses are added. The requirement content fingerprint is recomputed
after pooling, while the complete membership/evidence digests retain their meaning.
Source and severity references remain solely on each owning requirement member;
requirements carry only proof/train-binding references. Selected upgrade repacking
prunes unused claim-only sources and remains exactly native-oracle equivalent.

The first full-source attempt failed the unchanged128MB aggregate bound. Size
preflight measured82,311,614 bytes of requirements and46,729,260 bytes of exact
study-family facets. Their129,040,874-byte sum already exceeded that bound before
other child reports. Source pooling addresses15,131,048 bytes of inline receipt
values: replacing36,482 values with64-character hashes has an estimated net saving
of12,577,308 bytes, before any newly interned nonaffected receipts. Thus116,463,566
bytes is only a partial two-component estimate, not proof of aggregate fit. Actual
root/selected/working measurements and remaining children belong to the final
source-run receipt. Limits are unchanged; unknowns are not dropped to fit.
