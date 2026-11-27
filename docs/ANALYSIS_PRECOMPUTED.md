# Precomputed analysis preview

The [four-view public-data replay](research/2026-11-26-precomputed-analysis-preview.md) found a useful loading improvement with exact exports. Delivery remains disabled by default. The later [worker/eight-view verification](research/2026-11-26-analysis-worker-verification.md) records browser behavior, measured capacity and retained-artifact inventory, with explicit memory and cold-time limitations.

The v2 publication writers accept `analysis_precomputed_delivery=True` to build
a local preview from a complete public switching-analysis projection. Both
writers default to disabled. This preview is an alternative to the existing
vendor-delivery preview. The [named operator profile](HOSTED_SERVICE.md) now wires
these options through the snapshot and hosted paths; live hosted activation
remains separately gated. The closed `campus-switching-common-views-v1` profile
fixes the year to 2025 and does not use the rolling low-level default below.

Pass `analysis_precomputed_options` as a list of selection dictionaries. The
supported keys are `vendor`, `window`, `scope_level`, and `cve_ids`. Omitted fields
mean All vendors, all years, OS family, and no explicit CVE filter. The writer
accepts up to 32 distinct selections. A supplied CVE subset, including an empty
list, uses the existing compiled reader. Without an options list, the writer
selects All vendors and each named vendor for the all-years window and the
previous calendar year when that year is within the study. The [worker/eight-view verification](research/2026-11-26-analysis-worker-verification.md)
certifies the explicit eight choices for the pinned generation. Future generation
cutoffs and profile changes require a fresh capacity check.

```python
from infrastructure_impact.application import publication_v2

options = [
    {"vendor": "cisco", "window": "2025"},
    {"vendor": "aruba"},
    {"vendor": "arista"},
    {},
]
publication_v2.write_bundle(
    destination,
    public_projection,
    analysis_precomputed_delivery=True,
    analysis_precomputed_options=options,
)
reader = publication_v2.inspect_bundle(destination, {})
publication_v2.verify_projection(
    reader, public_projection, analysis_precomputed_options=options
)
```

Use a fresh destination. Supply the same explicit options from an independent
configuration when verifying a pilot. Verification derives selection membership,
decoded bytes and gzip parts again from the native public facts, checks the
on-disk manifest sidecar and parts, and streams the ordinary logical roots.

The earlier [in-page browser check](research/2026-11-26-precomputed-browser-check.md)
found a 9.3-second main-thread task. The subsequent
[worker and eight-view check](research/2026-11-26-analysis-worker-verification.md)
reduced the captured cold Cisco task to 365 ms, preserved all checked exports and
verified the complete publication plus accepted artifact inventory. Cold wall
time increased in that run; memory figures have different scopes. Hosting stays
disabled until a separate activation proposal is approved.

## Format and reader behavior

`switching-analysis-selected.json` is an ordinary v2 logical root. Its compact
manifest bytes also live at `data/v2/<logical SHA-256>.json`, authenticated by the
root metadata. Eligible browser reads use that sidecar and the listed chunks
without loading the complete analysis or global string and shape tables. The
manifest binds generation, study definition and observation cutoff, source
fingerprint and complete accepted cohort for each option.

Each selected DTO is one compact native UTF-8 JSON document. The writer slices
it every 4,000,000 decoded bytes and emits deterministic single-member gzip
files at `data/v2/<wire SHA-256>.json.gz`. A boundary may split a Unicode
character or a JSON token. Readers authenticate the individual wire and decoded
slices, assemble the bounded document and check its aggregate digest before
strict UTF-8 and JSON parsing. The 8 MB physical-part, 128 MB selected-result,
16 MB raw-cache and 1 GB site ceilings still apply.

Legacy publications and selections without an advertised view use the existing
compiled source. The browser also uses that path when gzip support is
unavailable. An advertised eligible view with corrupt content raises an error.
The browser retains one prepared view and returns a mutable copy per caller.
Native JSON retains native key order. The browser uses the compiled reader's
facts-map order for exact JSON downloads and preserves both CSV exports.

## Browser worker and downloads

The preview writer builds a standalone classic worker from the packaged browser
reader and validators. The preview page pins its SHA-256 filename on the client
script. The worker loads from the same immutable assets directory under the
publication's base path. Serve these files with the publication.

`await reader.switchingAnalysis(study, options)` returns a complete mutable
selected report. For an advertised view, the worker authenticates, decodes and
validates the report, and the browser delivers an independent structured clone.
`await reader.switchingAnalysisExport(study, format, options)` returns a fresh
UTF-8 `Uint8Array` for `json`, `csv` or `upgrades-csv`. It returns `null` for
an unsupported format or route. A configured worker failure or corrupt view
rejects the operation. A subsequent call can retry. The controls use the
accepted study and publication from the clicked panel.

Both methods accept `max_bytes`, `signal` and `deadline` (milliseconds since
the Unix epoch). The selected report and each encoded download must fit the
applicable byte cap. Physical requests use the reader's existing cache and
six-request pool. Consecutive callers for the same view share preparation.
Cancelling one caller leaves interested callers running. Different views
queue, and the worker keeps one prepared report. Each delivered report and any
download held by a caller contribute additional browser memory.

Without Web Worker support an eligible read uses the original in-page selected
reader, and the UI encodes its accepted report for download. The worker releases
its prepared report after 60 seconds idle. The application retires the old
reader when an accepted publication is replaced, allowing outstanding exports
to finish. A caller closing a reader can use `reader.dispose()` to terminate
its analysis worker and cancel outstanding worker requests immediately.
