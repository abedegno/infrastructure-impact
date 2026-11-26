# Optional packed switching analysis preview

**Measured preview: do not activate.** The [paired public-data measurement](research/2026-11-26-packed-analysis-preview.md) found no meaningful loading improvement and higher reader traffic. This remains an experimental local opt-in.

A local v2 publication can carry a packed copy of its complete compiled switching analysis. The packed root is disabled by default. It preserves every claim, requirement, field, observation bound, and source reference. Selections still use the existing analysis logic and the same JSON and CSV export functions.

Given a sanitized native projection with complete switching analysis, write to a fresh local directory.

```python
from infrastructure_impact.application.publication_v2 import write_bundle

write_bundle(preview_directory, public_projection, analysis_packed_delivery=True)
```

The same strict boolean keyword is available on `publication.write_bundle` with `publication_format="v2"`. Packed delivery and `analysis_vendor_delivery=True` are mutually exclusive. Hosted configuration requires a separate activation decision.

Native inspection is available without writing a publication.

```python
from infrastructure_impact.application.analysis_packing import pack_report, unpack_report

packed = pack_report(public_projection["switching_analysis"])
compiled = unpack_report(packed)
```

Both functions accept `max_bytes` as a keyword. The existing 128 MB selected-value ceiling still applies. `unpack_report` returns independently mutable data.

## Wire format and validation

`switching-analysis-packed.json` has schema version `1` and representation `packed-analysis`. It binds the publication, generation time, study definition, observation end, original source fingerprint, complete source byte count, and its own canonical content fingerprint.

- `skeleton_json` retains the complete source with three null placeholders at `claims`, `requirements.members`, and `requirements.requirements`.
- `layouts` holds distinct ordered lists of property names. Each claims or members row holds a pooled key ID, a layout ID, and pooled field IDs in layout order. Requirement rows start with a layout ID. `counts` records the size of each table.
- `values_json` holds distinct compact JSON literals. The skeleton and each pool entry use consecutive text chunks of at most 65,536 Unicode code points so a large literal fits the existing v2 part limit. Joining the chunks preserves native numeric spellings, nested order, and Unicode.

Preparation checks the envelope, table counts, required and permitted layout keys, indexes, duplicate keys, and pool closure. The declared source size must equal the expanded raw UTF-8 size. The browser also charges the requested JavaScript serialization, which can use a different number spelling. These checks run before expanded row allocation. Native and browser readers then run the complete compiled-analysis shape, fingerprint, and semantic validation. Independent publication verification regenerates the exact packed root from fresh native analysis.

## Browser loading and compatibility

When the catalog advertises the packed root, both All and individual vendor selections use it. The browser checks the root size and expanded-source metadata under each caller's budget. Shared preparation and metadata reads give each caller independent cancellation and deadlines. A failed fetch can be retried. A malformed advertised root produces an error. A catalog without the packed root uses its existing full or [vendor delivery](ANALYSIS_DELIVERY.md) path.

The browser prepares a frozen private report and returns separately mutable selection results. The original `switching-analysis.json` root and its legacy descriptors are still emitted. Native `PublicationReader.switching_analysis()` continues to select from the original root.

## Size and preparation cost

On the public generation `e05fc9e8e5ce404190173f4c3c037498`, the packed logical value was 47,156,423 bytes versus 126,637,532 bytes for the compiled source. The native round trip reproduced the original compact JSON byte for byte. These sizes describe logical values. The browser still reads shared v2 dictionaries, reconstructs the complete source, and validates it before selection. Transfer, latency, and peak memory require separate measurements.
