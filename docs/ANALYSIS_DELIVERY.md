# Optional vendor analysis delivery preview

Vendor delivery is inactive by default. The preview API adds four v2 logical roots while retaining `switching-analysis.json` unchanged. No publish command, deployment workflow or hosted configuration enables it automatically.

Given an already sanitized public projection with complete analysis:

```python
from infrastructure_impact.application.publication_v2 import write_bundle

write_bundle(preview_directory, public_projection, analysis_vendor_delivery=True)
```

The ordinary publication validation gate still validates the complete source, current/retained record authority and evidence before writing. The lower-level public-report API is also available for local inspection:

```python
from infrastructure_impact.application.analysis_delivery import project_vendor, validate_vendor

envelope = project_vendor(validated_public_analysis, "cisco")
validate_vendor(envelope, source=validated_public_analysis)
```

Use a fresh preview directory. These APIs write artifacts; they do not activate a hosted publication. Preview publication requires v2 and complete optional analysis. False is the default; unsupported flag types and v1 opt-in are rejected.

## Contract and validation

`switching-analysis-delivery.json` binds publication, generation, study definition, observation end and the complete source report fingerprint. Each exact vendor descriptor names a fixed vendor root and commits its envelope fingerprint and claim/member/requirement counts. The manifest has its own content fingerprint.

Each `switching-analysis-vendor-{vendor}.json` envelope declares schema version 1 and representation `compiled-analysis-vendor`. It carries identity/bounds, source fingerprint, vendor, membership counts, payload and content fingerprint. Envelope and manifest fields are closed and checked explicitly; the payload continues to use the existing compiled-analysis JSON schema and semantic validator. Existing lossless JSON parsing, authenticated v2 token/range transport and budget guards apply unchanged.

The payload contains every claim and upgrade requirement for its vendor across all dates, trains and scenarios. It retains referenced facts and complete referenced inference/source groups. Release history stays complete, including global sources/diagnostics. Disclosure children are projected by vendor. KEV children retain both selected-vendor entries outside the effective cohort/CVE filter and globally unmapped entries. Child complete-selection metadata is normalized to the projected payload; ordinary selection overwrites this metadata and recomputes selected summaries.

The native projection function validates the complete source first. `validate_vendor(..., source=...)` independently validates that source and regenerates exact closure, detecting omissions even when caller-owned hashes/counts have been recomputed. The publication's independent `verify_projection` gate derives the optional roots from fresh native facts and compares exact root membership and logical hashes. Unadvertised extra roots and missing advertised roots fail verification.

The browser freezes each decoded envelope, validates all applicable existing compiled invariants, and checks explicit vendor ownership plus manifest-advertised fingerprints/counts. Accepted-study cohort equality remains mandatory for every selection. Returned values are independent selected objects; changing them does not mutate cached source data.

## Loading and compatibility

Only an explicit optional analysis request for one vendor reads the manifest and that vendor projection. Failed preparation can be retried. Advertised malformed manifests, missing vendor roots, mixed generations, bad hashes, incomplete scenario ownership and budget failures are errors; they do not trigger a fallback.

A publication advertising the [packed analysis preview](ANALYSIS_PACKING.md) uses that root for all selections. Without that preview, All-vendor selection uses the full root, as does single-vendor selection when the vendor manifest is absent. The Python `PublicationReader.switching_analysis()` remains on its legacy full-root path; the new native projection API and browser loader are the preview surfaces.

Year and train controls do not reduce delivery in this version. JSON and both CSV exports include all trains, policies and scenarios for the accepted study. The upgrade walk needs earlier version state and taint, and compact selected requirements retain members outside the requested window. Dropping those dependencies would change exports.

## Validation and limits

Focused tests cover exact selected JSON and both CSV exports against complete native/public-vector reports, vendor/scope/window/CVE combinations, historical carry, undated claims, referenced groups, history, KEV entries, native regenerated omissions, scenario removal, accessor rejection, immutable preparation, lazy loading, cache behavior, selected-byte limits, missing advertised roots and absent-manifest compatibility.

No new dependencies or byte limits are introduced. Vendor splitting duplicates some metadata/history in the offline artifact and leaves the full legacy root in place. Each envelope and each selected export must still fit the existing 128 MB limit; the complete publication must fit its existing site budget. A vendor that exceeds the bound causes preview generation to fail. This change therefore does not remove the legacy All-vendor ceiling.

The accepted public generation `141c2f9dc8f04c12a795ac819e7b4c8e` passed a local native projection/export proof for all three vendors. The [sanitized receipt](research/2026-11-26-analysis-vendor-delivery-proof.json) records fingerprints, counts and measured logical sizes; no source records were copied into the receipt.

| Delivery object | Logical bytes | Representative exact export comparison |
| --- | ---: | --- |
| Complete legacy report | 126,633,200 | Source authority for each comparison |
| Cisco envelope | 122,781,333 | Cisco, 2025 |
| Aruba envelope | 3,839,930 | Aruba, window `all` |
| Arista envelope | 3,390,303 | Arista, window `all` |

Logical sizes exclude the decoded file's trailing newline (the complete file is 126,633,201 bytes). Each vendor proof called `project_vendor`, validated the envelope against a freshly validated complete source with regenerated closure, and compared selected JSON structures and both CSV export bytes exactly. All three comparisons passed. Selected JSON fingerprints use the native canonical fingerprint; CSV hashes cover UTF-8 export bytes.

Cisco is only about **3.04% smaller** than the complete report and remains the dominant delivery cost. All-vendor selection still loads the complete legacy root. This split therefore provides substantially smaller vendor objects for Aruba and Arista while leaving the main Cisco scaling problem unresolved.

The recorded native proof elapsed times (Cisco 227.50 seconds, Aruba 44.99 seconds, Arista 42.85 seconds) include repeated full-source validation, projection/regeneration, both selections, export comparison and size measurement. They are neither browser latency measurements nor CPU-time measurements. No browser speed or memory guarantee follows from these results, and no additional speed benchmark was run.

The complete retained-generation preview bundle, aggregate hosted/site budget, browser network/latency behavior and hosted-format activation review remain pending. The small fixture publication tests do not establish those gates. No hosted activation is authorized or performed by this proof.
