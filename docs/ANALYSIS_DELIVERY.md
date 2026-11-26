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

A publication without the manifest uses the existing full-root path. All-vendor selection also uses the full root. The Python `PublicationReader.switching_analysis()` remains on its legacy full-root path; the new native projection API and browser loader are the preview surfaces.

Year and train controls do not reduce delivery in this version. JSON and both CSV exports include all trains, policies and scenarios for the accepted study. The upgrade walk needs earlier version state and taint, and compact selected requirements retain members outside the requested window. Dropping those dependencies would change exports.

## Validation and limits

Focused tests cover exact selected JSON and both CSV exports against complete native/public-vector reports, vendor/scope/window/CVE combinations, historical carry, undated claims, referenced groups, history, KEV entries, native regenerated omissions, scenario removal, accessor rejection, immutable preparation, lazy loading, cache behavior, selected-byte limits, missing advertised roots and absent-manifest compatibility.

No new dependencies or byte limits are introduced. Vendor splitting duplicates some metadata/history in the offline artifact and leaves the full legacy root in place. Each envelope and each selected export must still fit the existing 128 MB limit; the complete publication must fit its existing site budget. A vendor that exceeds the bound causes preview generation to fail. This change therefore does not remove the legacy All-vendor ceiling.

The retained public-generation benchmark has not been rerun for this preview. Fixture parity and request-path tests establish correctness, not production speed or memory savings. A public-artifact benchmark and hosted-format review are required before activation.
