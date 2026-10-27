# Build inventory evidence proposals

A firmware release reference is not an inventory. A vendor-neutral, offline
proposal workflow now records the evidence needed to investigate an exact build.
It uses installed vendor plugins for official-source policy and accepts any
component and service role. It does not parse arbitrary SPDX/CycloneDX files,
extract firmware, connect to devices or infer vulnerable versions.

The two-vendor **Product cohorts** pilot provides a blank JSON proposal for each
selected build. The download contains only research target labels and unknown
fields. It does not inherit advisory conclusions, upload evidence or submit a
review. A side-by-side table shows field evidence states and the latest advisory
check separately; an access failure does not erase retained evidence.

## Prepare a proposal

Generate a proposal for any installed vendor, product, exact firmware build,
component and role:

```sh
impact research inventory-template \
  --vendor arista --product 'Arista EOS' --build '4.32.2F' \
  --component OpenSSH --role 'SSH management on switching platforms' \
  > inventory-proposal.json
```

The [version 1 contract](../infrastructure_impact/schemas/build-inventory-submission-v1.json)
accounts for nine fields:

| Field | Evidence to seek |
| --- | --- |
| `firmware_reference` | Exact firmware label, matching the target build. |
| `component_version` | Literal package/upstream version with downstream variant context. |
| `package_patch_id` | Applied patch or backport identifier; distinguish unknown from a reviewed explicit absence. |
| `hardware_model` | Exact hardware scope, with build compatibility evidence. |
| `image_digest` | Algorithm-qualified `sha256:` or `sha512:` digest for the target image. |
| `service_configuration` | Relevant service and configuration, with observation scope and date. |
| `historical_support_window` | Dated lifecycle/support facts for the research period. |
| `historical_download_availability` | Independently retained availability evidence, separate from a publisher date claim. |
| `build_component_binding` | Evidence that the component/patch applies to the exact image and platform, rather than a source bundle or related release. |

Each field must appear exactly once. Unknown fields require a null value and
empty evidence list. A `publisher_statement` or `artifact_observation` requires a
value and at least one artifact ID with an exact section, row or package locator.
These states describe the submitted basis; they are not verified findings.

Name local evidence files in `artifacts`, with a unique ID, basename, SHA-256,
actual capture time, kind and redistribution declaration. Supported evidence
kinds include publisher manifests, SBOMs, advisories, release notes, source
archives, image metadata, private device exports and historical captures.
Publisher URLs must meet the installed vendor's official HTTPS policy. Device
exports use a null URL to avoid recording private device locations.

Do not place firmware images, complete captures or private device data in a
public issue or repository. Prepare scoped local evidence exports only when
permitted; their hashes identify those exported bytes, not an omitted original.
A file's own SHA-256 is distinct from the image digest described inside it.
A source-code archive does not by itself establish which packages or patches
shipped in a firmware image. A version string alone does not establish CVE status.

## Audit locally

```sh
impact research inventory-audit inventory-proposal.json \
  --evidence-dir ./private-inventory-evidence
```

The command performs no network requests, opens no evidence vault, and writes no
files. It reads only the named regular files in the explicitly supplied directory.
It rejects symlink artifacts, paths containing directories, duplicate IDs and
fields, missing references, unreferenced artifacts, future or unqualified capture
times, mismatched bytes and non-finite/duplicate-key JSON. The proposal limit is
250 KB; at most 32 artifacts may be named, each at most 32 MB and 128 MB in total.
Use a bounded export for larger originals rather than bypassing those limits.

A blank proposal is accepted as an incomplete proposal. If every field has a
value and evidence, the audit reports `all_required_fields_documented: true`;
it still returns `inventory_verified: false`. The audit cannot authenticate a
publisher, validate a locator's meaning, certify a rights declaration or verify
historical availability. Its output excludes target labels, filenames, source
URLs, claim values and local paths. Error messages do not echo submitted values.
The canonical proposal hash binds the exact submitted structure for later review.

## Maintainer and independent review

1. Review source authenticity, exact image/component/hardware binding, patch
   state, service role and observation period against the retained files.
2. Record disagreements and access gaps. A checksum match proves byte identity,
   not that the proposed interpretation is correct. A complete manifest can
   still omit runtime conditions or downstream modifications.
3. Review redistribution rights separately. `permission_confirmed` needs a
   stated basis but remains an unverified declaration. The audit publishes nothing.
4. Seek independent human adjudication before using the inventory in a study.
   This workflow does not change the existing frozen extraction-review packet.
5. Enroll reviewed inventories through an explicit future study revision that
   establishes cross-vendor equivalence, sampling, lifecycle alignment and missing
   evidence handling. No proposal can unlock denominators, rates or rankings.

There is deliberately no automatic import or certification switch. Public reports
rebuild blank templates from reviewed target definitions and cannot publish a
private proposal passed in operator report fields. Existing advisory schemas and
the component-reference normalization hook remain separate contracts.

See [Product cohorts](PRODUCT_COHORTS.md), [independent extraction review](EXTRACTION_VALIDATION.md)
and the [dated source-access research](research/inventory-source-routes-20261027.md).
