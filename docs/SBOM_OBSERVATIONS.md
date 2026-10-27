# Private SBOM component observations

The offline reader normalizes selected JSON fields from CycloneDX 1.5/1.6/1.7
and SPDX-2.2/SPDX-2.3 documents into one
[versioned observation contract](../infrastructure_impact/schemas/sbom-observations-v1.json).
It supports evidence preparation for any vendor; it does not identify which
firmware a document applies to or create CVE assessments.

```sh
impact research sbom-inspect private-evidence/bom.json > private-observations.json
impact research sbom-inspect private-evidence/bom.json --component openssh
impact research sbom-inspect private-evidence/bom.json --summary
```

Keep these outputs private until their scope and redistribution rights have been
reviewed. The command reads one supplied regular local file, opens no vault,
fetches no links and publishes nothing. It rejects symlink/FIFO inputs and limits
source documents to 15 MB, parsed components to 20,000 and component nesting to
32 levels. XML, compressed documents, SPDX 3 JSON-LD and undeclared formats are
not accepted. No network schemas or external document references are loaded.

## Normalized observations

Each row retains its exact JSON locator, parent locator, declared identifier,
literal name/version, optional type/group/scope, declared external-component flag,
PURL/CPE references and selected package hash statements. Missing selected fields
stay null. Multiple instances with the same name are retained separately; parsed
component references must be unique. `--component` is an exact, case-sensitive
name filter. It performs no alias matching or package-version comparison.

CycloneDX metadata components and SPDX packages explicitly named by
`documentDescribes` are labelled declared document subjects. That label is not a
verified firmware identity. Nested components retain parent locators even when a
name filter omits the parent. Inherited/runtime scope is not computed; inspect the
original document and ancestor context before making an inventory claim.

SHA-256/SHA-512 package hashes retain their field locators; other supplied hash
algorithms are counted as unnormalized. Package hash statements are distinct from
the report's `source_sha256`, which hashes the complete original supplied file.
Neither becomes a verified firmware image digest. PURL/CPE strings are retained
as explicitly supplied identifiers with bounded format prefixes, not verified
vendor/product matches or canonicalized package identities.

The report separates the total observed component count from the returned count.
An empty match is not evidence of component absence. Creation timestamps remain
literal document claims; no historical availability date is derived. Duplicate
JSON keys and non-finite numbers, including overflow such as `1e999`, are rejected.
The inventory proposal loader now shares that strict input boundary.

## Standards subset and limits

This is a field-observation reader, not a complete standards validator. Its
`full_standards_validation_performed` flag is always false. It does not validate
signatures, licenses, VEX/vulnerability assertions, relationships, dependency
closure, compositions or lifecycle semantics. Those claims are not imported or
promoted to affected/unaffected states. Author names, contact details, license
text and arbitrary properties are not copied into the observation report.

CycloneDX 1.7 external components and version ranges remain distinct from literal
package versions. A component cannot supply both `version` and `versionRange`;
`versionRange` requires explicit external scope. A document subject cannot be an
external component. The reader does not apply these 1.7 fields to older formats.
The implementation follows the official [CycloneDX JSON reference](https://cyclonedx.org/docs/1.7/json/)
and [SPDX package model](https://spdx.github.io/spdx-spec/v2.3.1/package-information/)
for these selected fields. It does not bundle third-party schemas or promise full
conformance to either specification.

## Use with an inventory proposal

Review the original source and a selected observation's locator before placing a
literal component-version claim in a [build inventory proposal](BUILD_INVENTORY.md).
Reference the original SBOM file as an artifact with its own SHA-256, capture time,
official source URL and rights declaration. Copying an observation report does
not preserve the original SBOM's byte identity; hash each artifact accurately.

Exact build-to-component binding, image identity, package patches/backports,
hardware compatibility, service configuration, support/availability alignment and
independent review remain separate requirements. The reader creates no automatic
proposal, verified inventory, comparison denominator, vendor rank or disclosure
finding. A supplied SBOM may be incomplete, pre-build, describe another image or
include externally provided packages. Literal observations cannot resolve those
questions by themselves.

`--summary` produces `private_sbom_summary`; detailed reports use
`private_sbom_observations`. Both variants have explicit schema requirements. The
summary excludes component names, values, the selection name and the document
creation claim. It still identifies the supplied artifact by hash and counts;
it is not automatic permission to publish proprietary metadata. Neither detailed
nor summary reports are added to database state, served by the API or included in
public dataset exports. The contract ships with the source and installed package.
