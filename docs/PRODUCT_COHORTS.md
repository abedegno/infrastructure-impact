# Product and build cohort planning

The **Product cohorts** view records selected product scopes, retained component
references and the build, hardware, configuration and support facts still needed
for comparisons. It does not change the frozen CVE study enrollment.

## Initial scope and evidence

`resources/product-cohorts.json` inherits the three existing comparison-plan role
groups: security gateways, switching and management. Their 15 scopes cover 14
families. PAN-OS 11.1 and 11.2 are separate targets; Panorama 11.2 is a separate
management target. Other release trains remain unspecified. Branches from one
vendor cannot be counted as independent vendors or vulnerability events.

Selection is retrospective and purposive, not representative or historically
preregistered. The fixed 2023-01-01 through 2026-10-26 research period is a target
for evidence alignment, not reconstructed historical exposure. Current references
are retained with their actual capture dates rather than silently filtered away.

Each target records release train, firmware build, hardware model, deployment,
service enabled state, support window and exact bound component-source URLs.
Null means unspecified. Non-null targets define what to investigate; they do not
certify that a device shipped that build, enabled the service or was supported.

Only the exact bound URL and vendor can supply component references. The report
retains literal versions, section locators, source hashes, capture times and scope
qualifications. Retrieval status is separate: a failed latest check cannot erase
an older reference or make it current. HTTP success cannot certify parsing.

PAN-OS cannot fill Panorama or another vendor's scope. Junos OS Evolved references
cannot fill SRX or EX/QFX, and iLO references cannot fill OneView. Unbound sources
still appear in descriptive vendor coverage. Counts measure retained sources,
not inventory completeness or vendor security. See [Source access](SOURCE_ACCESS.md).

All build denominators and comparison rates remain null. Inventory, backports,
downstream variants, deployment equivalence, lifecycle alignment and independent
review remain blockers even for completely populated targets. A future validated
inventory/enrollment workflow must establish those facts before rates; editing
this definition cannot certify them.

## Contracts and extension

The input contract is `schemas/product-cohort-definition-v1.json`. Its canonical
SHA-256 covers all fields except `definition_sha256`, using sorted JSON keys and
compact separators. Scope changes need a new version, reviewed selection reasons
and a new fingerprint. Duplicate cohort/unit IDs, unknown families, reversed
periods and URLs outside the family's official vendor policy are rejected.
New vendors use the existing plugin and family catalogue contracts.

Validate a proposal without opening or writing the evidence vault:

```sh
impact research cohort-validate infrastructure_impact/resources/product-cohorts.json
```

Validation does not install a definition or modify a publication. Review and ship
the changed package resource to change the default plan; do not edit an immutable
publication in place. Definition review must verify that each bound source applies
to its target; a vendor-domain check alone cannot establish product equivalence.

`/api/v1/product-cohorts` and static `/product-cohorts.json` use
`schemas/product-cohorts-v1.json`. The public projection rebuilds the report from
sanitized configured sources, excluding operator report fields and private notes.
The report and browser bootstrap carry the same publication generation.

## Exact firmware evidence pilot

The report's optional `build_pilot` adds a separate, versioned two-vendor SSH
management pilot. [Research and limits](research/build-and-disclosure-pilot-20261027.md)
record why EOS 4.32.2F and AOS-CX 10.13.1031 were selected. Exact fixed-release
references and qualified backport statements have field-level provenance.
Package versions, image hashes, exact hardware compatibility, installed service
configuration and historical support/availability remain unknown. These are
partial public evidence profiles, not completed build inventories. Additive report
fields preserve compatibility with earlier v1 publications.
