# Product groups

The comparison supports one versioned product-role group alongside its reporting
period and CVE cohort. Groups include firewalls, switching, routing, shared
routing/switching operating systems, wireless, management, access control,
servers/HPC and secure web gateways. Roles narrow the sample; they do not establish
like-for-like hardware, portfolio completeness or a vendor security rate.

`resources/product-groups.json` supplies source-linked, dated family rules.
`product-groups.json` publishes the definition plus mapping coverage, unresolved
labels and statement counts for each vendor. Counts in that catalogue cover all
retained non-draft statements, independently of the comparison controls. The
Python reader exposes `/api/v1/product-groups`; the Pages comparison applies the
same rules locally. `schemas/product-groups-v1.json` is the report contract.

Rules use the retained `product_family` when present, otherwise the exact publisher
product label. After trimming whitespace, a name must equal the family prefix or
continue with a space, hyphen or opening parenthesis. The longest matching prefix
wins. Conflicting longest matches are ambiguous; unknown names remain unmapped.
A numeric version leaf can inherit its retained named family; a bare numeric
label never supplies a device class. Matching is vendor-specific and case-sensitive.

Specific boundaries include Panorama-labelled PAN-OS statements in management,
FortiProxy in secure web gateways, and broad EOS/IOS/IOS XE statements in a shared
routing/switching OS group. No router/switch platform split is inferred from an OS
name. Published platform, configuration and version qualifiers remain attached to
the original assessment and must be checked before operational use.

The `group` comparison control accepts a declared group ID. Exact per-vendor
`products` selections intersect it. The filter is applied to each assessment,
so identical numeric leaf labels in different families cannot leak between groups.
An unmapped vendor/group has no usable sample, not zero exposure. The UI shows
mapping gaps, source errors and backfill limits. All vendor-rate and true timing
comparisons remain suppressed.

To extend coverage, add a reviewed family rule with its vendor ID, official HTTPS
source, role rationale and review date, then increment `taxonomy_version`. Add a
boundary test for confusing names, platforms and deployment roles. New installed
vendor plugins work immediately with the common schema and receive unmapped
classification until their role rules are reviewed. Rules are data; new groups do
not require new parser dispatch or database tables. Independent human review of
the initial taxonomy remains pending.
