# Official archive-source review — 2026-10-26

This review covers four vendors. It used anonymous direct retrieval, retained
primary-response fingerprints and a small set of first, continuation, terminal
and document probes. An automated assistant performed it; independent human
review and portfolio completeness are not established. Access can differ between
search/browser services, the native collector and GitHub-hosted runners.

Machine-readable decisions and retained landing-response hashes are bundled in
`resources/archive-source-review.json` and exposed in the source audit. Runtime
queue counts and observed product filters are separate from these dated findings.

| Vendor | Reviewed official source | Decision and historical boundary |
| --- | --- | --- |
| Cisco | [CSAF directory](https://www.cisco.com/.well-known/csaf/), [index](https://www.cisco.com/.well-known/csaf/index.txt), [provider metadata](https://www.cisco.com/.well-known/csaf/provider-metadata.json) | Index retrieved: 2,888 document links in 2017–2026 directories. Five sampled exact document URLs returned HTTP 403 to the local anonymous collector. Archive backfill remains disabled; hosted document access is not established. Current feed and curated sources continue. |
| Arista | [Security Advisories](https://www.arista.com/en/support/advisories-notices), [advertised last page](https://www.arista.com/en/support/advisories-notices/securityadvisory?start=200) | Enabled through a pure listing parser. Follow only advertised Next links; the sampled last page included the June 2008 advisory. Current RSS and the advertised CSAF RSS each remain bounded windows. |
| Palo Alto Networks | [Public advisories](https://security.paloaltonetworks.com/), [advertised CSV export](https://security.paloaltonetworks.com/csv) | Enabled through the public listing's reviewed GET form. The landing page advertised 587 records, but CSV returned only the current 25 rows. The adapter recognizes the exact published page-increment control without executing JavaScript and fails on changed/contradictory controls. |
| Fortinet | [PSIRT listing](https://www.fortiguard.com/psirt) | Enabled through the publisher's default infrastructure product filter. Root, advertised continuation and terminal page were retrieved. At review time 19 product identifiers were selected; the advertised terminal page included 2016 advisories. This is a filtered archive, not all Fortinet products. |

## Specific boundaries

Cisco's lower-case archive filenames cannot safely be substituted into mixed-case
content API URLs. Four such rewrites returned 404 during the review; those errors
were distinct from the 403 responses at the exact advertised URLs. Year-directory
archive URLs are now preserved. No access challenge is solved and no web/search
cache is used to fill the collector's missing document bodies. Cisco's provider
metadata allows listing and sets `mirror_on_CSAF_aggregators` to false; original
vendor documents are not republished by this project.

Arista's listing parser selects advisory headings rather than all page links.
It requires the explicit Next control, including its reviewed disabled state at
the end. It excludes lifecycle and unrelated navigation links. The oldest listed
advisory does not establish that the archive contains every original publication.

Palo Alto's first and second public pages were checked. Duplicate top/bottom Next
controls must agree, and the returned page must match the requested one. Product
or other query filters are outside this reviewed adapter. Reviewed OSS HTML tables
keep their per-CVE exceptions. Other PAN-SA bulletins can resolve through an exact
CSAF link advertised in their HTML; an unrecognized bulletin is still an error.
Neither the listing table nor its CSV is used as product-impact evidence.

Fortinet's selected identifiers were: FortiAP, FortiAP-C, FortiAP-S, FortiAP-U,
FortiAP-W2, FortiAnalyzer, FortiAnalyzer Cloud, FortiAnalyzer-BigData, FortiExtender,
FortiManager, FortiManager Cloud, FortiOS, FortiOS-6K7K, FortiSandbox, FortiSandbox
Cloud, FortiSandbox PaaS, FortiSwitch, FortiSwitchAXFixed and FortiSwitchManager.
This excludes independently searching FortiProxy, FortiMail and other products,
even if a selected advisory mentions them. Continuation product filters must match
the actual selected options and preserve the reviewed empty non-product filters.
IR identifiers discover the separately reviewed canonical `/psirt/FG-IR-…` route;
only the resolved document parser can produce exposure claims. A web retrieval
service returned 403 for this listing while the direct collector succeeded; that
is not evidence of a vendor-wide outage or of hosted accessibility. The four
sampled CSAF records supplied publication timestamps without a timezone; these
remain unmodified and are excluded from UTC date comparisons. The archive audit
counts current records without usable publisher dates explicitly.

## Deployment and evidence

New sources use two pages and four documents per scheduled pass each. Aruba
retains its two-page/eight-document budget. A fresh local pass processed 20
documents across all four configured sources without errors. Synthetic tests cover
changed layouts, terminal pages, page echoes, scope-changing links, unrecognized
representations and shared queue provenance. This does not estimate global
extraction precision or guarantee all historical layouts will parse.

Migration 006 adds per-page scope strings without changing normalized advisory
schema v2 or modifying older migrations. Discovery edges retain the exact page
fingerprint advertising each queued item. Daily collection is additive; removal
from a listing does not delete retained evidence. Initial publisher-date ranges
cover only processed current records and will expand as the queue progresses.
Full archive backfills can take many scheduled passes. Use the documented manual
budgets for supervised acceleration within storage and retrieval limits.

Read [Archive collection](../ARCHIVE_COLLECTION.md), [Source audit](../SOURCE_AUDIT.md)
and [Vendor plugins](../PLUGINS.md) for operator and extension contracts. Archive
coverage is not a vendor ranking or evidence of concealment.

Later document-layout reviews are separate from this listing review. See the
[older applicability matrices](arista-legacy-applicability-20261027.md),
[routing qualifications](arista-routing-scope-20261027.md) and
[CloudVision management-appliance scope](arista-management-appliances-20261027.md)
for the exact Arista advisories subsequently normalized. Their successful
layouts do not establish support for every older archive page.
