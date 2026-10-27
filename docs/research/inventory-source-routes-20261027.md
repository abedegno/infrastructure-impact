# Exact-build source routes — 27 October 2026

Assistant research for the EOS 4.32.2F / AOS-CX 10.13.1031 SSH-management pilot.
Independent human review remains pending. This is a bounded route investigation,
not an exhaustive search or a finding about a vendor's disclosure practices.

## Arista

The official [open-source page](https://www.arista.com/en/support/product-documentation/gpl)
explicitly lists an **EOS-4.32.2F Source** link. This is a useful acquisition lead,
which was absent from the initial advisory-only pilot. Its stable publisher route
is [the EOS source archive entry](https://www.arista.com/opensource/?f=EOS-4.32.2F-source.tar).
A web-tool request encountered a signed storage redirect it could not open.
No signed query string is retained in this document or added to collection config.

A separate ordinary anonymous HEAD check at 11:02 UTC returned HTTP 200 with
`text/html` and reported length 3038 from this route. That is metadata, not a
validated source archive. No archive bytes or packages were downloaded, and no
image-to-source binding, OpenSSH version or patch identity was established.

The [product documentation catalogue](https://www.arista.com/en/support/product-documentation)
also lists an EOS 4.32.2F product bulletin. Following its download link through the
web tool reached the vendor login page. The separate HEAD check again returned
HTTP 200 / HTML, not a validated PDF. A listed source archive and a release
bulletin would have different evidence roles even if both were accessible.
Neither proves historical availability of the corresponding binary image.

## HPE Aruba Networking

The official [AOS-CX 10.13 license written offer](https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/6100%20Release%20Notes/aos-cx-10-13-xx/license-written-offer-5.html)
is indexed as describing a product/version-specific source request, including an
online request route. The web tool could not retrieve this page directly; the
anonymous HEAD probe returned 403. This indexed lead is not retained exact-build
source evidence. No request was submitted and no terms or account were used.

The [AOS-CX 6000 10.13.1031 release-note entry](https://support.hpe.com/hpesc/public/docDisplay?docId=sd00007242en_us&docLocale=en_US&page=GUID-1A91EA40-F5C9-4577-BBDB-01A94D1F28AF.html)
is another product-specific lead. Its index and navigation headings do not
establish package versions, model compatibility or an installed inventory.
Other release versions and platforms are not substituted for the selected build.

## Implementation consequence

Keep all existing unknown image/package/runtime/lifecycle fields unknown. Add an
explicit exact-build-to-component binding gap and an offline evidence proposal
contract. A submitted source archive, vendor SBOM or manifest needs its own byte
fingerprint, capture time, locator, rights review and exact target binding. The
current implementation audits local evidence but does not certify the inventory
or automatically map an arbitrary SBOM to CVE applicability.

These routes are not enabled as scheduled collectors. HTTP status or a published
link alone cannot establish a parseable manifest, source freshness, redistribution
permission or historical image availability. Access differences between tools
remain observations with method and time, not claims about their cause.
