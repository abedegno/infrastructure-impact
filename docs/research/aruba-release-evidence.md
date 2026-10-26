# Aruba release-history source lead

Reviewed on 2026-10-26 by an automated assistant. This is a source lead, not
an enabled adapter or a verified release-availability observation.

The official [AOS-CX 10.10.1140 release notes for 4100i switches](https://www.arubanetworks.com/techdocs/AOS-CX/10.10/RN/rn_4100i_10-10-1140.pdf)
contain a Version history table on PDF page 5. Search-readable publisher text
reports 10.10.1140 dated 2024-09-19 and 10.10.1131 dated 2024-07-12,
with published-release remarks. This is retrospective publisher testimony,
not an independently observed historical download.

Direct retrieval from both www.arubanetworks.com and arubanetworking.hpe.com
returned HTTP 403 in the local environment. No raw PDF was captured, no
release asset was registered, and no adapter was enabled. Search snippets
must not substitute for retained source bytes or parser validation.

A follow-up needs supported machine retrieval of the public PDF or an official
release-history export. Validate its table and product scope against retained
bytes before enabling collection. Firmware checksums absent from such a source
must remain absent; the release metadata contract currently requires an artifact
checksum and would need a documented extension for history-only records.

The [OpenSSH advisory](https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04669.txt)
separately identifies fixed AOS-CX versions. Its original publication predates
the reported 10.10.1131 release date, so these dates do not demonstrate a fix
preceding disclosure, much less concealment. Any future linkage requires
matching platform/version scope and a review of earlier disclosure sources.

## Current-portal trace and request comparison

Follow-up on 2026-10-26 found that the old documentation portal redirects to
[HPE's current CX portal](https://arubanetworking.hpe.com/techdocs/ArubaDocPortal/content/new-portal/aoscx.html).
Selecting 4100i identifies the consolidated HTML documentation at
[4100i Release Notes](https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/4100i%20Release%20Notes/index.html).
The 10.13 series contains release-specific pages, including 10.13.1031.
Its Overview → Important information → Version history links lead to
[this version-history table](https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/4100i%20Release%20Notes/aos-cx-10-13-xx/version-history-43.html).

A normal Chrome session displayed that table without a login or challenge.
The collector's actual User-Agent and Accept headers received HTTP 403 with
`Server: AkamaiGHost` at the same HTML URL. This establishes a request-context
access difference; it does not identify whether IP reputation, TLS/client
fingerprint, cookies, headers or another edge rule caused it. No challenge was
solved and no cookies or credentials were exported to the collector.

The old PDF URL displayed Not Found in Chrome. Earlier request comparisons
returned Akamai 403 for curl/browser-style user agents, while the collector
user agent followed the old-domain redirect and received nginx 404. Consequently,
403 alone cannot diagnose a live document or a user-agent-only restriction.

The replacement table includes 10.13.1030 dated 27/06/2024 but omits 10.13.1031,
despite being linked from that release's navigation. Do not assign a neighbouring
row's date to the selected release. The table is incomplete for that timing
question; neither the omission nor the migration establishes concealment.

Next integration work should distinguish scheduled HTTP retrieval from explicitly
labelled browser-assisted evidence capture. Browser-rendered HTML must carry its
capture method and observation time, rather than masquerading as origin response
bytes. A successful supported HTTP route or separately tested browser collector
is required before enabling unattended collection of this source.
