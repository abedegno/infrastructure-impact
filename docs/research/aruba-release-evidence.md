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
