# Historical batch and infrastructure expansion review — 26 October 2026

The three preceding Arista failures (0123, 0124 and 0129) were reviewed against
retained primary bodies. Automated triage then sampled 135 queued sources across
four vendors. The initial Arista sample exposed one additional CloudVision layout
(0116), reviewed before repeating the sample. This is maintainer source review and
automated parser validation, not independent human certification or a completeness
estimate.

| Batch | Documents | Final parser outcomes |
| --- | ---: | --- |
| Arista | 64 | 64 normalized after review of 0116 |
| HPE Aruba Networking | 32 | 32 normalized |
| Palo Alto Networks | 24 | 24 normalized |
| Fortinet | 15 | 15 normalized |

A normalized outcome means schema-valid output from the current parser. It can
include reference-only records or notices without product/CVE claims. Similar
heading signatures do not certify applicability. Reports remain private; the
[triage command](../ARCHIVE_TRIAGE.md) makes the process repeatable.

## Arista source scope

0123 preserves nested per-CVE indicators and mitigation headings within their
combined section. 0124 retains shared scope for five CVEs across DMF, CCF, CVA and
MCD, including the explicit CloudVision Portal virtual-appliance exclusion. 0129
is a reposted VMware-era VeloCloud Edge advisory: the older initial date is not
established as first Arista disclosure. Its local web interface is disabled by
default. 0116 is CloudVision Portal on premises, with onboarding-token and user
privilege conditions retained from mitigation as well as configuration context.
No available firmware fixes are inferred from these software lists.

| Primary source | Source SHA-256 |
| --- | --- |
| [21316-security-advisory-0116](https://www.arista.com/en/support/advisories-notices/security-advisory/21316-security-advisory-0116) | `86c632b5a15ce1ae4c2a07e1fbf941d5ab6549bba2b6b7d49adfd796fce779e1` |
| [22535-security-advisory-0123](https://www.arista.com/en/support/advisories-notices/security-advisory/22535-security-advisory-0123) | `3708eedc3936a98cc87e88f93552eea6b0a8ac059116353ccd47c695f535426f` |
| [22538-security-advisory-0124](https://www.arista.com/en/support/advisories-notices/security-advisory/22538-security-advisory-0124) | `fed359167e684b63c53f51204134d82b6d70e3cc307d2c09463e8c826bd327de` |
| [23117-security-advisory-0129](https://www.arista.com/en/support/advisories-notices/security-advisory/23117-security-advisory-0129) | `f210b0da21d691f764a146a33f1b6bf11241c6edb21a67e47988b06520963452` |

## Infrastructure expansion

Ten reviewed vendor-authored registry records add pinned scopes for Cisco NX-OS
and managed UCS; Juniper SRX, EX/QFX and mixed SRX/MX platforms; HPE OneView; and
Check Point Quantum Security Gateway/Management. Each record is verified against
its configured CNA organization, affected-product vendor and publisher reference.
An upstream-authored CVE mentioned by a feed supplies no vendor product claim.

The shared parser preserves explicit ranges, change points, platform lists and
publisher prerequisites, including NX-API/NGOAM, ADVPN, phone-home and configured
application services. No inventory equivalence or public fix availability is
inferred. Mixed EX/SRX/QFX or SRX/MX scopes stay mixed. New source-linked product
role aliases classify only the explicit publisher product names.

| Vendor-authored registry record | Source SHA-256 |
| --- | --- |
| [CVE-2025-37164](https://cveawg.mitre.org/api/cve/CVE-2025-37164) | `2b2ac38a3fdacdebb6b756fd3f2e8426fd5b84ee4007d1aebeedeabe0a8d2736` |
| [CVE-2026-102059](https://cveawg.mitre.org/api/cve/CVE-2026-102059) | `245b417e4d2ed55b2799dfe00c9e5de0a5f037d59aaa4d37d20dc3f6007b97d1` |
| [CVE-2026-102081](https://cveawg.mitre.org/api/cve/CVE-2026-102081) | `b01c70f743c720768755ca9ab185d4d7c7b9c610d09734f62b186fbbfaccab86` |
| [CVE-2026-102084](https://cveawg.mitre.org/api/cve/CVE-2026-102084) | `306fbc00e2f54032897b3b5984adf8e5a10fbdd4734095565d516fce0335b39c` |
| [CVE-2026-76471](https://cveawg.mitre.org/api/cve/CVE-2026-76471) | `e32e9e48c1a3fdb1151ab6944d34ef4d3eacf12a097d050563e5f1a72eb5bb73` |
| [CVE-2026-76485](https://cveawg.mitre.org/api/cve/CVE-2026-76485) | `42b136ce56f38b536e936effcfb9eeb2f9c811d6815357162d67b6dcf7c38373` |
| [CVE-2026-76719](https://cveawg.mitre.org/api/cve/CVE-2026-76719) | `63916262e6ab1da4ff3f087e316db1e4a782e0a7423218a141b2f1a649ceb250` |
| [CVE-2026-85102](https://cveawg.mitre.org/api/cve/CVE-2026-85102) | `533b5ffce4e533799fb93a8ac28a215c3fe16401be5f31b5f07c1e6985a379ae` |
| [CVE-2026-85103](https://cveawg.mitre.org/api/cve/CVE-2026-85103) | `ea5ffb8bd5dc327216115a7711e408244dcf0cfd692b445f75941f739e6718dd` |
| [CVE-2026-93616](https://cveawg.mitre.org/api/cve/CVE-2026-93616) | `95deeefdeb1cbc389bba43a92b4c9a55832c53a5c57bc44175a124b139d399dd` |

Aruba's coverage profile now names product families already represented in retained
CSAF, including switching, wireless, EdgeConnect and infrastructure management.
This describes observed source scope, not every model or release. HPE discovery
remains curated. Cisco archive/release and Check Point detailed-SK access blocks
remain visible; registry records do not establish every blocked document exception.
Vendor comparison eligibility and the independent review packet are unchanged.
