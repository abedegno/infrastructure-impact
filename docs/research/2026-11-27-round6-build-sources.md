# Round 6 per-build source evidence

Research packet: [2026-11-27-round6-build-sources.json](2026-11-27-round6-build-sources.json). Production resources, branch and commits were not changed. Full captures are outside Git under `$RELIABILITY_ROUND6_CACHE/build-sources/` or the explicitly cited prior public cache.

| Build | Intended scope / existence observation | Build reason | Date treatment |
| --- | --- | --- | --- |
| Cisco 17.12.5a | Catalyst 9200/9300 existence unknown | unknown | Software release date unknown |
| Cisco 17.12.5b | Catalyst 9200/9300 existence unknown | unknown | Software release date unknown |
| Cisco 17.12.7a | C9200 literal resolved-caveat row; C9300 literal caveat heading | unknown; predecessor not established | No binary release date established |
| Aruba 10.13.1003 | 6200 version-history row | unknown | Indexed software release date 2024-03-05; research-only |
| Aruba 10.13.1005 | 6200 version-history row | unknown | Indexed software release date 2024-03-22; research-only |
| Aruba 10.13.1031 | AOS-CX family literal fixed version | security_fix | Advisory initial/revision dates kept separate; software release date unknown |
| Aruba 10.13.1101 | 6200 version-history row, blank Remarks | unknown | Indexed software release date 2025-05-09; research-only |
| Aruba 10.13.1161 | AOS-CX family literal fixed version | security_fix | Advisory date kept separate; software release date unknown |

The [C9200 caveats](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/caveats.html) place CSCws28363 under the literal 17.12.7a resolved-caveat heading, with Applicable Models C9200. The packet retains the exact short headline, locator and excerpt receipt. This identifies a resolved flow-export issue; neither its predecessor nor an explicit non-security classification is established. The admitted build reason is therefore unknown, with defect_fix_status `predecessor_not_established`; the resolved row remains candidate evidence only. The [C9300 caveats](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/caveats.html) provide a literal 7a heading observation; that does not transfer the C9200 defect to C9300.

[HPESBNW04669](https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04669.json) explicitly names 1031 in `product_status.fixed` and vendor-fix remediation. [HPESBNW05027](https://csaf.arubanetworking.hpe.com/2026/hpe_aruba_networking_-_hpesbnw05027.json) does the same for 1161. Both original anonymous captures were rehashed against their original receipts. Their retrieval times remain 2026-11-27T11:20:49.882570+00:00 and 2026-11-27T11:20:51.598374+00:00 respectively, rather than a new retrieval claim. Neither advisory binds an individual catalogue switch model or establishes a binary release date.

The [6200 early history](https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/6200%20Release%20Notes/aos-cx-10-13-xx/version-history-19.html) and [later history](https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/6200%20Release%20Notes/aos-cx-10-13-xx/version-history-25.html) explicitly label their release-date columns. Their dates are recorded as indexed research observations, with DD/MM/YYYY normalization, separate from original-document evidence and production admission.

Nine bounded indexed-search batches are captured with full query receipts and SHA-256 hashes. No Cisco or Aruba documentation origin requests were made after the known robots 403 results. No detail-page opens, logins, mirrors or challenge bypass were used. Incidental third-party fixed-version expansions and unrelated SD-WAN, router, WLC and alternate-host results were excluded. In particular, no admissible Catalyst 9200/9300 image/release/advisory evidence confirmed 5a or 5b; their absence from these results does not prove nonexistence. A final exact-literal official Cisco security-advisory indexed search returned no results for 5a/5b. Their OS-family-only security reason is also unknown; router-only release notes were not transferred. No timing coincidence was used as a build reason.

Every source includes URL, exact locator, short quotation, retrieval-time basis, original-versus-excerpt hash labeling, scope and outside-Git capture location. Unknown values are intentionally retained for integration by the parent agent.

Cache macros: `$RELIABILITY_ROUND6_CACHE` means outside-Git `data/reliability-round6-20261127`; `$RELIABILITY_CORRECTIONS_CACHE` means outside-Git `data/reliability-corrections-20261127`. Existing raw captures were not altered.
