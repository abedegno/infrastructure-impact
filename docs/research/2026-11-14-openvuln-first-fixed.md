# Authenticated Cisco first-fixed evidence, 14 November 2026

This is a local, bounded evidence pass, not a new hosted publication. It queried
59 ordinary release literals already observed in retained vendor evidence:
22 in IOS XE 17.9, 20 in 17.12 and 17 in 17.15. All 59 queries succeeded. Successful
captures were reused; 62 HTTP requests include three OAuth requests across the
pilot, controls and expansion. Authentication response bodies and credentials
were not retained.

The captures total 37,138,346 bytes; the largest is 1,299,423 bytes. Every capture's
SHA-256 and exact returned `iosRelease` were checked. There were 1,800 advisory
observations, representing 83 distinct advisory IDs and 110 CVEs. All 83 IDs were
already present in the retained Cisco advisory collection. No response reached
100 rows, the documented maximum page size; this check does not establish an
exhaustive vendor archive or complete platform coverage.

## Source-bound fixes

The existing ownership reducer joins API responses to exact retained advisory,
CVE and affected-query product scope. Parser revision `cisco-first-fixed-api-2`
produces 1,364 bound observations across 75 distinct retained advisories and 84
CVEs; 436 observations remain ownership-unresolved. Repeated queries are not
additional vulnerabilities or patch events. These counts describe IOS XE source
scope, including non-switching products; they do not prove Catalyst model
applicability or customer exposure.

| Train | Queried releases | Advisories with bound fixes | CVEs with bound fixes | Bound query observations |
| ----- | ---------------: | --------------------------: | --------------------: | -----------------------: |
| 17.9  |               22 |                          70 |                    79 |                      764 |
| 17.12 |               20 |                          44 |                    50 |                      337 |
| 17.15 |               17 |                          31 |                    32 |                      263 |

Advisories/CVEs overlap between trains. The three initial highest-release queries
returned empty, cross-train or unsupported fix alternatives. Older source-observed
controls supplied same-train 17.9.10, 17.12.8 and 17.15.6 targets. Empty lists,
special releases and other-train alternatives remain visible rather than becoming
inferred same-train fixes or automatic migration recommendations.

For the hardening advisory `cisco-sa-hardening-iosxe-V8NMuMZJ`, the API returns an
empty `firstFixed` array for the 17.9.9, 17.12.7 and 17.15.5 controls, while the
retained vendor table states fixes. The table remains valid evidence; missing API
values do not establish absence of a fix. The separate held-out inference check
remains two matches from four issued candidates, with one additional abstention.

## Identifier correction and cached replay

The API supplied `cisco-sa-iosxe_infodis-6J847uEB`, an advisory ID containing an
underscore. Revision 1 rejected its 14 observations. Revision 2 accepts underscores
inside the bounded ASCII `cisco-sa-` namespace while continuing to reject URL
separators, spaces, control characters, non-ASCII text and overlong identities.
It does not change ownership or release-ordering rules.

The 59 acknowledged captures were reparsed offline. Original acquisition rows,
parser-revision-1 results, hashes and capture timestamps remain unchanged; the
new derived frames identify revision 2. There were zero replay network requests.
The corrected replay adds 14 bound observations for one advisory/CVE, fixing at
17.15.5. Prior report identities remain historical receipts rather than being
restamped.

Existing successful queries retain their stored parse revision. `run` deliberately
does not redownload them; this pass explicitly exported a new offline parse using
`parse_response` and the original acknowledged source receipts. It does not add
an automatic cache migration or alter CLI defaults.

## Method and limits

Cisco documents this endpoint as a query of Software Checker that includes
first-fixed information: [retrieve advisories by software version](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/).
The collection deliberately keeps a conservative request rate and its existing
resumable acknowledgements. Official API response evidence and derived reports
are retained outside Git; public tests use authored inputs.

The synthetic regression failed before the fix and passed afterward. The covering
collector, first-fixed and transport suites passed 190 tests, including cached
acknowledgement behavior and malformed identifier controls. Independent human
source review remains pending. Source archive completeness, fixed-release
historical availability and model applicability remain separate unknowns. No
hosted pin, scheduled collection, workflow permission, secret mapping or study
publication was changed by this pass.
