# Public-source coverage repair observations — 2026-11-05

These are observations from an isolated public-only local stage of unreleased
source-coverage repairs. They do not replace frozen benchmark results, certify
security quality, establish vendor-wide completeness or activate a hosted build.
Automated validation remains independent-human-review pending.

## Method and observed counts

The final anonymous crawl ran from 19:07:32 to 19:07:54 UTC, with 21.687 seconds
spent collecting. Every stage path was explicit. Ambient Cisco OAuth variables
were removed from the subprocess environment without reading their values. No
authenticated Cisco request, browser challenge, private/customer data or hosted
recovery input was used. Raw response bytes, hashes, retrieval metadata and
operator receipts remain outside the public source tree.

The Aruba invocation had the existing 20-page/200-document maximum. It enumerated
one [published 2021 directory](https://csaf.arubanetworking.hpe.com/2021/) and
processed only its listed documents. The Arista rows below were explicit pins;
“selected” is their test denominator, not enumeration of a publisher archive.

| Public source | Listed / selected | Retrieved documents | Parsed advisories | Positive notices | Unsupported | Access blocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Aruba 2021 directory | 19 listed | 19 | 2 | 0 | 17 | 0 |
| Arista SA-0202 | 1 selected | 1 | 1 | 0 | 0 | 0 |
| Arista SA-0203 | 1 selected | 1 | 1 | 0 | 0 | 0 |
| Arista SA-0204 | 1 selected | 1 | 0 | 1 | 0 | 0 |
| Cisco reviewed informational article | 1 selected | 1 | 0 | 1 | 0 | 0 |

Aruba 001–012 and 014–018 stayed `unsupported_or_invalid_document`. Retrieval
success is not parser support. No 19/19 parsing claim is made. The final run
retained 24 response captures: the directory, 19 Aruba documents and four pins.
An initial sandbox-only attempt failed DNS resolution and produced no advisory
evidence; that failed attempt was retained separately. The authorized anonymous
network stage then succeeded at retrieval. No challenge was executed.

## Source facts and unresolved scope

[Aruba 013](https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-013.txt)
reports publication on 2021-07-13; its update date is unknown.
[Aruba 019](https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-019.txt)
reports publication on 2021-12-13 and update on 2022-01-11. They produce nine
AOS-CX claims: four affected and five explicitly unaffected. The full documents
also retain 70 claims outside the classified switching family. Four per-CVE CVSS
metrics validate. Shared product prose does not establish 6300M or 6410 model
bindings. Literal fix guidance remains source-bound with unresolved product
scope where appropriate; no release dates or counted remediation bindings are
invented.

[Arista 0202](https://www.arista.com/en/support/advisories-notices/security-advisory/24853-security-advisory-0202)
reports publication/update on 2026-11-02 and produces 22 literal claims.
[Arista 0203](https://www.arista.com/en/support/advisories-notices/security-advisory/25023-security-advisory-0203)
reports publication on 2026-11-02 and update on 2026-11-03, producing 21 claims.
The affected products, EOS exclusions and triage groups remain separate. EOS
exclusions do not mean all EOS is unaffected. SA-0203's MPTCP configuration
qualification does not establish absence of vulnerable IPv4 code. Labels such
as `720XP/722XPM`, `750X` and `7500R` remain literal, with no invented exact-model
matches. Unsupported HTML score formats remain unknown.

[Arista 0204](https://www.arista.com/en/support/advisories-notices/security-advisory/25024-security-advisory-0204)
is an advance notice dated 2026-11-03. The
[Cisco informational article](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-notice-I8z3n6lK)
reports first publication on 2026-10-28 and update on 2026-11-04. Both retain
positive notice evidence and produce zero own CVEs, assessments and scores.
Linked advisory CVEs and upcoming publication dates do not become recovered
vulnerability evidence. Integration exposed and fixed traversal of the Cisco
notice's advertised empty CSAF representation; positive own-article notice
classification now preserves its HTML. Unrecognized articles retain ordinary
structured resolution.

## Publication, replay and remaining gates

The live publication contains four advisories, 122 literal claims and four valid
public CVSS metrics. Strict writer, study and index/default monitor checks pass.
The compact monitor checks 909,406 bytes across 26 parts, within the unchanged
20,000,000-byte budget; the default API response is 584,610 bytes. These checks
do not verify a full compressed archive or turn missing KEV configuration into
available KEV evidence. The ordinary frozen cohort intersects the four actual
Log4j CVEs: CVE-2021-44228, CVE-2021-44832, CVE-2021-45046 and CVE-2021-45105.
No cohort override or frozen-resource edit was needed. The stage's benchmark
result is 0/47; this narrow source set does not supersede original frozen results.

A separate replay used seven dedicated public captures originally recorded at
17:19:45–17:19:47 UTC, with their exact manifest hashes and original metadata
retained. Its six document pins produced the same four advisories, 122 claims,
four metrics and two notices. The retained directory independently lists 19
links; only the two authorized captured Aruba documents were replayed. This is
source replay, not a live recovery or proof of historical availability. Its
compact monitor checked 889,759 bytes. Retrieval timestamps in the replay vault
are replay processing times; original capture metadata remains separately
labelled. Neither stage used native data.

The operator report and explicit `coverage-gaps` CLI validate against the closed
version-1 schema and leave database/source-state bytes unchanged. Enumeration,
retrieval, normalized identities, notices, unknown aliases and sampled previews
remain separate; source rows must not be summed as vendor totals.

Real authenticated Cisco history still needs separately authorized client
credentials and a later acceptance run. The 17 unsupported Aruba documents,
future publisher layouts, exact-model scope, unresolved remediation bindings and
independent human review remain open limits. Disclosure counts do not establish
security quality, equivalence, cause, concealment or a Glasswing conclusion.
[Release-history research is the next milestone](2026-11-05-source-coverage-backlog.md).
Published v0.9.1 artifacts, package/dependency versions, runtime pin, defaults,
limits, schedules, permissions and hosted activation remain unchanged. This is
an unreleased test build; exact-head remote Python 3.11/3.13 and container CI,
whole-branch review and any release/activation approval are subsequent gates.
