# Public baseline reconciliation and staged backfill — 2026-11-06

This operational follow-up used the merged reconciliation implementation at
`faf630885af4eb1835fdb26138ba6e99e092d6ab`. It changes no hosted configuration,
source pin, schedule, permissions, frozen study or public generation. Human impact
review remains pending. Counts describe collection and disclosure evidence, not
vendor security quality, concealment or equivalent campus-platform exposure.

## Inputs and separate baselines

Discovery reused the [verified official CVE List snapshot and corrected selectors](2026-11-06-cve-reconciliation-observations.md).
The inclusive **registry publication** window is 2021-01-01 through 2026-11-06.
Candidates include explicit family rows and ambiguous leads, with affected,
unaffected and unknown literal statuses. They are not a list of affected campus
switches. Outside-window candidates remain retained but are excluded below.

The published `snapshot.json.gz` was retrieved anonymously at 13:09:17 UTC and
verified against its publication manifest. Generation
`0f0e7be466ff47cfa9367d85cf80f20f` was generated at
2026-11-06T07:34:40.209529+00:00 and contained 952 records. Its compressed SHA-256
was `148837f710e906b51a606e6f6958f1f8eaf84bac1747d1a7596fd513738680ad`;
expanded SHA-256 was
`b720bacb994442070df8b14a894b0928d42bb506c83ff5fc2977d2979c2715df`.
Published membership is a latest-record check, not a reconstruction of the hosted
vault's private revision, source-selection or collection-attempt history.

A separate new public-only local stage collected the three vendors' existing
configured RSS/index windows and pins. Archive backfill was not activated. That
stage contained 49 normalized advisory identities: Cisco 13, Aruba 4 and Arista
32. One configured Cisco source failed with `edge_access_denied`; this is separate
from the targeted backfill results. An earlier pins-only run is retained as a
separate receipt and is not the default-window baseline.

## Published gaps and local repair

Presence requires the matching CVE and vendor. Family presence additionally uses
the existing reviewed family matcher on that CVE's assessment; it does not infer
software from hardware model labels. Presence includes retained draft and
unaffected statements and therefore does not measure vulnerabilities requiring a
patch. The three family candidate sets happen to be disjoint at this source pin.

| Family | In-window candidates | Published vendor presence | Published family presence | Backfilled local vendor presence | Backfilled local family presence |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cisco IOS XE | 201 | 0 | 0 | 201 | 200 |
| Aruba AOS-CX | 70 | 67 | 67 | 3 | 3 |
| Arista EOS | 86 | 84 | 82 | 42 | 1 |

**The local stage is not a copy or union of the published collection.** Its
smaller Aruba/Arista counts reflect its bounded input set, not lost evidence or a
regression on the website. Do not divide these columns into vendor coverage rates
or compare local vendor totals as a security ranking.

The targeted local backfill selected 173 distinct Cisco article URLs cited by the
in-window candidates, plus one confirmed Aruba bulletin. All 174 targets completed
successfully in 435.253 seconds using the existing anonymous collector and source
resolution. Targets were processed sequentially with a one-second pause between
targets. Existing transport limits remained 15,000,000 response bytes, a 25-second
request timeout and at most two attempts. Neither source nor scan limits increased. Older `tools.cisco.com` article links and newer `sec.cloudapps.cisco.com`
links both yielded usable primary evidence. This does not establish that every
Cisco archive or CSAF route is accessible. No OAuth credentials were used.

The retrieved vendor documents supplied family evidence for all 180 explicit IOS
XE candidates; the conditional vendor-authored registry fallback needed zero
requests. Five vendor-authored registry identities already present in the default
stage remain separate; zero fallback requests does not mean the stage contains no
registry records. The resulting stage contains 223 normalized identities: Cisco 186,
Aruba 5 and Arista 32. These are mixed collected records, not patch events or
vendor-wide archive totals. The selected-target denominator is known; the vendors'
complete expected historical advisory totals remain unknown.

Latest local vendor documents with an exact target-family assessment, grouped by
literal **vendor document** publication year, were:

| Year | IOS XE | AOS-CX | EOS |
| --- | ---: | ---: | ---: |
| 2021 | 52 | 1 | 0 |
| 2022 | 24 | 0 | 0 |
| 2023 | 20 | 0 | 0 |
| 2024 | 26 | 0 | 3 |
| 2025 | 33 | 0 | 1 |
| 2026 | 19 | 0 | 5 |

These are observed identities in the bounded local stage, including all literal
assessment statuses. Zero means no matching document in this stage, not no vendor
vulnerabilities. The table excludes three EOS documents dated 2020 and separates
registry records from vendor documents; it is a run summary, not a comparison of
complete archives, affected CVEs or patch events.

`CVE-2024-20508` remains present for Cisco but lacks the exact reviewed IOS XE
family binding. Its registry discovery class is ambiguous and status unknown;
[the referenced UTD/Snort advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-utd-snort3-dos-bypas-b4OUEwxD)
does not justify forcing that missing association.

[Aruba bulletin 2021-013](https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-013.txt)
recovers `CVE-2021-29143`, `CVE-2021-29148` and `CVE-2021-29149`. Its overview and
resolution explicitly name AOS-CX. Assessments remain `bulletin_shared`, with
literal series labels, version ranges and configuration context. The series
references do not establish exact 6300M or 6410 applicability.

The after-backfill reconciliation report ID is
`e44599aedc0e702ce6898a624aea4e288c199bbd89a86c2d5de0ddf99cc7d974`;
its baseline fingerprint is
`335841a30b029570cce06e129790c5294665d187b2421dd514f44350c90c8218`.
`scan_complete` remains true and `coverage_complete` remains null.

## Reproduced Arista defects and repair backlog

Two absent EOS candidates are collection defects, not evidence of a vendor
withholding a CVE. Retained primary bytes and offline reproduction establish:

1. [SA-0099](https://www.arista.com/en/support/advisories-notices/security-advisory/19862-security-advisory-0099)
   names both `CVE-2024-27890` and `CVE-2024-27892`. The generic parser keeps the
   first tracking paragraph and misses the CVE-specific EOS version-group
   markers. It drops 27890 and assigns both groups to 27892. Repair must preserve
   the separate six/eight expression groups and their source locators; adding a
   missing identifier alone would retain incorrect version attribution.
2. [SA-0103 HTML](https://www.arista.com/en/support/advisories-notices/security-advisory/19917-security-advisory-0103)
   names `CVE-2024-6858`, while its explicitly advertised
   [CSAF representation](https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_103.json)
   contains `CVE-2023-5501`. The generic resolver accepts the populated CSAF
   without checking the article's CVE scope. Direct HTML parsing preserves 6858
   and four literal ranges. Repair should retain independently validated HTML,
   expose the alternate-source disagreement through existing source-selection
   contracts, and handle collection starting at either exact URL. Do not rename
   a CVE, merge these scopes or borrow the contradictory CSAF's fixed versions.

These proposed repairs are not implemented by this research branch. Required
regressions include reversed tracking order, unrelated navigation CVEs, missing
or foreign group markers, no version-range cross-binding, contradictory draft
and final alternates, direct-CSAF replay and persisted source provenance.

The other two EOS family gaps (`CVE-2021-28501`, `CVE-2023-24512`) already have
published vendor records and remain ambiguous family leads. They need source
scope review rather than automatic family attribution. The supported-format,
oversized-record, alias and embedded-component discovery limits from the original
observations still apply.

## Comparison rerun and remaining performance gate

The existing switching reducer was invoked on the expanded local stage with its
frozen study unchanged. The already configured official CISA KEV mirror was
collected locally, separately from vendor advisory storage, before exporting the
after-backfill reconciliation. No comparison export completed after more than ten
minutes, so the operator stopped that attempt. This was an operator time budget,
not an application-declared timeout or a passing comparison. No validation was
removed and no partial comparison was accepted.

The stage has 91,993 normalized assessments across 223 identities. These are
normalized assessment rows, including product/version fanout, not distinct CVEs. A one-second process sample reported
a 3.6 GB peak physical footprint. A separate read-only profiling pass
completed source-to-study input construction in 16.067 seconds for 91,393 research
claims. A follow-up with a 45-second operator budget reached projection validation
and stopped without an accepted output; samples included copying, JSON encoding
and format validation. These samples do not attribute the entire longer attempt
to one function. The expanded projection/reduction path needs profiling and
regression coverage before a full year/pre/post/model comparison is claimed.
The known complete backfill, baseline and reconciliation results above remain
separate from this incomplete comparison attempt.

The next implementation scope should prioritize the two reproduced Arista
attribution/source-selection defects, then the expanded-corpus comparison path.
It should preserve all primary bytes and source disagreements, maintain validation
and unknown completeness/model states, and test bounded source-scale fanout.
Retrieval success cannot by itself establish a usable comparative study.

## Verification and publication boundary

Raw captures, SQLite stages, exact source hashes, configuration, read-only
projection receipts and JSON/CSV exports are retained outside Git. An auxiliary
pilot-summary query initially used the wrong collection-attempt column; its
read-only receipt was repaired without refetching or changing collected evidence.
No native/customer vault, hosted recovery material or credentials were accessed.

The staged records and reports have not replaced the website. Any public source
configuration, replay budget, release or activation proposal remains a separate,
reviewable operation. Higher disclosure can reflect more scrutiny; neither these
candidate counts nor improved retrieval prove a difference or equivalence in
security quality or operational patching load.
