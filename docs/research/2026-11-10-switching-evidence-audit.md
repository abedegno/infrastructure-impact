# Switching coverage and validation audit — 10 November 2026

This audits public publication `6d1e2458972f428ebe023e5deaa4a993`, generated at
`2026-11-10T02:41:08.074204+00:00`. Hashes and compact observations are recorded in
[evidence.json](2026-11-10-comparison-evidence/evidence.json). No private evidence,
operator configuration, customer data or worker logs were needed.

## Thirteen failures is not thirteen switching gaps

Run 74 finished at `2026-11-10T02:41:05.433552+00:00` with 13 failures. The latest
public health rows within that run reconcile them as follows:

| Source category | Latest-run failures | Effect on this switching comparison |
| --- | ---: | --- |
| Arista retained-capture normalization | 8 | Cached triage dates these before 2021; no new HTTP requests for these replays |
| Check Point verification/access gaps | 4 | Blocks separate vendor/benchmark evidence; not Cisco/Aruba/Arista observations |
| Fortinet structured advisory without publisher scope | 1 | Separate vendor source; no scope may be manufactured from its empty envelope |

There are **70 retained source error identities**, a different inventory: Arista
51, Palo Alto 13, Check Point four and Fortinet two. Do not add 13 to 70, treat
these as 70 missing CVEs, or assign collection/check dates as advisory years.
The source audit and collector reports describe observed sources, not complete
vendor histories.

## What is and is not complete

| Vendor | Observed source inventory | Remaining boundary |
| --- | --- | --- |
| Cisco | Current RSS window and retained exact targets; no current source errors | RSS is bounded; no complete IOS XE archive denominator. Earlier sampled CSAF access failures do not mean every exact document is blocked. Supported authenticated enumeration remains an option; credentials are not available in this work. |
| Aruba | Observed CSAF index: 112 documents processed, zero queue errors | Current index starts in 2022. Nineteen 2021 TXT sources were already captured; two normalize, 17 remain unsupported. Only 013/019 explicitly name AOS-CX in the earlier text triage; both relevant repairs are retained. Missing family labels do not prove unaffectedness. |
| Arista | 21 listing pages, 203 documents: 152 processed and 51 errors | Fifty error identities were triaged as pre-2021. The remaining error is an alternate SA-0103 route, whose selected HTML is retained. Queue state is not complete product/disclosure coverage. |

The [yearly CSV](2026-11-10-comparison-evidence/coverage-by-year.csv) joins current
study affected-advisory identities to their retained normalized publication dates.
All 170 Cisco, 16 Aruba and 53 Arista identities match exactly once. These are
observed affected advisories, not expected totals or CVE-first-disclosure counts.

| Original advisory year | Cisco | Aruba | Arista | Expected total / completeness |
| --- | ---: | ---: | ---: | --- |
| 2021 | 50 | 0 | 1 | Unknown for all vendors |
| 2022 | 24 | 4 | 6 | Unknown for all vendors |
| 2023 | 19 | 3 | 3 | Unknown for all vendors |
| 2024 | 26 | 3 | 5 | Unknown for all vendors |
| 2025 | 33 | 3 | 13 | Unknown for all vendors |
| 2026 through 10 November | 18 | 3 | 25 | Unknown for all vendors |

In particular, the zero Aruba cell is an observation of this affected-advisory
collection, not proof that Aruba disclosed no applicable CVEs in 2021. The two
historical bulletins also contain unaffected/shared context. A completed index
queue and a complete history of indirect dependency exposure are different things.

## Validation results and the actual repairs

| Check | Exact matches | Reviewed section matches | Missing selected-record sources | Unreviewed revisions | Disagreements |
| --- | ---: | ---: | ---: | ---: | ---: |
| Older 47-case mapping benchmark | 44 | Not applicable | 3 | Not applicable | 0 |
| Global 25-case extraction sample | 13 | 7 | 3 | 2 | 0 |
| Switching 16-case extraction sample | 7 | 6 | 3 | 0 | 0 |

The three benchmark misses concern two Check Point articles. Fresh bounded requests
return HTTP 200 shells without advisory product bodies, so a successful status is
not usable source content. The three global extraction misses use one of those
articles. A supported official export/access path is needed; parser changes cannot
recover absent content.

The two global unreviewed cases refer to the FortiProxy 7.2.8 resolved-issues
article. A fresh response exactly matches the published current raw hash, but its
structural digest differs from the frozen reviewed scope. Its text still names
the two CVEs and fixed-only statement. Keep the revision unreviewed until a separate
scope review; do not overwrite frozen expectations or infer earlier affectedness.

The three Cisco study cases reference the exact retained CSAF alternate for
`cisco-sa-openssh-rce-2024`, hash
`6d4f25908f5740ae1144d036930019bc8fbb0a13ead92d4322d1465cc393bb96`.
The selected HTML includes broader product statements. The alternate is neither a
failed fetch nor part of the selected normalized assessment inventory. A fresh
request reproduced its reviewed hash.

The local correction adds `source_context.state=retained_unselected_representation`
to those cases, anchored to the public selected capture. Real-data replay adds
exactly three contexts and leaves the complete report otherwise identical. This
does not turn metadata into a pass, merge representations or change public
affectedness. Existing publications remain immutable. The context is available in
the validation JSON after deployment; it does not change the headline counters.

The sample's three CSAF controls concern Catalyst SD-WAN. They do not provide three
additional reviewed examples for the customer's Catalyst switch models. Arista's
six structural matches likewise remain separate from full-byte matches.

## Release access and the next bounded activation

The exact optional [Cisco IOS XE Dublin 17.12.1 model page](https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-dublin-17-12-1/model.html)
now returns its software metadata anonymously: 120,943 bytes, SHA-256
`2f6c9f50a4dededb423e5ba80a4873e194310499d7911b7b34f22d8aded79ba6`.
Its directly owned Release Date is **28-JUL-2023**, distinct from lifecycle dates.
The existing adapter's synthetic section layout rejects the actual table layout.
The focused repair supports those explicit metadata owners and keeps unrelated
hardware/document dates invalid. Raw capture stays outside Git; tests use an
authored reduced fixture. This source remains disabled on the hosted collector.

After code review, the concrete next activation is that single existing optional
source, with unchanged schedules, permissions and limits. It adds one reported
software date, not a complete release history, patch-delay estimate or extra CVE.
No hosted source or runtime pin was changed during this audit.

## Prioritized remaining work

1. Review the [blind packet](2026-11-10-comparison-evidence/README.md). Only the
   maintainer's actual adjudication can complete the requested human review.
2. Enable the repaired Cisco reference only through the separately approved
   activation process. Then extend documented release/bundle coverage from
   explicit official links, preserving missing dates and affected/fixed ownership.
3. Establish a dated IOS XE discovery denominator using supported official API
   access or verified archive documents. Credentials must use the existing secret
   interface; none are requested in chat or assumed present.
4. Review mixed Arista SA-0070 and shared-unaffected SA-0081 research scope before
   broadening the typed bridge. **SA-0075 is already repaired**, as are SA-0128 and
   SA-0201; the earlier worklist is historical. No new CVEs are assumed from a lead.
5. Obtain model/configuration and change-history evidence before estimating
   operational patching load. No private artifacts are currently available.

The remaining 17 Aruba historical unsupported documents and other vendors' queues
remain visible backlog. Fixing every legacy parser first would not close the
current switching study's main comparability gaps.
