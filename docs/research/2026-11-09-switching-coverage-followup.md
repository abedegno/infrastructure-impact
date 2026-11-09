# Relevant switching coverage follow-up — 9 November 2026

This is a bounded public-source follow-up to the
[live investigation](2026-11-09-live-switching-readiness.md). It changes no hosted
collection, source configuration, publication, credentials, permissions or schedule.
The baseline is generation `036b4934119c48cf890aed3df205739e`.

## Most archive errors do not block this study

The 51 Arista source errors visible in the public source audit were captured and
triaged independently of the 32 unsupported switching research representations:

| Arista queue-error group | Documents | Result |
| --- | ---: | --- |
| Explicit revision-table initial date before 2021 | 46 | Outside the registered study period |
| Older literal Date fields, with explicit pre-2021 years | 4 | Outside the period; exact day need not be inferred |
| SA-0103 alternate CSAF route | 1 | Current HTTP-200 challenge page; retained disagreement remains unresolved |

Thus 50 of 51 are legacy backlog outside the study period. They should not be
silently dropped from collector health, but fixing them first would not improve
2021-onward switching counts. The remaining route is already deliberately
rejected in favour of separately validated SA-0103 HTML; its failure is not proof
of an absent primary advisory. A challenge page is not a vendor advisory, and no
challenge was executed or bypassed. The 50 normalizations remain unsupported;
period triage does not turn them into parsed records.

The Aruba 2021 directory has 19 explicitly advertised TXT documents. The existing
captures for 013 and 019 were reused; the other 17 were captured once. All 19 have
literal 2021 publication dates. Only **013 and 019** contain an AOS-CX/ArubaOS-CX
text reference, and both already normalize. The other 17 remain unsupported and
are not classified as unaffected; absence of a family label cannot exclude an
indirect dependency exposure or establish exhaustive disclosure.

- [2021-013](https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-013.txt)
  is already included in the live import, with four shared AOS-CX claims.
- [2021-019](https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-019.txt)
  is the supported missing candidate. It retains 75 total claims, five AOS-CX
  shared unaffected statements, and publication date 2021-12-13. Its capture
  SHA-256 is `8d1abe635fbabc246c475f22e8ea6ee05c5a09501be1ef9a8b2384aa553b6199`.
  Those five statements must not increase the affected-CVE count or prove exact
  CX 6300M/6410 scope. A local candidate is not an approved hosted import.

## The separate research-adapter gaps are more relevant

All 32 unsupported research representations freshly normalize through existing
core adapters. Ten are outside the study period and 22 are in it. Many in-period
sources concern management, wireless, other software, aggregate notices or
security notices without CVEs. An EOS mention in their body is not affectedness.

Five in-period core records have EOS-labelled assessments worth a typed research
bridge review:

| Advisory | Initial date | Existing evidence / remaining work |
| --- | --- | --- |
| SA-0070 | 2021-12-12 | Mixed Log4j product/CVE/status scopes; EOS statements need local section ownership, not a global family join |
| SA-0075 | 2022-04-26 | CVE-2022-0778, affected EOS-based products; preserve separate non-EOS exclusions |
| SA-0081 | 2022-11-01 | Two OpenSSL CVEs, shared EOS unaffected statements; do not promote to explicit affectedness |
| SA-0128 | 2025-12-16 | CVE-2025-8872; explicit EOS version list, with platform scope still requiring review |
| SA-0201 | 2026-10-23 | CVE-2026-111943; separate EOS and TerminAttr lists; neither may inherit the other's versions |

The last two already use the same core affected-software HTML parser. A narrow
reviewed bridge can reuse its literal CVE/product/version claims without model
inference or generating publisher product IDs. The earlier mixed/table layouts
need their own source ownership review. These five are repair leads, not five
new affected CVEs: some are unaffected and CVEs may already appear through another
representation. Changed fresh HTML hashes also do not automatically certify the
published retained bytes.

## Cisco bundle recovery works with existing code

A fresh anonymous capture of
[ERP-75056](https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056)
is exactly the source already recognized by the shipped bundle binding:
`3ca993c5411757fe2567f966978c329f54c138b8139231b4d8161201e6563cb2`,
173,383 bytes. The parser returns one bundle with no extraction issues. This
particular gap needs the source retained alongside member advisories, rather
than a new bundle parser or inferred same-day grouping.

A separate local replay used 12 available member documents from an explicitly
public-only staging copy, opened read-only with an immutable SQLite connection.
It retained the official bundle page through the existing evidence writer in a
separate replay database. Full typed evidence and comparison construction passed:

| Same local member set | Before retaining bundle | After retaining bundle |
| --- | ---: | ---: |
| Affected advisory identities | 12 | 12 |
| Affected CVEs | 13 | 13 |
| Counted remediation events | 12 | 1 |
| Explicit bundled events | 0 | 1 |

The public stage lacks the thirteenth listed advisory, which is outside this
bounded IOS XE member set. This is a twelve-member subset demonstration, not a
recount of the full live site's 170 events or a complete Cisco bundle history.
Source input size/mtime remained unchanged. Replay processing times are not new
historical HTTP observations, and no raw evidence is redistributed in Git.

## Concrete next inputs

1. Retain the recognized Cisco bundle source in the authorized publication input,
   preserving its source-only role and member identity list. A hosted change needs
   a separate concrete activation proposal; do not add a fake advisory merely to
   get the page into storage.
2. Review/import the supported Aruba 2021-019 candidate through the existing writer
   and capture provenance. Its AOS-CX evidence is shared unaffected context.
3. Bridge SA-0128 and SA-0201 through the typed research hook with synthetic
   CVE/product/version separation negatives and fresh-source replay. Keep models
   unresolved and do not invent fixes.
4. Review SA-0070/0075/0081 local scope and representation selection next. Preserve
   all three categories: actual extraction gap, legitimate non-target content and
   unresolved evidence. A complete archive denominator remains unknown.

## Receipts and reproduction

Outside-Git operator artifacts are in `/tmp/impact-followup-20261109/`:
`triage.json`, `research-triage.json`, `coverage-worklist.json`/`.csv`, capture
hash/time metadata, scripts and `bundle-replay.json`. The source worklist has
102 rows (19 Aruba, 51 Arista queue errors, 32 separate research representations),
SHA-256 `2692b3090c89721ff88f5e0ee4739bca00586e28d9dd4c82e8627285cd25b408`.

Primary reads were bounded to 2,000,000 bytes each, at most four concurrent
requests, no retries, and a vendor-wide stop on observed rate limiting. Capture
bytes were cached. Existing normalizer fingerprints for the triage were Aruba
`325f186810f36cfe` and Arista `85c124006aa0bde2`, before the subsequent availability
repair. The triage ran existing parsers rather than fabricating normalized
advisories. Source listing hashes, URLs and capture times remain in the receipts.
No original/private vault, key, customer artifact or original sources.json was read.
