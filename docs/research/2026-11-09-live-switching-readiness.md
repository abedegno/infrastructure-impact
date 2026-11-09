# Live switching comparison investigation — 9 November 2026

The Cisco import is live. It materially improves discovery coverage, but the
current patch-publication counts cannot support the customer's workload comparison.
The most useful next work is source attribution and release/bundle evidence, not
another transport or capacity redesign.

This updates the [7 November customer brief](2026-11-07-vendor-comparison-brief.md).
Its pinned registry-discovery results remain historical observations; its website
membership table predates the import and must not be presented as current.

## What the live data establishes

Public generation `036b4934119c48cf890aed3df205739e`, generated
`2026-11-09T07:14:24.130713+00:00`, contains these OS-family observations for
2021-01-01 through 2026-11-09:

| Observation | Cisco IOS XE | Aruba AOS-CX | Arista EOS |
| --- | ---: | ---: | ---: |
| Advisories with explicit affected claims | 170 | 16 | 50 |
| Distinct explicitly affected CVEs | 199 | 104 | 65 |
| Counted remediation publications | 170 | 1 | 1 |
| Counted explicit bundles | 0 | 0 | 0 |
| Scoped draft advisory identities | 0 | 0 | 22 |
| KEV-listed affected CVEs at generation time | 4 | 0 | 0 |
| Expected historical advisory total | Unknown | Unknown | Unknown |

These are the existing reducer's observations, not newly inferred exposure. Cisco
has more observed affected CVE IDs in this retained family-level dataset. That
is not yet a like-for-like Catalyst/CX/EOS model comparison, a complete disclosure
census or evidence of greater maintenance work. Drafts are excluded from affected
counts; scoped draft counts do not include every draft in a vendor's collection.
KEV values above are pinned to the generation-time evaluation, not a fresh claim
about exploitation or current feed freshness.

The IOS XE family includes other product roles: one counted publication is
`cisco-sa-9800cl-openscep-SB4xtxzP` (CVE-2025-20293), a wireless-controller advisory.
The family total must therefore not be labelled a Catalyst switching total.
The live rows flag 34,831 of Cisco's 34,920 claims and all 877 Aruba claims as
model-unresolved. Those are version/product statements, not independent CVEs.

## Why the existing readiness result is not the study's gate

`application/readiness.py` uses the older 24-CVE dependency benchmark. Its
switching plan selects Cisco **NX-OS**, Aruba AOS-CX, Arista EOS and Juniper
switches, rather than this study's IOS XE/Aruba/Arista cohort. It always emits
`eligible_comparisons: []`, blocked rows and suppressed rates. Several requirements
are deliberately fixed as missing/unverified, regardless of imported volume.

That is a conservative benchmark report, not a dynamic pass/fail test for whether
we may describe the separate campus/branch study. More imports cannot make it
pass. Keep the ranking safeguards, but clearly identify which report a readiness
message describes. The campus study needs metric-specific readiness: observed
counts can be shown with gaps even when upgrade workload remains unknown.

## Validation: missing evidence was mistaken for extraction failure

The global 25-case report contains:

| Outcome | Cases |
| --- | ---: |
| Exact reviewed source bytes and expected extraction match | 13 |
| Reviewed section matches after surrounding source bytes changed | 7 |
| Source missing from the evaluated current records | 3 |
| Source revision not reviewed | 2 |
| Extraction disagreement | 0 |

All three missing cases concern one Check Point source. Both unreviewed-revision
cases concern one Fortinet release-note source. Thus **13/25 is not a 52% parser
accuracy estimate**, nor evidence of twelve switching extraction failures. The
seven section matches remain distinct from exact-byte passes. Independent human
review is still pending.

A separate 16-case switching definition and CLI exist, but the live publication
catalogue exposes no `switching-validation.json` or switching review packet. Its
bootstrap exports section fingerprints for the global definition only.
Replaying the switching definition against the 27 current public records selected
by its eight CVE IDs produces seven exact-byte passes, three `source_missing`
results and six `source_revision_unreviewed` results:

- Cisco: two exact matches; three cases use the OpenSSH **CSAF alternate** absent
  from the selected current records. This does not establish whether alternate
  bytes exist in the hosted retained vault. Those three controls are SD-WAN
  products, so they also do not independently validate three Catalyst cases.
- Aruba: all five cases match the reviewed bytes and expected claims.
- Arista: all six cases require fingerprints of changed source bodies that the
  global export does not supply. This public replay cannot substitute for the
  vault-backed `switching-validation` CLI.

A bounded fresh check of the four Arista official pages found that **all four
reviewed structural section hashes still match**, covering those six cases, while
all four complete-page hashes differ from the published records. This supports
page-wrapper changes as an explanation. It does not bind fresh bytes to the
published record hashes, certify the retained six cases, or constitute human review.
Publish the actual retained-source switching validation report instead of guessing.

## Why patch-publication counts are not comparable

`switching_comparison._events` requires an explicit affected claim and a reported
available vendor fix bound to that same product ID or a reviewed source section.
Fixed-only release claims cannot independently authorize an event. These guards
prevent false joins, but source formats currently receive very unequal attribution.

For [Aruba HPESBNW04669](https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04669.json),
a fresh download exactly matches the published SHA-256
`07e221b234c64d09ef18a2d291639e2bbca2d6f4bd511dbb6325fee088daa138`.
Adapter replay preserves five affected AOS-CX ranges and three fixed releases.
The affected branches receive workaround evidence; the `vendor_fix` is scoped to
separate fixed product IDs. Its typed availability also remains `unknown` under
the conservative wording classifier. Consequently this disclosed fix contributes
no remediation event, despite explicit resolution information in the source.
The source's multi-product text also contains negated lifecycle wording; broad
keyword relaxation would risk attributing fixes to the wrong product or branch.

For Arista, the only counted event is [SA-0100](https://www.arista.com/en/support/advisories-notices/security-advisory/19904-security-advisory-0100),
where an existing reviewed bridge explicitly links EOS affected and resolution
sections. The live rows retain 384 Arista and 443 Aruba fixed-only claims. These
are not hundreds of upgrade events, but they show why a value of one cannot be
interpreted as the vendors having published only one patch.

For Cisco, the reviewed [March 2024 bundle ERP-75056](https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056)
lists 13 advisories covering 14 vulnerabilities. The code has a binding for that
bundle, but retained-source assembly reports `bundle_source_unavailable`; all 170
counted Cisco events are currently labelled unbundled. Missing bundle evidence
must mean **grouping unknown**, rather than proof each advisory was an independent
patch cycle. Same-day grouping would not establish publisher membership.

## Coverage gaps that remain after the import

- **Cisco:** 173 pinned CSAF documents were imported, but source audit still says
  `bounded_feeds_and_pins`, archive not enumerated, total unknown. A successful
  target import is not complete IOS XE archive coverage. The older access-review
  entry is dated context; it is not a new probe proving current access failure.
- **Aruba:** all 112 documents in the observed CSAF index are processed with no
  queue errors. That index's publication range starts in February 2022. The added
  2021-013 bulletin helps, but does not complete 2021. The earlier public stage
  found 19 historical TXT documents and parsed only two; that remains a concrete
  bounded source list to triage, rather than an invitation to guess URLs.
- **Arista:** 21 listing pages are processed, with 203 discovered documents: 152
  done, 51 errors, zero pending. The queue is not complete while errors remain.
  Many errors are old publications; triage by actual date/family relevance before
  spending effort on them. Separately, 32 retained representations report
  unsupported switching research layouts; this overlaps other error categories
  and must not be added to 51 as independent missing advisories.

The switching row's `coverage.state` is currently constructed as `partial` whenever
source observations exist, with expected totals null. It does not measure yearly
completeness, even where a particular listing has been exhausted. Per-vendor row
issues also include report-wide issues: `bundle_source_unavailable` appearing on
Aruba or Arista is not evidence that their own bundle source failed.

Dates add another boundary: the study groups latest retained CVE claims by the
advisory's initial publication date. Arista SA-0100 added CVE-2024-6409 in a later
revision. Such a CVE is still grouped under the original advisory date. That is
an advisory-cohort measure, not the date each CVE was first disclosed by the vendor,
so it cannot establish a post-7-April discovery effect without revision evidence.

## Recommended repair order

Reuse the existing [coverage and comparison backlog](2026-11-05-source-coverage-backlog.md),
with these narrowed next actions and acceptance checks:

1. **VAL-01: publish truthful study diagnostics.** Export the vault-backed switching
   validation and its matching fingerprints/packet. Separate exact, section-match,
   unavailable and disagreement outcomes. Show metric-specific readiness and
   attribute vendor issues to their actual source. Test retained alternates,
   changed wrappers and foreign-vendor issues without marking human review complete.
2. **CMP-01: repair remediation and bundle attribution.** Recover the explicit
   Cisco bundle source and membership; add source-supported Aruba/EOS affected-to-fix
   links using product/CVE/section ownership. Represent unverified grouping and
   attribution as unknown. Test cross-CVE/product negatives, plans, workarounds,
   lifecycle exclusions and same-day non-bundles. Do not turn fixed-only claims
   into inferred model exposure or actual required upgrades.
3. **COV-01/COV-04/COV-05: close relevant source gaps.** Triage the known 2021 Aruba
   TXT list and Arista errors first by study period/family. Reconcile Cisco's
   imported targets with pinned official CVE discovery and observed archive links.
   Report discovered/retrieved/parsed/qualified counts separately. Exhausted queue
   and complete exposure inventory remain different concepts.
4. **CMP-01/CMP-03: answer the customer's question in the right scope.** Separate
   broad OS-family context from explicitly supported model applicability; update
   the dated customer brief with observed CVEs, severity, KEV, known/unknown event
   grouping and coverage. Add first-observed CVE additions/revisions before claiming
   annual or pre/post vendor-disclosure trends. Actual deployment workload and
   fix latency need supported releases/configurations and dated release evidence.

The current evidence supports saying that Cisco has more observed affected CVE
IDs in this family-level collection. It does not establish that the customer's
Cisco switches require more upgrades, that vendors are equally secure, or that
another vendor concealed fixes. Missing CVE references remain investigation leads.

## Verification and evidence handling

Public index/bootstrap/catalogue/overview hashes were checked, and the actual
published browser data client was used to load the selected validation records
and all three event-detail ranges. Downloads were cached; no hosted collection,
schedule, permissions, publication or private vault changed. Five official source
checks used bounded reads and at most three concurrent requests. This was data-client
execution, not visual browser testing.

The focused existing tests passed: **73 tests in 8.09 seconds**, covering switching
set/event semantics, validation outcomes and dependency readiness:

```sh
IMPACT_SOURCES=infrastructure_impact/resources/sources.json \
  .venv/bin/python -m pytest -q tests/test_switching_comparison.py \
  tests/test_switching_validation.py tests/test_research_foundations.py
```

Verified public input digests:

- Bootstrap: `dfe7d25e433c8a4248f2a389f5dbeeb198534cb2eeb9b51f5ce4cf49ffb65a31`.
- Publication catalogue: `53105a9d484628d2afbc1472e6e10093d50f76fdac739ce97a9233c0b237b43e`.
- Switching overview: `81d2c6c0564bb55daae3364d7f548f2ee262ccfc14443c5a66aa3acad993728e`.

Public diagnostic downloads, scripts and detailed receipts remain outside Git,
under `/tmp/impact-investigation-20261109/` for this local investigation. No source
captures, databases, credentials or customer data are added to the repository.
