# Round 4 first delivery: release catalogues and publisher actions

25 November 2026; round 4 steps 1–4 only. Independent human review is pending.
Counts describe disclosure and collection, not vendor quality. Missing evidence is
unknown, never zero. These are bounded public-source investigations and an offline
catalogue implementation, not complete archive backfills or a vendor ranking.

## Release catalogue and coverage

| Train and requested models       |         Observed version references | Stated release dates by year: 2024 / 2025 / 2026           | Coverage and denominator                                                                                                                                                                |
| -------------------------------- | ----------------------------------: | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IOS XE 17.12; Catalyst 9200/9300 |     8 unique; 16 model/version rows | Unknown / unknown / unknown                                | Partial enumeration from two model-specific release-note boot-loader tables; dates and historical download catalogue missing. Denominator unknown.                                      |
| AOS-CX 10.13; 6200/6300          | 24 unique; 27 platform/version rows | 11 / 8 / 5 unique dated references, research excerpts only | Partial; original documents unavailable, histories differ by model and TOC-only references remain gaps. Denominator unknown.                                                            |
| EOS 4.33; 720XP/720DP            |         8 unique version references | Unknown / unknown / unknown                                | Partial; two exact availability announcements, three bulletin-link leads, two advisory-only leads and one deferral identity. Model scope and full history unknown. Denominator unknown. |

2026 is year-to-date through 25 November. Aruba's individual model rows are
6300: 10/8/5; 6200: four observed early-2024 dates, with later history unknown.
Summing model rows would inflate distinct-version counts. The repeated 6300
10.13.1000 table row was deduplicated. The blank remarks on 10.13.1101 do not
establish its posted/support status. TOC entries do not supply missing release dates.

Cisco's version table includes 17.12.7a but not 17.12.7; that absence establishes
neither a withdrawal nor whether the omitted version shipped. Original HTML was
retrieved and fingerprinted for both tables, five notices and the 17.9 control.
The current C9300 index contains 11 notice IDs, five of whose detail pages were
investigated. Six older leads and the C9200 notice-index route remain gaps.

Arista's RSS retains only two 4.33 availability announcements. Their dates are
15 October and 3 November 2026; they remain announcement dates, with binary
release dates unknown. The two advisory version references are explicitly research
leads and do not establish shipped releases or support for the study models.
Twenty field-notice summaries were inspected at offsets 0 and 40, plus a rolling
10-item notice feed; this is not the complete archive. Full sampled detail and
release bulletin routes require sign-in. Automation permission remains unresolved.

## Possible respins

The configurable same-base rules find **21 distinct observed version pairs** in
Aruba's rendered, model-scoped histories within 90 days: 19 for 6300 and two for 6200. **Two** are within 30 days:

- 6300: 10.13.1005 → 10.13.1010, 18 days.
- 6200: 10.13.1003 → 10.13.1005, 17 days.

All are `possible_respin`, research-only, with both source dates and quotations
retained in the [machine-readable summary](2026-11-25-release-catalogue-summary.json).
The AOS-CX grouping is the configured 10xx/11xx maintenance convention, not a
publisher statement that these were emergency fixes. Routine maintenance can
produce these pairs; missing intervening releases can change predecessor selection.
No corrective relationship or reason is inferred from timing. The true historical
corrective-respin total remains unknown.

Arista's 4.33.11M → 4.33.11.2M announcements are 19 days apart. This remains an
announcement-follow-up observation in its research packet, not a dated/model-bound
release-respin pair. Cisco has no dated pair in the extracted catalogue; its
respin total is unknown rather than zero.

## Notices, explicit status wording and the control case

Cisco: five detail notices investigated. FN74221 and FN74135 provide conditional
configuration/certificate-remediation context. FN74135's model-specific display-fix
versions are structured separately: 17.12.2 for Catalyst 9200 and 17.12.1 for
Catalyst 9300, with their conditions retained. They are not universal upgrade or
release-withdrawal claims. FN72416 is explicitly hardware/manufacturing context;
its header first-publication date (24 May 2024) conflicts with its initial revision
(22 May), so the normalized notice date is unknown and both source dates remain
in the packet. FN74383 is an access-point scope exclusion. FN72510's switching
applicability starts at 17.15.1 despite a generic 17.12.1 reference; it is excluded.

Arista: FN0103 explicitly defers EOS 4.33.3F for a stated software defect. Its notice
is dated 1 July 2025; action date, replacement release and study-model applicability
remain unknown. The normalized record retains this as a release-deferral notice
and an explicit status statement, without assigning it to 720XP or 720DP. FN0144
is timezone context, not a withdrawal, and its announcement/display dates differ.

Aruba: a public HPE **Customer Advisory** source was found at
[a00142509en_us](https://support.hpe.com/hpesc/public/docDisplay?docId=a00142509en_us&docLocale=en_US).
The inspected advisory names 8325/9300 and qualified cables, so it is an exclusion
control, not a 6200/6300 or withdrawal incident. A separate security bulletin is
context and has differing portal/history dates; no such date becomes a software
release date. A systematic public nonsecurity notice archive for this cohort has
not been established. No qualifying withdrawal was found in the bounded searches;
absence and a zero incident total cannot be claimed.

**Cisco IOS XE 17.9.6 withdrawal remains unverified.** The original Cisco 17.9
release-note chapter explicitly states a 17.9.6a fix for CSCwm57734. It does not
establish the first affected version, withdrawal decision/date, release dates or
an explicit 17.9.6 → 17.9.6a corrective relationship. This control is outside the
17.12 catalogue and contributes no cohort count.

## Provenance, validation and remaining work

- [Cisco packet](2026-11-25-round4-cisco.json) and [notes](2026-11-25-round4-cisco.md).
- [Aruba packet](2026-11-25-round4-aruba.json) and [notes](2026-11-25-round4-aruba.md).
- [Arista packet](2026-11-25-round4-arista.json) and [notes](2026-11-25-round4-arista.md).
- [Normalized catalogue](2026-11-25-release-catalogue.json), [summary](2026-11-25-release-catalogue-summary.json), and [tool documentation](../RELEASE_CATALOGUE.md).

Each fact has quoted evidence, a locator and a source receipt. Original-document,
research-excerpt and blocked-response fingerprints remain distinct. Full vendor
captures are cached outside Git; only facts and limited source quotations are
retained here. Access outcomes and robots/terms checks are in each vendor packet.
No login, challenge bypass, third-party mirror or customer data was used.

Thirty focused catalogue/packet tests and 106 tests including adjacent release-signal checks passed. The final capture audit verified 47 cached public documents and excerpts against their declared fingerprints. The fresh code and packet reviews
reported no remaining blocking findings after fixes for model aggregation, receipt
chronology and coverage handling. These are automated/code reviews; they do not
mark publisher classifications as independently human reviewed.

Outstanding before defensible rates: Cisco release dates and historical enumeration;
Aruba original bytes plus missing 6200/TOC history; Arista public historical release
and model evidence; complete notice/status histories for all three; source-specific
permission for unattended collection; and independent human review. The catalogue
therefore keeps all nine train/year denominators null.

**Stopped before steps 5–8**, as requested. Rates, staircase annotations, site
markers/tables, hosted collection, publication roots, README/changelog integration
and the final human-approval packet remain for the next approved delivery.
