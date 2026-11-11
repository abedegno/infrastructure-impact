# Switching comparison evidence audit — 11 November 2026

This is a dated successor to the [10 November audit](2026-11-10-switching-evidence-audit.md), using publication `c2115c35b1c84b7dbdb3134ccac98acd`, generated `2026-11-11T10:29:39.376925+00:00`. Its [compact evidence receipt](2026-11-11-comparison-evidence/evidence.json) records source identities, hashes and counts. Public metadata was downloaded once and reused. No private evidence, credentials, full snapshot archive or worker logs were needed.

## What the current observations support

| All-period OS-family observation | Cisco IOS XE | Aruba AOS-CX | Arista EOS |
| -------------------------------- | -----------: | -----------: | ---------: |
| Affected advisories              |          170 |           16 |         55 |
| Distinct affected CVEs           |          199 |          104 |         70 |
| Remediation publications         |          159 |            6 |          6 |
| Expected applicable advisories   |      Unknown |      Unknown |    Unknown |
| Coverage                         |      Partial |      Partial |    Partial |

These are study observations from original advisory publication dates, starting in 2021. They are not complete company-wide CVE totals or counts of customer upgrades. The model-unspecified claim counts are 34,831 / 882 / 478 respectively: the family totals cannot be asserted for every named chassis or configuration. Observed advisory totals including unaffected and other context are 170 / 21 / 60, distinct from the affected-advisory row.

The site contains 1,240 current advisory records, 1,241 retained records and one exclusion. Its public health inventory contains 1,291 distinct vendor/source-URL identities and 73 retained errors. Those inventories describe different things; none supplies a missing-CVE denominator.

The [yearly advisory table](2026-11-10-comparison-evidence/coverage-by-year.csv) remains explicitly through **10 November**, not an updated 11 November census. A fresh per-year join needs deferred identities and publisher dates beyond the compact overview. This audit does not assign a source to a year using its collection date or a CVE's identifier year.

## Fourteen latest-run failures, classified

Collection run 78 ran from `2026-11-11T10:26:05+00:00` to `10:29:36+00:00` and reported 14 failures.

| Category                                                          | Count | Consequence for this study                                                                                                                                                                                                                             |
| ----------------------------------------------------------------- | ----: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Arista SA-0007, 0009–0014 and 0016 retained normalization replays |     8 | Their exact URLs join the previous preserved triage: initial dates in 2014–2015, outside this advisory-date study. Current metadata reports cached normalization, not new HTTP fetches. This is a historical triage join, not a fresh raw-hash review. |
| Arista SA-0226                                                    |     1 | In-period server-hardware bulletin, initially published 10 November 2026. Explicit EOS-unaffected evidence is currently lost to an unsupported layout. It does not justify adding affected EOS CVEs.                                                   |
| Check Point access/verification                                   |     4 | Separate vendor, including articles needed for the older global mapping benchmark. No product body may be invented from a challenge shell.                                                                                                             |
| Palo Alto PAN-SA-2016-0033                                        |     1 | Separate vendor. Current diagnostic places an advisory identifier in a CVE field; no CVE should be guessed.                                                                                                                                            |

There is no latest-run Fortinet failure. The older 13-failure breakdown cannot be reused as today's 14. Retained errors are another inventory: Arista 52, Palo Alto 14, Check Point four and Fortinet three. These are not 73 missing vulnerabilities.

## Coverage boundaries that remain

| Vendor | Observed discovery state                                                                                             | Missing evidence                                                                                                                                                                                                                                                  |
| ------ | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cisco  | RSS window of 50, four items per pass; retained exact targets; no current source errors; historical archive disabled | No established complete IOS XE advisory denominator. Supported authenticated enumeration already exists but authorized credentials are unavailable. Rewriting it or increasing RSS depth would not prove completeness.                                            |
| Aruba  | Current CSAF index: 113 listed/processed, no queue errors or pending documents; published dates begin in 2022        | Index exhaustion is not a complete 2021+ AOS-CX archive. Earlier review captured 19 historical 2021 TXT documents; two relevant repairs are retained, 17 layouts remain unsupported. Missing family labels do not prove unaffectedness.                           |
| Arista | 219 discovered identities: 155 done, 51 error, 13 pending; 21 listing pages; known queue not exhausted               | Pending IDs/dates are absent from the compact public report, so their study relevance is unknown. A selected SA-0103 HTML source exists despite an alternate-route retained error. Completed discovery would still not establish all indirect component exposure. |

A bounded fresh Arista listing request returned a client challenge; collection stopped without executing or bypassing it. The existing bounded incremental queue may process pending identities on later runs. No schedule, limit or hosted configuration is changed here, and queue completion must not be called historical completeness.

## Two bounded implementation corrections

**Cisco release context.** The exact retained OpenSSH HTML already owns CVE-2024-6387 / `IOS XE Software with NETCONF enabled` / `17.15.1` in one source row. A fresh primary response reproduced SHA-256 `efd1e8a9f975b68a6b5c002567b2279a27fd1feb61b5c5a6b8d9d2407b82e7d0`. The release projection previously omitted every Cisco product. This branch admits that reviewed product and a bare numeric three-component literal, preserving source-row ownership. The separate reported `17.12.1` release date cannot supply a date for `17.15.1`. No new affected CVE, remediation publication, fixed-only claim, release date or customer-model qualification follows.

**Arista SA-0226.** The fresh [primary bulletin](https://www.arista.com/en/support/advisories-notices/security-advisory/25048-security-advisory-0226) is 113,647 bytes, SHA-256 `a13c363d04840f17d5c31cd41e1301478150bf6b367d10759a583eba54a2aeb7`. Its two CVA tables own 15 CVEs and its platform section explicitly excludes EOS-based products. The generic fallback misses its lowercase exclusion/div/list layout. The scoped repair recovers shared-bulletin unaffected EOS evidence only; it does not reconstruct OEM server, DMF or AGNI affected/fixed matrices. Slash labels such as `720XP/722XPM Series` and `7050X3/X4 Series` remain literal and unresolved; `750X Series` does not become the frozen study's `750` model. The DCA-350E/DCA-350 discrepancy is retained as a limitation.

The fresh SA-0226 hash is not proof of byte identity with the failed hosted capture, whose hash is not exposed in health metadata. Local replay and synthetic fixtures are not hosted acceptance. Existing published generations remain immutable; branch changes do not clear a live error before a normal approved rollout.

Ordinary local normalization and research projection of those verified bytes now produce 15 shared-bulletin unaffected EOS assessments/claims, with 27 literal platform entries and unresolved bindings. The selected EOS list includes the publisher's `CloudVision eXchange, virtual or physical appliance` literal; adjacent outer Wi-Fi/CVA blocks do not enter that list. The resulting comparison has zero affected CVEs, remediation events, fixed-only claims and model-qualified CVEs. The Cisco byte replay produces one `17.15.1` affected-scope reference, versus none with the baseline projector; its fixed-only count is null and software date remains unknown. Both replay receipts are included in the compact evidence JSON. These are scoped correctness checks, not a recomputed full live snapshot.

## Validation: two different sets of three

| Automated check                     | Current result                                                                            | Remaining boundary                                                                                     |
| ----------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Global 47-case mapping benchmark    | 44 pass, three missing sources                                                            | Check Point `sk182459` / `sk181833`, not Cisco switching extraction                                    |
| Global 25-case extraction sample    | 13 exact, seven reviewed-section matches, three missing sources, two unreviewed revisions | Different match categories remain distinct                                                             |
| Switching 16-case extraction sample | Seven exact, six reviewed-section matches, three missing selected sources                 | Cisco OpenSSH CSAF alternate; controls concern Catalyst SD-WAN, not three extra campus-switch examples |

All three Cisco cases now carry `retained_unselected_representation` context binding the reviewed CSAF hash to selected HTML. That is provenance clarification, not extraction acceptance, and their outcomes remain unchanged. These three must not be conflated with the Check Point benchmark misses. Independent human review is still pending; the maintainer's [blind packet and instructions](2026-11-10-comparison-evidence/README.md) remain the review entry point. Automated development review does not substitute for that adjudication.

## Next evidence with the highest value

1. Use authorized Cisco API access when available to establish dated enumeration totals; retain document retrieval failures separately.
2. Observe bounded Arista queue catch-up and classify pending documents once identities and source bodies are available. Do not spend the study's effort repeatedly retrying legacy out-of-period failures.
3. Expand source-owned release/train and platform/configuration evidence. One Cisco fix reference and partial peer histories cannot establish relative upgrade burden.
4. Complete the independent sample review. Preserve uncertainty where a source is inaccessible, model-unspecified or unreviewed.

The [customer assessment](2026-11-11-customer-comparison-assessment.md) answers what can be said now without treating these gaps as zeros.
