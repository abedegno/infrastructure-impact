# Published switching comparison run — 14 November 2026

Publication `3591f3596d5e41fe8d50ac633b8357e1`, generated `2026-11-14T22:02:30.723081+00:00`, is the final published evidence for this report. [Apply run 43645634729](https://github.com/abedegno/infrastructure-impact/actions/runs/43645634729) completed from [source commit a0e1f4212fb1f11bfdcc79564aa45f0bb237cead](https://github.com/abedegno/infrastructure-impact/commit/a0e1f4212fb1f11bfdcc79564aa45f0bb237cead), with verified recovery, Pages delivery and fresh health. The run performed maintenance; full benchmark acquisition was **not run**. Read the [customer comparison](2026-11-14-published-vendor-comparison.md) for the decision-facing interpretation and the [machine evidence](2026-11-14-published-switching-evidence.json) for exact rows and hashes. Earlier reports pinned to publication `a3a7a1fcdc194599b2903d39484ba340` remain unchanged.

The study uses publisher initial dates from 1 January 2021 through 14 November 2026. Family-level findings are not proof that a selected hardware model or installed configuration is affected. All three vendors have partial source coverage with unknown expected inventories.

## 1. Usable fix evidence by scenario and method

These are issue-free usable requirements, with distinct advisory/CVE coverage within each row. Rows overlap and cannot be added to estimate releases or upgrades.

| Vendor | Scenario              | Requirements | Advisories | CVEs |
| ------ | --------------------- | -----------: | ---------: | ---: |
| Cisco  | Publisher first fixed |        2,183 |         76 |   91 |
| Cisco  | Known fixed target    |        2,184 |         77 |   92 |
| Cisco  | Inferred inclusive    |        2,851 |        116 |  134 |
| Aruba  | Publisher first fixed |            0 |          0 |    0 |
| Aruba  | Known fixed target    |          288 |          6 |   64 |
| Aruba  | Inferred inclusive    |          288 |          6 |   64 |
| Arista | Publisher first fixed |            0 |          0 |    0 |
| Arista | Known fixed target    |           28 |          6 |    8 |
| Arista | Inferred inclusive    |           28 |          6 |    8 |

Cisco's publisher-first-fixed requirements comprise 1,518 OpenVuln API requirements (75 advisories/84 CVEs) and 665 stated-table requirements (one advisory/seven CVEs). Known-fixed adds one affected-scope association; inferred-inclusive adds 667 inferred-next-release requirements (57 advisories/60 CVEs). Aruba's 288 and Arista's 28 usable requirements use affected-scope links. A known-fixed association does not establish the **first** fixed release: the retained Aruba CVE-2021-41002 direct versions and Arista SA-0158 associations remain known-fixed only.

The API supplies 38 alternative version literals and 241 version/CVE pairs across its 75 advisories/84 CVEs; these are alternatives, not 38 required upgrades. It supplies no availability dates for these requirements. The [Cisco OpenVuln API](https://developer.cisco.com/docs/psirt/) and retained publisher evidence have different scopes; neither missing dates nor missing publisher-first-fixed evidence establishes that no fix exists.

## 2. Retained-table inference calibration

The census covered all 224 current retained Cisco records, including retained excluded wrappers: 223 have no normalized stated table, and one has six table units. It does not establish completeness of raw extraction, unretrieved advisories, historical revisions or the vendor archive. Native table validation passed. Against the retained [Cisco hardening advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxe-V8NMuMZJ/csaf/cisco-sa-hardening-iosxe-V8NMuMZJ.json), excluding that advisory from the release catalogue used for inference:

| Train            | Publisher target    | Inferred candidate | Result                     |
| ---------------- | ------------------- | ------------------ | -------------------------- |
| 17.8 and earlier | Migrate             | None               | Migration stratum; abstain |
| 17.9             | 17.9.10             | 17.9.10            | Match                      |
| 17.12            | 17.12.8             | 17.12.8            | Match                      |
| 17.15            | 17.15.6             | 17.15.7            | Mismatch                   |
| 17.18            | 17.18.4 or 17.18.4a | None               | Eligible abstention        |
| 26.1             | 26.1.2              | 26.1.3             | Mismatch                   |

Five units are eligible: four candidates issued, two matches, two mismatches and one abstention. Both any-alternative and exact-set agreement are 2/4 (50%). The migration row is outside that denominator. This is one shared bulletin table, not six independent advisories or an accuracy estimate for Cisco generally. The catalogue is observed-only and evidence timing is latest-known retrospective.

## 3. KEV reconciliation and chronology repairs

The [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) revision `2026.11.13` has 1,781 entries; exact family-pair mapping yields 29 candidates: five documented affected and 24 with no observed vendor record. SA-0137 now documents conditional EOS affectedness for [CVE-2026-7473](https://www.arista.com/en/support/advisories-notices/security-advisory/24005-security-advisory-0137), retaining tunnel/platform prerequisites and mitigation with no planned software upgrade path. The earlier draft is retained. No patch target or selected-model alias was inferred.

The final 24 unmatched CVE IDs exactly equal the 24 independently enriched baseline leads. Cached official CVE records and exact CVE-linked Cisco advisory headers put **all 24 initial vendor publications in 2016–2018**, before the study starts. This verifies the candidate set against the final publication, while preserving the external enrichment's old-baseline provenance. These are historical collection leads; they do not establish an in-window 2021-onward gap, concealment or model exposure. CVE updates and vendor “Last Updated” dates do not move initial-publication cohorts. The evidence JSON includes all 24 primary header URLs, literals and hashes; independent AI verification reported no actionable errors, with human review pending.

All 33 repaired Arista CSAF records (SA-0165–0183 and SA-0185–0198) use corrected effective initial dates while preserving original current-release dates. The method uses the HTML advisory's explicit initial/revision-1.0 date: SA-0165–0182 **9 September**, SA-0183 **22 September**, the separate HTML SA-0184 **29 September**, and SA-0185–0198 **6 October 2026**. The task's RSS dates of 21/28 September and 2 October describe different observations; they were not substituted for the HTML initial date. This does not establish the first moment a page became publicly available, and no timezone reconciliation is inferred. See representative [SA-0165](https://www.arista.com/en/support/advisories-notices/security-advisory/24721-security-advisory-0165), [SA-0183](https://www.arista.com/en/support/advisories-notices/security-advisory/24765-security-advisory-0183), [SA-0184](https://www.arista.com/en/support/advisories-notices/security-advisory/24776-security-advisory-0184) and [SA-0185](https://www.arista.com/en/support/advisories-notices/security-advisory/24801-security-advisory-0185). SA-0178 retains current fixed products and its revision conflict; preserved current dates earlier than corrected initial dates remain visible.

## 4. Disclosure, bundles and severity

The original study cutoff is 7 April 2026, included in the post period. These native public selections use the same OS-family scope; the pre period starts in 2021 and is not a matched-duration control.

| Vendor | Before 7 April: advisories / CVEs | From 7 April: advisories / CVEs | Remediation publications: pre / post |
| ------ | --------------------------------: | ------------------------------: | -----------------------------------: |
| Cisco  |                         164 / 187 |                          6 / 12 |                              153 / 6 |
| Aruba  |                           15 / 68 |                          2 / 38 |                                5 / 1 |
| Arista |                           29 / 35 |                         27 / 36 |                                5 / 2 |

Advisory and remediation-publication dates are separate counting bases. These publication counts do not establish customer upgrades or a causal effect of Glasswing.

Cisco's July comparison uses **1 January 2021–30 June 2026**, followed by **1 July–14 November 2026**. The earlier denominator is the whole study window before July, not only early 2026.

| Cisco period | Advisories | CVEs / owned pairs | Umbrella CVEs | Disclosure method pairs       |
| ------------ | ---------: | -----------------: | ------------: | ----------------------------- |
| Before July  |        164 |                187 |             0 | 186 pre-risk-based; 1 unknown |
| From July    |          6 |                 12 |             7 | 7 risk-based; 5 unknown       |

The seven umbrella CVEs belong to one security-hardening advisory. The separate [ERP-75056 bundle](https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056), initially published 27 March 2024, links 13 member advisories; 12 are selected, covering 13 selected CVEs. An umbrella, a bundle, an advisory and a remediation event are different units. Whole-window Cisco has 159 remediation events, including one bundled event; these are not required customer upgrades.

Cisco source-specific severity rows are CVSS 3.1 Critical 7, High 102, Medium 85; CVSS 3.0 High 1, Medium 3; and Unknown 1. Aruba and Arista provider/version-specific rows, annual rows and disclosure-period mixes are retained in the evidence JSON. Unknown rows remain explicit, and mixed versions/providers or overlapping CVEs are not combined into a vendor risk ranking. Across the selected disclosure evidence, 178 metadata associations and 356 explicit-bundle associations are unavailable; absence of bundle metadata does not establish an unbundled publication.

## 5. Exact requested trains and release context

The annual matrix contains all nine requested trains: Cisco 17.9/17.12/17.15, Aruba 10.13/10.14/10.16, and Arista 4.32/4.33/4.34. Nine trains × six years (2021–2026) × three scenarios × two policies yields **324 rows**. Every required total `event_count` is null. Partial `supported_event_count` values are evidence counts and must not be published as minimum upgrade requirements. Actual installed baselines, complete fix/release histories and necessary model/configuration bindings are unknown; 2026 is a partial year. The wider analysis has 3,240 upgrade rows, of which 24 have known totals; those do not change the 324 requested rows.

| Vendor / train | Initial advisory years in retained requirement statements | Annual upgrade totals, all requested policies/scenarios |
| -------------- | --------------------------------------------------------- | ------------------------------------------------------- |
| Cisco 17.9     | 2021–2026                                                 | Unknown                                                 |
| Cisco 17.12    | 2021–2026                                                 | Unknown                                                 |
| Cisco 17.15    | 2021, 2022, 2024–2026                                     | Unknown                                                 |
| Aruba 10.13    | 2021–2026                                                 | Unknown                                                 |
| Aruba 10.14    | 2021–2025                                                 | Unknown                                                 |
| Aruba 10.16    | 2021–2026                                                 | Unknown                                                 |
| Arista 4.32    | 2024–2026                                                 | Unknown                                                 |
| Arista 4.33    | 2024–2026                                                 | Unknown                                                 |
| Arista 4.34    | 2024–2026                                                 | Unknown                                                 |

These are years of the advisories behind latest retained statements, including requirements with no usable target. They are not train introduction years, support years or proof of historical exposure. For example, a revised advisory can name a train introduced after its initial publication. The matrix still retains all requested calendar rows; missing observed years do not become zero upgrades.

Separate [Arista lifecycle matrix](https://www.arista.com/en/support/product-documentation/eos-life-cycle-policy) context, updated 23 October 2026, gives 4.32.x initial/support-end dates 9 April 2024/9 April 2027; 4.33.x 10 October 2024/10 October 2027; and 4.34.x 25 April 2025/25 April 2028. These are train dates, not patch availability or first-fixed dates, and future support dates are planning statements. The retained matrix and independent AI visual inspection are separate research context; they were not added to hosted release history. Platform exceptions for 7500R/R2 do not establish applicability to the selected 750 chassis. Independent human review remains pending.

## 6. Model bindings, incompleteness and acceptance

The union computed from model-bound advisory/CVE IDs is **four advisories and five CVEs**. Cisco literal-model rows overlap: 9200 has 2/2, 9300 3/4, 9300L 1/2 and 9500 1/1 advisory/CVE counts. Other requested model rows have zero retained bindings; zero bindings does not establish unaffectedness. Do not add model rows or substitute family totals for a customer-specific assessment.

Expected complete vendor inventories, unretrieved counts, raw-table extraction completeness, historical revision completeness, family/year attribution of source errors and actual customer upgrade counts remain unknown. The published source audit reports zero retained source errors for Cisco and Aruba, and 51 for Arista. Those 51 are last-recorded unsupported-document outcomes: 46 have explicit initial dates before 2021; four have older Date headers but unknown initial dates and cohort membership; one is the already-excluded SA103 draft alternate. They are not 51 newly missing current EOS advisories. Zero recorded errors likewise does not establish complete collection.

Fresh health's `source_failures=0` describes the latest maintenance run only; full acquisition did not run. The health probe checked 28 default parts without downloading the snapshot archive endpoints. Separately, the public Pages artifact was downloaded once and its manifest matched the live generation. The health benchmark receipt is 44/47, not an all-passing source-extraction claim.

The published switching extraction sample has 19 cases: seven exact byte-bound matches, six scoped matches on changed captures, and six unresolved case bindings. These are not a global accuracy estimate.

| Vendor | Cases | Exact matches | Scoped matches | Unresolved |
| ------ | ----: | ------------: | -------------: | ---------: |
| Cisco  |     5 |             2 |              0 |          3 |
| Aruba  |     5 |             5 |              0 |          0 |
| Arista |     9 |             0 |              6 |          3 |

The Cisco cases pin an absent normalized source revision; the Arista cases still require a reviewed scope for the new capture. Missing case categories remain explicit in the evidence. These bindings are follow-up work, separate from the passing targeted repair assertions. The broader extraction sample is 13/25, and independent human review remains pending.

Final repair acceptance passed, including 16 hydrated claims and 33 corrected chronology records. Executed browser code passed full selected-JSON structural parity, both CSV byte/hash comparisons, lazy-loading behavior and the analysis render contract. Full claim hydration was false in that browser receipt; the separate repair receipt covers the targeted claims. **No actual visual browser review was completed.** Independent human extraction review is pending.

To reproduce from a materialized public publication directory, using the repository environment with `python` available:

```sh
python -m checks.switching_analysis_acceptance --publication PUBLIC_DIR --profile campus-switching-openvuln-2026-11-14-v1 --output PROOF_DIR
python -m checks.switching_release_summary PUBLIC_DIR PROOF_DIR SUMMARY.json
node checks/switching_browser_acceptance.cjs PUBLIC_DIR PROOF_DIR /infrastructure-impact
```

Both repository reproduction helpers were executed against this public generation. Their hashes and results are recorded separately from the original operator helper; all observations agree. The profile input SHA-256 is `e8cc5e131c3c2bd835185795357044f427ec9c796f708a98eb652f9831289356`. Exact selected JSON, CSV, catalogue, index and native source hashes are in the evidence JSON.

Obtain the public directory from the `github-pages` artifact of the linked run, then extract its `artifact.tar`. Compare the archive SHA-256 with the evidence before extraction. The Actions artifact expires on 15 November 2026 at 22:26:39 UTC under existing retention; this report does not change publication retention. Exact full JSON/CSV replay needs that materialized snapshot while available. The companion evidence independently retains the 376 source-owned advisory/CVE pairs needed to recompute the headline and annual affected counts, plus the reported train rows and calibration units. It does not replace the complete source corpus.
