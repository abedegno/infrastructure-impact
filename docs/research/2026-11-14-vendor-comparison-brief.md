# Campus and branch switching: disclosure and patch evidence

## What the customer can conclude

In this retained OS-family sample, Cisco has more distinct affected CVEs over the
whole observation window: **199**, compared with **104** for Aruba and **70** for
Arista. In partial 2026, the ordering reverses: Cisco **24**, Aruba **43**, Arista
**36**. Neither comparison establishes a complete vendor inventory or a security
quality ranking. The observed histories and model coverage differ substantially.

The evidence does **not yet establish that Cisco requires more customer upgrades**.
Every Cisco annual upgrade total remains unknown. Known-fixed release evidence
exists for all three vendors, but a listed fixed version is not necessarily the
first fixed version, a release date, or an upgrade an installed device needed.

This is an **interim report for a pinned publication**, not a statement that all
critical collection gaps are closed. Independent human extraction review remains
pending. Later website generations can contain different evidence. Extraction repairs
prepared after this publication are not silently included in these frozen counts. The tables
below describe only the identified publication.

## Why CVE volume is a poor security metric

A CVE count measures published identifiers under a particular disclosure and
collection process. It does not measure undiscovered bugs, deployed vulnerable
configurations, exploitation likelihood, time exposed, or the number of operator
changes. Product scope, research scrutiny, disclosure policy, grouping and bundles
can change the count without an equivalent change in customer risk or workload.

The observed 2021 sample alone contains 55 Cisco CVEs, zero Aruba CVEs and one
Arista CVE. With collection completeness unestablished, that difference cannot be
assumed to describe the complete vulnerability history. A zero is an observation
about this sample, not evidence that the vendor had no vulnerabilities.

More research and disclosure could increase published CVEs while fixes reduce
remaining exposure. That is a possible mechanism, not a causal finding about any
vendor here. Attribution to a specific research programme requires explicit
source evidence; a date change or a CVE count is insufficient.

A potential silent fix likewise requires corroboration: an exact product and
component/version relationship plus release, patch or other authorized evidence
showing a security-relevant change. A missing advisory, parser gap or unclear fix
link alone does not prove concealment.

## Documented disclosure context

Cisco [announced its participation in Glasswing on 7 April 2026](https://blogs.cisco.com/news/rising-to-the-era-of-ai-powered-cyber-defense);
[Anthropic also names Cisco](https://www.anthropic.com/glasswing). Participation
is verified. The selected evidence does not identify which individual CVEs were
found through Glasswing or measure its contribution to the vendor-count difference.

Cisco's [June announcement](https://blogs.cisco.com/security/strengthening-the-foundation-a-predictable-customer-focused-response-to-ai-accelerated-vulnerability-discovery)
describes scheduled hardening and batching as a way to reduce separate maintenance
events while addressing newly discovered latent defects. This is Cisco's stated
rationale, not an independently measured reduction in this cohort's workload.

Cisco's [disclosure policy](https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure)
describes grouping bugs of the same weakness class into umbrella CVEs and scoring
the group using its highest-severity member. One CVE therefore need not mean one
underlying bug, and one advisory need not mean one operator upgrade. Underlying
bug counts not disclosed by the source remain unknown. Research-programme launch
and disclosure-policy change are distinct events; neither is a demonstrated causal
explanation for the observed counts.

These official sources were checked on 14 November 2026. They establish announced
practices and participation, not relative vendor security quality or concealment.

## Evidence and reproduction

The [machine-readable evidence](2026-11-14-vendor-comparison-evidence.json)
records the publication, source commit, profile, public descriptor hashes and
counting semantics. The producing [workflow run](https://github.com/abedegno/infrastructure-impact/actions/runs/43622373473)
completed native parity and recovery verification. The public artifact was then
checked against the native public reader and actual browser-code JSON/CSV exports.
This was code-based verification; visual browser review was unavailable.

Use the pinned source and its public artifact to reproduce the selected reference
with `python -m checks.switching_analysis_acceptance --publication PUBLIC_DIR
--profile campus-switching-openvuln-2026-11-14-v1 --output NEW_PROOF_DIR`. Compare
the resulting analysis and CSV hashes with the accompanying evidence. No private
recovery database or credentials are needed to inspect the public artifact.
See [the study method](../switching-comparison.md) for scope and limitations.

## Pinned observations

Publication `a3a7a1fcdc194599b2903d39484ba340`, generated `2026-11-14T17:42:54.283949+00:00`. Shared observation window: 2021-01-01 through 2026-11-14 (2026 is partial). Source commit `4e982748b2b45c9e2ffbeb522103645af4c39fa2`. Selected public analysis SHA-256 `530073c4348a9ee17a462dcf4e97d4d7bb09faa9693b4cd58788e92500efa95a` verified locally; overview read through PublicationReader with descriptor byte/hash verification. Full provenance and exact field semantics are in the [machine-readable evidence](2026-11-14-vendor-comparison-evidence.json).

Counts describe observed disclosure and scrutiny, not security quality, underlying bug counts, prevalence, or a causal ranking. Coverage denominators, role equivalence, lifecycle and release-train completeness remain unresolved.

| Vendor | OS-family affected advisories / CVEs | All observed advisories / CVEs | Explicit named-model union advisories / CVEs | KEV listed / affected denominator |
| ------ | -----------------------------------: | -----------------------------: | -------------------------------------------: | --------------------------------: |
| cisco  |                            170 / 199 |                      170 / 199 |                                        4 / 5 |                           4 / 199 |
| aruba  |                             16 / 104 |                       21 / 119 |                                        0 / 0 |                           0 / 104 |
| arista |                              55 / 70 |                       60 / 105 |                                        0 / 0 |                            0 / 70 |

The zero Arista KEV count is particularly incomplete: the pinned reconciliation
contains [CISA-listed CVE-2026-7473](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
for Arista EOS, but the retained advisory is draft-only and therefore outside
this affected cohort. It is an explicit unresolved source-selection case, not
evidence that Arista has no known-exploited vulnerabilities.

OS-family evidence includes any model-qualified claims. Aruba and Arista have zero explicit evidence for the selected named models; this does not establish unaffectedness. Cisco explicit model rows: 9200 2/2, 9300 3/4, 9300L 1/2, 9500 1/1 advisory/CVE counts; C9407R, C9410R and C9606R zero. These model rows overlap and must not be summed.

| Initial publication year | Cisco affected advisories / CVEs | Aruba affected advisories / CVEs | Arista affected advisories / CVEs |
| ------------------------ | -------------------------------: | -------------------------------: | --------------------------------: |
| 2021                     |                          50 / 55 |                            0 / 0 |                             1 / 1 |
| 2022                     |                          24 / 24 |                           4 / 34 |                             6 / 7 |
| 2023                     |                          19 / 20 |                            3 / 6 |                             3 / 4 |
| 2024                     |                          26 / 27 |                            3 / 4 |                             5 / 7 |
| 2025                     |                          33 / 49 |                           3 / 17 |                           13 / 15 |
| 2026                     |                          18 / 24 |                           3 / 43 |                           27 / 36 |

Year uses the initial publisher date, never the CVE identifier year. CVEs shared across advisories and years make year totals nonadditive.

| Scenario (separate alternatives) | Cisco usable advisories / CVEs | Aruba usable advisories / CVEs | Arista usable advisories / CVEs |
| -------------------------------- | -----------------------------: | -----------------------------: | ------------------------------: |
| publisher_first_fixed            |                        76 / 91 |                          0 / 0 |                           0 / 0 |
| known_fixed_target               |                        77 / 92 |                         6 / 63 |                           6 / 8 |
| inferred_inclusive               |                      116 / 134 |                         6 / 63 |                           6 / 8 |

Usable means target present and no requirement issues. Aruba has known targets for 64 CVEs in six advisories; train-scope issues leave 63 CVEs with usable requirements. Aruba and Arista therefore already have usable known-fixed targets for six advisories each. Their zero publisher-first-fixed count does not mean no usable fix evidence. The inferred-inclusive scenario contains known-fixed targets too; do not add scenarios together.

Upgrade rows are conditional immediate-remediation walks under an assumed below-first-target baseline. They are not observed customer changes or universal minima. Null event_count must remain unknown; supported steps in partial walks are not reliable bounds. Latest known fixed targets do not prove availability on initial disclosure day.

Severity remains source-specific in the JSON: version, provider, origin, preferred flag and band are retained separately, and facets must not be summed. Vendor SIR is separate from CVSS. Retrospective KEV membership uses catalogue 2026.11.13 (1,781 entries); Cisco lists CVE-2023-20109, CVE-2023-20198, CVE-2023-20273 and CVE-2025-20352. Aruba/Arista zero is within their observed affected cohorts, not proof of no exploitation.

Release-history root contains 100 release identities, 2 explicit bundle records and 57 platform-support rows. Expected releases/advisories are null and completeness is not_established. Release-history dates, remediation availability dates, vendor-fixed CVEs and affected-scope links have distinct meanings.

The public generation can answer what the retained evidence says was disclosed, how selected affected scope maps to explicit models, and which distinct fix scenarios have support. It cannot currently answer which vendor is inherently safer, provide a complete vendor release comparison, infer fix delay, attribute individual CVEs to AI or a disclosure programme, or establish a deployed-customer upgrade burden. Human extraction review is pending.

Source-specific CVSS facets (distinct CVEs per facet; rows can overlap):

| Vendor / provider            | CVSS        | Band     | CVEs |
| ---------------------------- | ----------- | -------- | ---: |
| cisco / Cisco                | 3.1         | Critical |    7 |
| cisco / Cisco                | 3.0         | High     |    1 |
| cisco / Cisco                | 3.1         | High     |  102 |
| cisco / Cisco                | 3.0         | Medium   |    3 |
| cisco / Cisco                | 3.1         | Medium   |   85 |
| cisco / unavailable          | unavailable | Unknown  |    1 |
| aruba / HPE Networking       | 3.1         | Critical |    2 |
| aruba / HPE Aruba Networking | 3.1         | Critical |    4 |
| aruba / HPE Aruba Networking | 3.1         | High     |   22 |
| aruba / HPE Networking       | 3.1         | High     |   25 |
| aruba / HPE Aruba Networking | 3.1         | Low      |    2 |
| aruba / HPE Networking       | 3.1         | Medium   |   12 |
| aruba / HPE Aruba Networking | 3.1         | Medium   |   26 |
| aruba / unavailable          | unavailable | Unknown  |   14 |
| arista / Arista PSIRT        | 3.1         | Critical |    3 |
| arista / Arista PSIRT        | 3.1         | High     |   15 |
| arista / Arista PSIRT        | 3.1         | Low      |    5 |
| arista / Arista PSIRT        | 3.1         | Medium   |   34 |
| arista / unavailable         | unavailable | Unknown  |   13 |

| Vendor | Release identities | With publisher release dates | Platform-support rows |
| ------ | -----------------: | ---------------------------: | --------------------: |
| cisco  |                  2 |                            1 |                     0 |
| aruba  |                 70 |                           10 |                    57 |
| arista |                 28 |                            0 |                     0 |

The two Cisco release-history identities exclude the separately owned API
first-fixed observations. Grouping that evidence by every literal fixed-release
alternative yields **38 distinct versions**, **241 distinct version/CVE pairs**,
and **84 unique CVEs across 75 advisories**. The machine-readable evidence lists
these versions separately, without adding duplicate scenarios. This is OS-family
fix context, includes IOS XE products beyond named switching models, and supplies
no missing release dates or customer upgrade counts. It is not a complete release
catalogue and must not be compared with the history table as though both measure
the same thing.

Across all 3,240 train/year/scenario/policy rows, only 24 have non-null event_count: 0 Cisco, 6 Aruba, 18 Arista. These include alternative scenarios and policies and must not be added as customer upgrades. Every Cisco total is unresolved despite extensive fix evidence.
