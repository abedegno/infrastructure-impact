# Switching analysis: retained public-source run, 14 November 2026

This run uses retained public captures, not a complete vendor archive or customer
inventory. Source captures retain their original 13 November or earlier timestamps.
The actual computation began at `2026-11-14T01:32:18.848968+00:00`; publication
`2f9e911bb5a34f4fb9ecaf78216984cc` was built at backend commit `03720a3`, with selected projection/browser code `3646827`, from
extraction commit `52f344f68df964c92c2426640e019819fa7029f0`. Independent human review
is pending. Counts describe disclosed evidence, not security quality, concealed
vulnerability counts, deployed exposure or observed customer upgrades.

## Retained source coverage

The verified staging database contains 313 latest representations: 312 current
and one retained SA137 draft. Current records comprise 189 Cisco, 23 Aruba and
100 Arista advisories, including 22 current drafts (23 among latest representations). Drafts and source errors are
not publication zeros. Verification covered 367 manifest entries and 353 unique
URL/hash pairs. The staging database SHA-256 is
`2abcd107dabd10b1ce5709cbde9e48c2c202c4796042a4ac2ff66347abb212e6`.

The complete native evidence contains 98,100 claims. The optional analysis keeps
all 36,482 claims within the frozen exact study families, including unknown
statuses, unresolved scope and missing dates. Its omitted 61,618 unclassified or
other-family facets cannot enter a supported study selection; they remain in the
native evidence. Their sorted identity digest is
`06b480ac04b54ee7449147c89a17667e48cf513467fdd68c692b0ceccb08cc08`.
This omission does not establish zero exposure outside the study.

SA201's research guard, SA202/203 normalization failures and SA103's unavailable
alternate remain explicit. Reviewed SA137 HTML supplies current evidence while
its draft CSAF remains retained. No acknowledged Cisco API results were supplied.
Generic Catalyst 9400/9600 chassis wording remains unresolved model evidence;
model-qualified scope is not a specific-device upgrade recommendation.

## First-fixed methods and calibration

| Vendor | Current records | Records with stated table | Stated units | Records with fix statements or fixed assessments |
| ------ | --------------: | ------------------------: | -----------: | -----------------------------------------------: |
| Cisco  |             189 |                         1 |            6 |                                              189 |
| Aruba  |              23 |                         0 |            0 |                                               20 |
| Arista |             100 |                         0 |            0 |                                               86 |

This last column includes generic vendor-fix statements without any version. The
original `03720a3` first-fixed summary called it `known_fixed_target_records`; that
label was inaccurate and its numbers must not be treated as target coverage.
The corrected metric is `fix_statement_or_fixed_assessment_records`.
Known fixed targets do not establish publisher-first-fixed status or historical
availability. Cisco's hardening table states five train rows with six versions:
17.9.10, 17.12.8, 17.15.6, 17.18.4/17.18.4a and 26.1.2; 17.8 and earlier require
migration. The current observed catalogue issued 896 inferred candidates and
abstained on 1,403. The held-out calibration had five eligible cases: four issued,
two correct, two mismatches and one abstention; a separate migration case was
recorded. Both any-alternative and exact-set rates were 2/4. These are small,
purposive source checks, not vendor-wide accuracy estimates. The source report
also records incomplete observed-catalogue and absent raw-manifest diagnostics.
That module did not receive a raw-source manifest frame; the separate staging
receipt still verifies the retained cached bodies.

## Owned target coverage

These counts use selected owned requirements with a non-null target and their
source proofs. They are not counts of records containing generic fix wording.
Scenarios are cumulative alternatives, not additive groups. A target may still
have unresolved eligibility or ordering issues, so target coverage alone does
not establish a complete walk.

| Vendor | Scenario              | Target requirements / all requirements | Distinct claims | Advisories | CVEs |
| ------ | --------------------- | -------------------------------------: | --------------: | ---------: | ---: |
| cisco  | publisher_first_fixed |                            665 / 34928 |             665 |          1 |    7 |
| cisco  | known_fixed_target    |                            666 / 34928 |             666 |          2 |    8 |
| cisco  | inferred_inclusive    |                           1445 / 34928 |            1445 |         59 |   68 |
| aruba  | publisher_first_fixed |                                0 / 481 |               0 |          0 |    0 |
| aruba  | known_fixed_target    |                              289 / 481 |             289 |          6 |   64 |
| aruba  | inferred_inclusive    |                              289 / 481 |             289 |          6 |   64 |
| arista | publisher_first_fixed |                                0 / 109 |               0 |          0 |    0 |
| arista | known_fixed_target    |                               18 / 109 |               6 |          4 |    6 |
| arista | inferred_inclusive    |                               18 / 109 |               6 |          4 |    6 |

Cisco's source proofs comprise 665 stated-table requirements, one additional
owned affected-scope target, and 779 additional inferred targets. Aruba has 289
owned affected-scope target requirements; Arista has 18 over six distinct claims.
No peer publisher-first-fixed targets were established. Per scenario Cisco retains
16,269 unsupported affected-release variants and 3,384 migration issue occurrences;
Aruba retains 91 unresolved affected-train scopes. Arista's publisher-first-fixed
scenario retains three unresolved fixed expressions. Issue categories overlap;
missing targets remain unknown, not no-fix assertions.

## Nine-train immediate-remediation scenarios

All 324 requested annual event totals (nine trains × six years × three scenarios
× two policies) are `null`. The following cells show only supported partial-walk
steps for **2021, 2022, 2023, 2024, 2025, 2026**, in that order. They are neither
reliable lower/upper bounds nor complete upgrade estimates. The final year ends
on 14 November. All/high-risk policies remain separate even where counts agree.

| Train       | Publisher all    | Publisher high-risk | Known target all | Known target high-risk | Inferred-inclusive all | Inferred-inclusive high-risk |
| ----------- | ---------------- | ------------------- | ---------------- | ---------------------- | ---------------------- | ---------------------------- |
| cisco 17.9  | 0, 0, 0, 0, 0, 1 | 0, 0, 0, 0, 0, 1    | 0, 0, 0, 0, 0, 1 | 0, 0, 0, 0, 0, 1       | 0, 0, 2, 2, 2, 1       | 0, 0, 2, 1, 1, 1             |
| cisco 17.12 | 0, 0, 0, 0, 0, 1 | 0, 0, 0, 0, 0, 1    | 0, 0, 0, 0, 0, 1 | 0, 0, 0, 0, 0, 1       | 0, 0, 0, 2, 2, 1       | 0, 0, 0, 1, 2, 1             |
| cisco 17.15 | 0, 0, 0, 0, 0, 1 | 0, 0, 0, 0, 0, 1    | 0, 0, 0, 1, 0, 1 | 0, 0, 0, 0, 0, 1       | 0, 0, 0, 1, 2, 1       | 0, 0, 0, 0, 1, 1             |
| aruba 10.13 | 0, 0, 0, 0, 0, 0 | 0, 0, 0, 0, 0, 0    | 0, 0, 0, 1, 1, 2 | 0, 0, 0, 1, 1, 2       | 0, 0, 0, 1, 1, 2       | 0, 0, 0, 1, 1, 2             |
| aruba 10.14 | 0, 0, 0, 0, 0, 0 | 0, 0, 0, 0, 0, 0    | 0, 0, 0, 1, 1, 0 | 0, 0, 0, 1, 1, 0       | 0, 0, 0, 1, 1, 0       | 0, 0, 0, 1, 1, 0             |
| aruba 10.16 | 0, 0, 0, 0, 0, 0 | 0, 0, 0, 0, 0, 0    | 0, 0, 0, 0, 1, 2 | 0, 0, 0, 0, 1, 2       | 0, 0, 0, 0, 1, 2       | 0, 0, 0, 0, 1, 2             |
| arista 4.32 | 0, 0, 0, 0, 0, 0 | 0, 0, 0, 0, 0, 0    | 0, 0, 0, 1, 1, 0 | 0, 0, 0, 0, 0, 0       | 0, 0, 0, 1, 1, 0       | 0, 0, 0, 0, 0, 0             |
| arista 4.33 | 0, 0, 0, 0, 0, 0 | 0, 0, 0, 0, 0, 0    | 0, 0, 0, 1, 1, 0 | 0, 0, 0, 0, 0, 0       | 0, 0, 0, 1, 1, 0       | 0, 0, 0, 0, 0, 0             |
| arista 4.34 | 0, 0, 0, 0, 0, 0 | 0, 0, 0, 0, 0, 0    | 0, 0, 0, 1, 1, 0 | 0, 0, 0, 0, 0, 0       | 0, 0, 0, 1, 1, 0       | 0, 0, 0, 0, 0, 0             |

The policy assumes immediate remediation and an unknown starting version below
the first target. State carries across years and selected windows; same-day
comparable targets count once. Batching or jumping releases can reduce actual
operations, so this greedy walk is not a universal minimum. Unknown risk/targets
remain in the walk; retrospective KEV and a latest-known target do not establish
historical availability or exposure. In 2026 Aruba 10.14 has no selected claims
but retains prior uncertainty; its zero supported steps is not a zero total.

## Cisco disclosure periods and model scope

| Cisco initial-publication period | Advisories | CVEs | Umbrella CVEs | Disclosure method pairs       |
| -------------------------------- | ---------: | ---: | ------------: | ----------------------------- |
| Before July 2026                 |        164 |  187 |             0 | 186 pre-risk-based; 1 unknown |
| From July 2026                   |          6 |   12 |             7 | 7 risk-based; 5 unknown       |

These calendar periods are distinct from the study's April comparison windows.
Before July, preferred vendor CVSS 3.0 supplies High 1 / Medium 3, CVSS 3.1 supplies
Critical 5 / High 94 / Medium 83, and one CVE has unknown severity. From July,
preferred vendor CVSS 3.1 supplies Critical 2 / High 8 / Medium 2. These facets keep
version, provider and advisory origin; umbrella severity is not a disclosed bug
count. The seven umbrella CVEs carry highest-score wording; the underlying bug
count remains undisclosed. These observations do not establish AI discovery,
concealment intent or a change in security quality; scrutiny can increase counts.

The finalized selected cohort has 36,478 claims, 290 with resolved model bindings
and 36,188 unresolved. Counts below overlap across models. They are current
selected coverage, not an asserted website increase from the earlier raw-template
baseline. Every nonzero model row here consists of affected claims; zero means no
owned selected evidence and does not establish unaffectedness.

| Model  | Claims | Advisories | CVEs |
| ------ | -----: | ---------: | ---: |
| 9200   |    110 |          2 |    2 |
| 9300   |    182 |          3 |    4 |
| 9300L  |     89 |          1 |    2 |
| C9407R |      0 |          0 |    0 |
| C9410R |      0 |          0 |    0 |
| 9500   |     91 |          1 |    1 |
| C9606R |      0 |          0 |    0 |
| 6300M  |      0 |          0 |    0 |
| 6410   |      0 |          0 |    0 |
| 7050X3 |      0 |          0 |    0 |
| 720XP  |      0 |          0 |    0 |
| 750    |      0 |          0 |    0 |

## Publisher chronology and KEV

The chronology repair verified 68 captures and corrected 33 paired Arista
advisories. HTML initial dates are 9 September for SA165–182, 22 September for
SA183, and 6 October for SA185–198. Informational HTML-only SA184 records
29 September. CSAF generation/current timestamps remain separate evidence;
observed RSS publication is 2 October only for SA188–198. Conflicts remain visible:
the repair does not substitute the earliest observed timestamp for the publisher's
initial release. Actual pinned cases SA165, SA183 and SA188 pass.

The retained CISA catalogue is version 2026.11.13 with 1,781 entries. Offline
catalogue ingestion did not create collection-health receipts, so current
availability is `missing` and current membership is `unknown`; historical listed
entries remain available. The compiled analysis has only 23 detailed catalogue
entries: five exact mapped candidates (four Cisco, one Arista), all documented
affected, and 18 unmapped entries. All 23 current memberships are unknown. Its
completeness is explicitly `not_established`; Aruba reports incomplete catalogue
details. This cannot establish that no additional mapped or missing-advisory
candidates exist. SA137 is historically listed and documented affected
at EOS-family scope, with no resolved affected campus-model claim. It must not
be turned into one affected campus-model KEV solely from family evidence.

A separate complete-feed reconciliation audit at `a41a8c2`, computed
`2026-11-14T02:33:02.170328+00:00`, corrects that candidate-discovery limitation.
It reuses the unchanged compiled publication's source-owned facets and the verified
312-current/1-retained record authority against the full stored catalogue. Its
wrapper references the original publication and compiled SHA; its audit timestamp
is separate from the inherited source-generation timestamp. This audit is **not**
a restamped or modified `03720a3` publication.

The audit checks all **1,781 entries** and finds **29 exact mapped candidates**:
28 Cisco and one Arista. Five are documented affected in current vendor evidence
(four Cisco plus SA137); **24 Cisco candidates have no observed vendor record** in
this retained collection. The other 1,752 catalogue entries are unmapped to the
frozen study pairs. All current memberships remain unknown because collection
health is absent. The complete capture has no matching Aruba AOS-CX catalogue pair;
that observation is not a claim that Aruba has no exploited vulnerabilities.
Vendor collection completeness remains `not_established`.

| Missing-record candidate year | Captured mapped CVEs absent from current/retained collection                                                                                                                                         |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2016                          | CVE-2016-6415                                                                                                                                                                                        |
| 2017                          | CVE-2017-12237, CVE-2017-12240, CVE-2017-12319, CVE-2017-3881, CVE-2017-6627, CVE-2017-6663, CVE-2017-6736, CVE-2017-6737, CVE-2017-6738, CVE-2017-6739, CVE-2017-6740, CVE-2017-6742, CVE-2017-6743 |
| 2018                          | CVE-2018-0151, CVE-2018-0156, CVE-2018-0158, CVE-2018-0159, CVE-2018-0167, CVE-2018-0171, CVE-2018-0172, CVE-2018-0173, CVE-2018-0174, CVE-2018-0175                                                 |

These are mapped OS-family collection leads, not proven Catalyst exposures or
hidden fixes. These older candidates predate the study window; source absence does not establish
unaffectedness, vendor non-disclosure or a collection error. Their discovery is
independent of current-CVE enrichment. Future opt-in builds pass the complete
retained details into reconciliation before ordinary public enrichment filtering;
default KEV payloads stay scoped. Null/default and explicit-CVE filters remain
distinct: explicit exclusions are labelled, not silently discarded.
The audit preserves catalogue SHA-256
`2b19960330815db7c8f43b31cfd433f1d44c3a1d17173345dcaed56a6fca3298`, version
2026.11.13 and capture time `2026-11-13T19:53:21.935450+00:00`. Its report and
selection receipts are under `round-two/final-run/complete-kev-a41a8c2/`.
The audit report SHA-256 is
`946680f36b005c4936f003ffb3f5c932c515f5912828eba3a6c546172087a8f2`.
Default, model-qualified, explicit-empty and SA137-only selections have exact
native/browser JSON parity. In model-qualified scope all five documented affected
candidates become `affected_scope_unresolved`, including SA137; no affected campus
model is inferred. The native selector at `505c61c` indexes each owned facet once,
preserving order; the four cases took 4.24 seconds natively and 14.99 seconds in
JavaScript. Original publication JSON/CSV parity remains separately preserved.

Supplementary validation at `79f25d7`, evaluated
`2026-11-14T02:04:30.978887+00:00`, passed two Cisco and five Arista pinned cases.
Aruba has zero pinned supplementary cases, not a zero-error success denominator.
The original failed current-membership assertion is retained separately; the
corrected check explicitly separates historical listing from current health.
These checks supplement claim extraction validation and do not complete human
review.

## Delivery measurements and parity

The validated compiled logical root is 122,303,798 bytes: requirements 82,750,600,
claim facets 34,151,952, disclosure 3,629,083, KEV 934,798 and release history
836,891 bytes. It owns 35,418 affected members, 106,572 requirements and 37,868
shared facts. The supported export adds one newline and has SHA-256
`13b95d9b7f92e4c9007f5795d61cd130eab82c11639e9aa63f2226d4b08d8950`.
The snapshot took 1,335 seconds with approximately 6.735 GB peak process RSS.
Process RSS is distinct from the unchanged logical codec budgets.

The first full-cohort selected export exceeded its unchanged 128 MB output gate.
Its failed receipt remains preserved. Lossless indexed row-evidence pooling at
`3646827` produces these accepted results without rebuilding the compiled root:

| Artifact                                        | Logical/output bytes | SHA-256                                                            |
| ----------------------------------------------- | -------------------: | ------------------------------------------------------------------ |
| Selected analysis JSON, including final newline |          120,680,818 | `f1fbe4830277c3e097543e54db9ce82c82a15be8136d51b4a77d1c7eab8f7a6f` |
| Analysis CSV                                    |           55,124,877 | `85008ab15889fbb31c64bebdc6efb51a102bbf46dd667c1d40d84a34560511e4` |
| Upgrade CSV                                     |           48,558,622 | `bcbc89d56fd8d1f869e2309fa892dac156a01e43bd0ec509e7be963601af20cd` |

Selected upgrade JSON is 97,520,682 logical bytes. Full-source Python/JavaScript
parity compares every JSON value, source, method and ownership reference; both
CSVs match byte for byte. Ordinary JSON float spelling differs between runtimes
(120,680,817 versus 120,680,783 bytes before the newline), while values and
canonical fingerprints match exactly. Native artifact-only selection took
203.74 seconds; selection plus JSON/CSV export took 318.10 seconds with 1.515 GB
peak RSS. The Node browser-selector replay took 127.76 seconds; CSV serialization
took 42.47 and 42.15 seconds, with 1,697,424 KiB peak RSS. These are substantial
full-cohort costs, not a browser responsiveness guarantee. No cap was raised.

Receipts outside Git are under
`round-two/final-backend-run/corrected-03720a3/` for the accepted publication and
`round-two/final-run/selected-3646827/` for selected exports, `export-result.json`,
`browser-parity.json`, `owned-summary-facts.json` and all 324 scalar annual rows
in `nine-trains-by-year.json`. Supplementary source validation has its own
`typed-source-validation-79f25d7.json` receipt, SHA-256
`2a162cd794cae60601a4506b553f58a3578a7e0287fe1f38c9d0ffb6649db90a`.
The coverage-label correction is pinned separately at `ac0913f`; it changes no
catalogue, target, inference or compiled artifact. Failed predecessor receipts
remain diagnostic records, not accepted outputs.

See [optional delivery and local commands](2026-11-14-switching-analysis-delivery.md)
for the default-off activation and API/static semantics. No hosted publication,
schedule, default activation or resource limit was changed. An attempted local
fixture visual check could not run because the browser access host was unavailable;
automated DOM, generation-race and transport tests provide the available UI evidence.
