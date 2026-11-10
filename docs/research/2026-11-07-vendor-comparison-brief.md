# Does Cisco disclose more switching vulnerabilities?

**Current brief:** [10 November evidence and customer answer](2026-11-10-vendor-comparison-brief.md).
The observations below remain dated historical evidence; do not combine their counts with the new publication.

**Dated update:** the [9 November live investigation](2026-11-09-live-switching-readiness.md)
records the published Cisco import and corrects the interpretation of validation
outcomes. The website-membership figures below describe the older pinned publication.

**Published update:** the [9 November activation results](2026-11-09-switching-activation-results.md) add explicit Cisco bundle evidence and two Arista EOS CVEs. Full-period observed affected counts are 199 / 104 / 67; the 2026 advisory-date cohort is 24 / 43 / 34. These are not disclosure rates or comparable deployed-switch risk. Generation `278bbaf40f714727a4eddcbaab450d85` is live; the historical membership observations below remain dated.

Observation date: **7 November 2026**. Public evidence only. This brief compares
Cisco IOS XE, HPE Aruba Networking AOS-CX and Arista EOS. It does not compare the
vendors' entire portfolios or certify applicability to a customer's switches.

## Updated customer answer — 9 November 2026

In the current retained OS-family collection, Cisco IOS XE has **199 distinct
explicitly affected CVEs**, compared with **104 for Aruba AOS-CX** and **67 for
Arista EOS**, over the study period starting 2021-01-01. Cisco therefore has more
observed CVE IDs in this collection. These are broad family counts: IOS XE also
includes wireless controllers and other non-Catalyst products. Historical coverage
and exact switch-model applicability remain unequal or unknown, so the figures
do not yet establish a fair comparison of the customer's switches.

We cannot reliably say Cisco requires more patching. Retaining Cisco's explicit
bundle page reduced the live collection's counted remediation publications from
**170 to 159 without changing its 199 affected CVEs**: twelve retained member
advisories now group into one explicit bundle. Peer event totals still undercount
fixes whose affected and fixed product branches lack explicit links. Comparing
these incomplete totals would compare extraction and publication formats as well
as vendors. A publication event does not establish an actual customer upgrade or
maintenance window.

The ordering also changes with the window: the partial **2026 advisory-date cohort**
has 24 affected CVEs for Cisco, 43 for Aruba and 34 for Arista. These are not vendor
disclosure rates. Coverage remains unresolved, and CVEs added in later revisions
still inherit the advisory's original publication date.

Higher CVE volume can reflect more defects, more discovery effort, broader
features/dependencies, or different disclosure and numbering practices. This
investigation has not measured their relative contributions. Counts alone cannot
separate these explanations, establish a Glasswing effect, prove vendors equally
secure, or demonstrate intentional concealment. A missing CVE reference or a
component update is a research lead requiring exact product/build, correction and
disclosure-history evidence.

Use disclosure volume as a descriptive signal alongside **applicable serious or
exploited exposure, supported fixes, known bundle/release grouping, emergency
versus planned actions, and visible coverage gaps**. Keep unknowns explicit rather
than treating missing statements as unaffectedness or low patch burden. The
[9 November evidence investigation](2026-11-09-live-switching-readiness.md) and
[bounded source/bundle follow-up](2026-11-09-switching-coverage-followup.md) record
the data identity, reproduction and remaining limits. The
[published activation results](2026-11-09-switching-activation-results.md) record
the current generation and verified exports.

## Historical answer and pinned observations — 7 November 2026

Our current evidence does not support a reliable conclusion that Cisco requires
more security patching than Aruba or Arista. The pinned official CVE scan finds
more IOS XE candidate records over 2021–2026, but that ordering reverses in its
2026 subset. These are incomplete discovery results, not confirmed affected
switch counts. More published CVEs can reflect more defects, more scrutiny, more
transparent disclosure, or differences in product scope and reporting. We cannot
currently separate those explanations. Compare applicable exposure and necessary
maintenance work alongside disclosure completeness, rather than treating CVE
volume as a vendor security score.

## 1. Is Cisco publishing more CVEs?

**There is an indication over the longer discovery window, but no defensible
vendor-wide or like-for-like switching conclusion yet.** Three different
questions need separate denominators: CVE IDs assigned by a vendor as a numbering
authority; CVEs affecting its products, including upstream dependencies; and
advisories or remediation publications. None directly measures required upgrades.

The pinned official CVE List scan uses **registry publication dates from
1 January 2021 through 6 November 2026**, inclusive. Its family discovery results
are:

| OS family    | Explicit family candidates | Ambiguous leads | All candidates in window | Candidates published in registry during 2026, through 6 Nov |
| ------------ | -------------------------: | --------------: | -----------------------: | ----------------------------------------------------------: |
| Cisco IOS XE |                        180 |              21 |                      201 |                                                          24 |
| Aruba AOS-CX |                         46 |              24 |                       70 |                                                          42 |
| Arista EOS   |                         76 |              10 |                       86 |                                                          51 |

These are **candidate CVEs**, including literal affected, unaffected and unknown
statements. An explicit family row is not confirmation that a named switch,
release and configuration are vulnerable. Registry publication year is different
from CVE identifier year, vendor advisory date and patch availability date.
The 2026 column is a partial year. Neither the totals nor that column establishes
a rise, fall, equivalence or causal effect.

The scanner attempted all 420,073 records at the pinned commit, but **14,060
remain unresolved**: 14,058 unsupported-format records and two oversized records.
Those omissions are not known to be evenly distributed between families or years.
Generic upstream-component CVEs can also lack downstream product names. A
completed traversal therefore does not mean complete discovery. See the
[original scan methods and limits](2026-11-06-cve-reconciliation-observations.md).

The latest website publication was downloaded and verified against its manifest.
Membership of those same in-window candidates is:

| OS family    | Candidate CVEs present under vendor | Candidate CVEs with matching family evidence | Candidate CVEs missing vendor evidence |
| ------------ | ----------------------------------: | -------------------------------------------: | -------------------------------------: |
| Cisco IOS XE |                                   0 |                                            0 |                                    201 |
| Aruba AOS-CX |                                  67 |                                           67 |                                      3 |
| Arista EOS   |                                  86 |                                           84 |                                      0 |

These are membership checks including drafts and all literal statuses, **not
coverage percentages or confirmed affected counts**. The website does contain
an IOS XE assessment for upstream OpenSSH CVE-2024-6387; that CVE did not enter
the pinned IOS XE discovery set. Thus zero candidate matches does not mean zero
IOS XE evidence. It also demonstrates why registry name matching alone is
insufficient.

The two repaired Arista CVEs, CVE-2024-27890 and CVE-2024-6858, are now present.
The two remaining EOS family gaps, CVE-2021-28501 and CVE-2023-24512, are ambiguous
leads with vendor records, not proof of missing vendor disclosures. Aruba's three
missing candidates are CVE-2021-29143, CVE-2021-29148 and CVE-2021-29149.

A separate public local stage successfully retrieved **173 selected Cisco article
URLs and one Aruba bulletin**. All 180 explicit IOS XE candidates obtained family
evidence in that stage. It is not the published corpus or a complete archive;
its unequal Aruba/Arista inputs cannot be used as peer denominators. See the
[dated collection receipts and distinctions](2026-11-06-public-reconciliation-followup.md).

## 2. Why might disclosure volumes differ?

The following are competing explanations, not findings about which vendor is
better:

| Explanation                       | Evidence needed to distinguish it                                                                                                                             |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| More underlying defects           | Comparable supported features, releases, observation periods and discovery effort; public counts alone cannot establish defect prevalence.                    |
| More discovery activity           | Advisory acknowledgements or publisher attribution identifying internal research, external reports, audits or AI discovery; retain unknown attribution.       |
| Broader software or feature scope | Product and configuration boundaries for each CVE; separate shared-component vulnerabilities from vendor-authored flaws without assuming downstream exposure. |
| Different disclosure channels     | Reconcile advisory archives with official CVE records, release notes, bug notices and security documentation; track inaccessible channels explicitly.         |
| Bundling or delayed publication   | Explicit bundle identities and initial publication dates, advisory revisions and fixed-release histories; do not infer a bundle merely from a shared date.    |

Cisco announced Glasswing participation on **7 April 2026** and described using
AI to find and fix vulnerabilities. This supports increased discovery as a
hypothesis; the statement provides no Cisco-specific estimate of additional CVEs
or switching patches attributable to the programme.
[Cisco announcement](https://blogs.cisco.com/news/rising-to-the-era-of-ai-powered-cyber-defense).

It is also **not a Cisco-only explanation**. Arista's statement dated **8 May
2026** describes AI-assisted discovery and partnerships including Project
Glasswing. These are vendor statements about process, not independently measured
comparative outcomes.
[Arista statement](https://www.arista.com/assets/data/pdf/glasswing/QA-Project-Mythos-Glasswing.pdf).
A split before and after 7 April would be descriptive: it cannot isolate AI's
contribution from reporting delays, seasonality, product changes or other
research activity.

Cisco's policy places some low-severity and most third-party issues in release
note enclosures rather than standalone security advisories. Its channel table
excludes those enclosures from RSS and openVuln. It also describes scheduled
IOS/IOS XE advisory bundles in March and September, with out-of-cycle exceptions.
Consequently, advisory feeds alone can miss disclosed security work, while many
advisories can be released together.
[Cisco vulnerability policy](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html).
Arista also describes routine batch publications and urgent releases, reinforcing
the need for explicit event evidence across peers.
[Arista vulnerability management process](https://www.arista.com/en/support/product-documentation/vulnerability-management-process).

**We have no evidence here establishing intentional concealment by any vendor.**
An unreferenced component update, missing CVE link or disagreement between HTML
and CSAF is an investigation lead. Establishing an undisclosed security fix
requires an exact product/build, independently supported vulnerability
applicability, a documented corrective change and dated disclosure history.
A fix can precede an advisory for several reasons; timing alone does not establish
intent. No authorized private build artifacts were available for this study.

## 3. Why is CVE volume a poor primary metric?

- **Discovery and disclosure affect the numerator.** Finding and publishing more
  issues can increase the count while removing vulnerabilities from supported
  releases. Publishing fewer can reflect fewer flaws or less visibility.
- **Applicability varies.** A routing-only feature, optional service or excluded
  model may not affect the campus deployment being evaluated.
- **Impact varies.** Equal weighting treats a constrained low-impact flaw like an
  exposed, exploited critical flaw. Even CVSS Base measures severity, not risk;
  threat and deployment context are needed.
  [FIRST CVSS guide](https://www.first.org/cvss/v4.0/user-guide#CVSS-Base-Score-CVSS-B-Measures-Severity-not-Risk).
- **CVE counts do not count maintenance windows.** In a hypothetical example,
  twenty CVEs fixed by one compatible release can mean less work than five CVEs
  requiring five urgent upgrade decisions. Workarounds and hotfixes may differ
  from full software upgrades and have their own costs.
- **Visibility and time windows differ.** Incomplete archives, unsupported source
  formats, revisions and partial years can change the apparent ordering.

A more useful operational comparison reports **applicable exploited or serious
exposure, days without an available applicable fix, distinct necessary upgrade
or mitigation decisions, emergency versus planned work, and unresolved coverage**.
CISA KEV membership is a useful exploitation signal, not a complete risk score;
absence from the catalogue does not establish absence of exploitation.
[Official CISA KEV data mirror](https://github.com/cisagov/kev-data).
Published remediation events remain a proxy until release, model, configuration
and maintenance evidence establishes the work actually required.

## What remains before a fair comparison

1. Close remaining relevant source and representation gaps after the published
   Cisco import, Aruba bulletin and Arista repairs. Expand official-source
   reconciliation while keeping unresolved upstream-component leads visible.
2. Obtain comparable historical archive coverage, dated release notes and explicit
   bundle/remediation links for all three families. Expected historical advisory
   totals remain unknown. None of the current three vendor histories is certified
   complete.
3. Review applicability for Catalyst 9200/9300/9300L/9400/9500/9600, CX 6300M/6410
   and EOS 7050X3/720XP/750-series, with supported releases and configuration
   preconditions. Family names do not establish these model scopes. The earlier
   corrected local stage had no qualifying model observations; that was missing
   evidence, not unaffectedness.
4. Complete independent human evidence review and analyse attributed discovery
   and release histories. The published switching sample has seven exact-byte
   matches, six reviewed-section matches and three missing-source cases out of
   sixteen. These outcomes are distinct, human review remains pending, and the
   purposive sample is not a population accuracy estimate.

There is no justified vendor ranking, equality claim, hidden-exposure finding or
causal Glasswing conclusion at this stage. Higher disclosure can reflect more
scrutiny. The present result identifies what must be measured to answer the
customer's operational concern.

## Evidence appendix and reproduction

The public-only evidence packet is retained outside Git, following the repository's
[contribution rules](../../CONTRIBUTING.md). It contains `evidence.json`,
`candidates.csv`, `checksums.json`, `reproduce.py`, the pinned reconciliation
report, verified public manifest and compressed snapshot, and reproduction
instructions. JSON preserves all 577 candidate rows, including 220 outside the
window, source URLs and SHA-256 values, literal statuses, matching current
revision identities, per-registry-year counts and existing published switching
summary fields. CSV provides the same candidate membership audit in tabular form.
Neither export is a new product API or an automatic applicability decision.

Numeric inputs are pinned to:

- Official CVE List commit `6abf4b509056d9996ae205d4ca8681abaae043ab`, selector
  `2026-11-06.2`.
- Reconciliation report ID
  `9a62007bbaa7bd9b3b153243711c1732db5c9f71450386f7b3d4c5de92625393`;
  report-file SHA-256
  `5e3a1d1aa574487f05b8ae463c0783c3a746dfd60cefda6abd38e58a440b938e`.
- Public generation `5f02de1195954639a6abb4731af8db96`, generated
  `2026-11-07T08:35:49.718634+00:00`: 966 current identities and one excluded
  retained historical identity. Excluded evidence does not supply current
  presence.
- Expanded snapshot SHA-256
  `7ceba4ed6d8c74c382ea02333336c3f2acebe7f3e7b818dcf07be90635031907`;
  compressed SHA-256
  `1275d80cc3d679cb36bcbe144c1bd7d2fed1b721a862b90d8281f2f8f6ce44f3`.

Reproduction verifies pinned hashes, manifest consistency, publication identity
and the reconciliation report, then uses the existing family matcher. It
recomputes membership only against current records; draft presence and all
assessment statuses remain visible. Published switching counts use vendor
publication dates and are copied as observations under the existing reducer's
rules; they are not equated to registry-window candidate counts. No new score,
upgrade rate or fix-latency estimate is calculated. Full input and method details
are in the packet; live website replacements require a new dated observation.
