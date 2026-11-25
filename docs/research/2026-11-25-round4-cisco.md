# Cisco round 4: release catalogue and notice coverage

Research date: 25 November 2026. **Independent human review pending.**
Scope: IOS XE 17.12 on Catalyst 9200/9300, requested years 2024–2026.
The 17.9.6 control is outside the cohort. Research only; no collector activation.

The [machine-readable packet](2026-11-25-round4-cisco.json) records 23 evidence
observations with source URL, locator, short quotations, retrieval time, original
and distinct excerpt fingerprints. Original captures remain outside Git at
`$RELEASE_RELIABILITY_CACHE/cisco`.

## Release catalogue

Both the [C9200 boot-loader table](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/rommon_versions.html)
and [C9300 ROMMON table](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/rommon_versions.html)
enumerate 17.12.1, 17.12.2, 17.12.3, 17.12.4, 17.12.5, 17.12.6,
17.12.7a and 17.12.8: **eight distinct versions, sixteen family/version rows**.
The current What's New tables agree. This systematically captures those current
tables, not every historical download. No actual release date was established
for these rows; yearly counts and membership in the date cohort remain unknown.
Document updates are not release dates. The absence of 17.12.7 does not establish
that it shipped, was withdrawn, or was replaced by 17.12.7a.

## Notice review

The [current C9300 index](https://www.cisco.com/c/en/us/support/switches/catalyst-9300-series-switches/series.html)
contains eleven distinct field-notice IDs. All five with displayed index dates
in 2024–2026 were reviewed individually. Display dates were discovery aids,
never substituted for dates or scope in the notice itself.

| Notice                                                                               | Detail-page evidence                                                                                                                                    | Treatment                                                                |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| [FN74221](https://www.cisco.com/c/en/us/support/docs/field-notices/742/fn74221.html) | First published 17 January 2025; explicitly lists 17.12.1–17.12.4; Umbrella API-key registration condition, token exclusion and certificate replacement | Conditional configuration remediation; no withdrawal                     |
| [FN74135](https://www.cisco.com/c/en/us/support/docs/field-notices/741/fn74135.html) | Initial revision 14 May 2024; conditional SUDI cases, fixed versions 17.12.2+ for C9200 and 17.12.1+ for the C9300 display-defect subcase               | Certificate context; no release or withdrawal dates                      |
| [FN72416](https://www.cisco.com/c/en/us/support/docs/field-notices/724/fn72416.html) | Header first publication 24 May 2024 conflicts with revision-table initial release 22 May 2024; last published 27 January 2025                          | Hardware manufacturing issue; retain date conflict                       |
| [FN72510](https://www.cisco.com/c/en/us/support/docs/field-notices/725/fn72510.html) | First published 7 March 2023; revised 20 January 2026; generic 17.12.1 row, but Switching applicability begins at 17.15.1                               | Exclude from 17.12 switching incident counts                             |
| [FN74383](https://www.cisco.com/c/en/us/support/docs/field-notices/743/fn74383.html) | First published 14 April 2026; revised 20 November 2026; affected AP/deployment list                                                                    | Exclude from study-switch incidents; index inclusion cannot confer scope |

The six older indexed leads—FN72524, FN72323, FN70359, FN72578, FN70489 and
FN72511—were inventoried but not reviewed in detail. Their older index dates
do not prove they have no later relevance. The old C9200 troubleshooting-index
route returned a web-tool internal error. Historical notice completeness remains
unestablished; no vendor incident rate follows from the five reviewed notices.

## Withdrawal control and access

Official-domain searches did not establish an explicit withdrawal statement for
17.12 or 17.9.6. This is **unknown**, not a confirmed zero. The
[C9300 17.9.6a section](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/release_notes/ol-17-9-9300/whats_new_in_cisco_ios_cupertino_179x.html)
explicitly associates CSCwm57734 with that fix release, without establishing the
first affected version, withdrawal action, replacement relationship or dates.

Ten bounded anonymous origin requests succeeded: robots, terms, both release
tables, five notices and the control chapter. Source content was checked beyond
HTTP status. Detail requests had two-second spacing, finite timeouts and a
stop-on-block rule. No authentication, challenge bypass or private data was used.
The initial sandbox DNS failure was environmental, not a Cisco refusal.
One later web date/control search exceeded the bounded investigation and was
terminated without usable results; it supports no claim.

[Robots rules](https://www.cisco.com/robots.txt) allowed the selected paths.
[Cisco terms](https://www.cisco.com/c/en/us/about/legal/terms-conditions.html)
limit content use and address disruptive automation. Public access and robots
allowance are not a redistribution licence or authorization for a production
crawler. Originals stay outside Git; only limited facts and short excerpts are
retained here. Original hashes improve research provenance but do not constitute
human review, evidence promotion or production eligibility.

Counts measure collected publisher disclosures, not comparative vendor quality.
