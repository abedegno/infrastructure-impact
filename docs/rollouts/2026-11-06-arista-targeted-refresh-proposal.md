# Two-advisory Arista refresh preview — 6 November 2026

Status: **local preview completed; hosted maintenance not authorized or performed**.
The website stays on released source `57b76f7db3486588538dc93b3752327730643cce`.

## Exact target scope and observed delta

The live preview requested only these two primary HTML targets, using the released
collector's existing source-selection policy in a backup of a separate public-only
research stage:

- [SA-0099](https://www.arista.com/en/support/advisories-notices/security-advisory/19862-security-advisory-0099)
- [SA-0103](https://www.arista.com/en/support/advisories-notices/security-advisory/19917-security-advisory-0103)

The SA-0103 resolver also checked its explicitly advertised CSAF alternate. It
retained the expected disagreement as an alternate-source issue. The outcome was
two imports and one explicit alternate issue, not an all-sources-success claim.
No credentials, local customer evidence, hosted vault or recovery assets were used.

| Item | Before in the local preview | After |
| --- | --- | --- |
| SA-0099 | Only CVE-2024-27892, with misbound version groups | CVE-2024-27890 has six literal version expressions; CVE-2024-27892 has eight. |
| SA-0103 HTML | No normalized HTML record | CVE-2024-6858, four literal version expressions. |
| Old SA-0103 CSAF | Literal CSAF identity with CVE-2023-5501 | Retained unchanged, including its earlier evidence and revision history; fresh research claims from that representation remain excluded. |

The public-only stage went from 11 to 12 latest identities. Every original
revision and evidence entry remained byte-identical, and the input database was
unchanged. These local counts are not a hosted-vault forecast. Fresh primary
capture hashes were:

| Source | SHA-256 | Retrieved UTC |
| --- | --- | --- |
| SA-0099 HTML | `3f682efd40ab9e0549c45dd8328d577700c9475e2cebb4c942041aef8cdaafde` | 2026-11-06T18:55:02.380990+00:00 |
| SA-0103 HTML | `1897a1d66d8310f1bc6bf72528c76c02b7633b8e79977f38e4a6aa3eff6eee68` | 2026-11-06T18:55:03.710698+00:00 |

Retrieval and reinterpretation times are not publisher disclosure/fix dates.

## What approval would cover

The existing hosted maintenance inputs select a vendor and attempt budget, not
exact advisory identities. `reparse_vendor=arista` with `reparse_limit=2` is **not**
an exact two-advisory refresh: it can select different retained records, and direct
replay of the contradictory CSAF correctly fails rather than fetching the HTML.
Do not use that shortcut or change recurring maintenance variables.

Before hosted application, prepare a separately reviewed one-run target control
that uses this exact pair through the existing writer, validation, source-choice,
audit and authenticated recovery boundaries. It must fail before recovery is
opened for an unknown profile, preserve source defaults/schedules/permissions,
retain every historical identity, and report attempted/selected URLs and alternate
issues. The target list must not accept arbitrary user-supplied URLs. A dry-run
or local stage is not a successful hosted repair.

The independently prepared Cisco model pilot is outside this two-advisory target
scope and would need its own explicit source-enrolment decision.

## Catalogue limitation requiring a separate decision

An exact source refresh alone does **not** remove the old CVE-2023-5501 CSAF record
from current catalogue views. The preview proves that limitation. Existing research
hooks reject its scope, but its retained normalized record still exists. Do not
declare the live catalogue fully corrected, rename it to CVE-2024-6858, delete
history, or claim that two imports repaired every downstream count.

A current-view retirement/contradiction policy requires its own source-led design
and explicit review: distinguish retained historical evidence from supported
current assessments, expose the reason, and define catalogue/count behavior
consistently across native/static/JSON/CSV views. This proposal does not implement
that policy or certify a live cleanup.
