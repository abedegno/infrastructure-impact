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

## Current implementation acceptance — 6 November 2026

The sections above preserve the earlier preview and its then-current limitation.
The integrated candidate now implements the reviewed exact-profile control and
current-evidence policy, with local acceptance described in
[the acceptance packet](../research/2026-11-06-targeted-refresh-acceptance.md).
All seven task reviews and the final whole-branch/scoped review are complete;
PR #33 merged on 7 November. Independent human source/extraction review remains
incomplete. The [v0.12.0 activation proposal](2026-11-07-current-evidence-0120-activation-proposal.md)
records the separately gated next steps.
No hosted preview/application, source-pin activation, release or dispatch occurred.

The only acceptance input was a checkpointed copy of the earlier explicitly
public-only preview stage, SHA-256
`609109890fc7e962eaf67a45644be92b61847eec45d4de622bd00cf764058e62`,
6,586,368 bytes, with a zero-byte WAL. It already contained the corrected HTML
primaries and selection facts. Under the new policy **before apply**, its 12 latest
identities partitioned into 11 current and one excluded retained identity. Those
counts remained 11/1/12 after apply. Thus apply did not create that exclusion.
All 17 old evidence rows and 13 old revision rows kept their complete row hashes;
actual public HTTP added two evidence rows and two normalization revisions.
Repeating those captured bytes under the same code imported zero revisions.

The exact bounded profile retrieved only the two registered HTML URLs above and
[the registered SA-0103 CSAF](https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_103.json).
All three returned HTTP 200. The new HTML captures were:

| Source | SHA-256 | Source capture UTC | Normalization UTC |
| --- | --- | --- | --- |
| SA-0099 HTML | `2d43fe824b08b7e2240e0bcb51224963afb8f2b6ea81b7288c3548af0892a595` | 2026-11-06T23:15:24.237031+00:00 | 2026-11-06T23:15:25.542173+00:00 |
| SA-0103 HTML | `252f7bf5802913c4e438d081ac5a30353c1dc3430a8e512ddae4f9f615863a04` | 2026-11-06T23:15:25.081373+00:00 | 2026-11-06T23:15:25.542821+00:00 |

CSAF bytes were identical to the retained hash
`3491af5ed3486c8e74fd04cd432a5072bf0938733cd059d9d24e7f3f2355ef74`
(8,073 bytes). Its original capture time stayed
2026-11-06T13:12:43.166299+00:00; the separate real HTTP recheck was recorded at
2026-11-06T23:15:25.520572+00:00. The old normalized identity/revision and literal
CVE-2023-5501 were preserved. SA-0099 retained the six CVE-2024-27890 and eight
CVE-2024-27892 literal version expressions; SA-0103 HTML retained its four
CVE-2024-6858 expressions. These observation times are not publisher event dates.
The complete core result was `completed`, with the expected alternate scope
conflict, which hosted operational reporting would label `partial`.

The local preview fingerprint was
`d6b769d9c9fb88d37be7fe2cb94f1acc4c1c38b4db48d2b677fa25ea3b8f7c35`.
It binds only this disposable public stage and installed code; it is not a hosted
fingerprint and must never be forwarded to hosted apply. Source activation, a
fresh hosted read-only preview, and one accepted-fingerprint application each
still need their own authorization. Scheduled collection can invalidate a
preview. Refusal must not trigger generic replay, broader source collection or
an automatic pin change.

The workflow recognizes the modern helper's `effects-v1` protocol and only the
checksum-bound approved old helper's ordinary protocol. Merging the workflow
preserves the existing source pin; maintenance stays disabled there. The bridge
is wire compatibility, not a rollback plan: pre-policy code can expose the
retained contradictory representation as current after activation. Any downgrade
requires its own source/recovery/public-generation review. The read-only monitor
can fail a generation but cannot restore Pages automatically.
