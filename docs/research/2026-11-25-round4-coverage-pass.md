# Round 4 targeted coverage follow-up

25 November 2026. Independent human review pending. Counts describe disclosure
and collection, not vendor quality; missing evidence remains unknown, never zero.
This is the approved targeted follow-up to steps 1–4. Steps 5–8, hosted collection
and site publication have not started.

## Result

The pass found **eight explicitly dated Cisco release references** in official
ISSU metadata and **one Arista train-level initial release date**. It did not
establish additional dates bound to the requested Catalyst 9200/9300 or Aruba
6200/6300 scope, nor Arista's per-release/model catalogue. Consequently the
[first-delivery catalogue](2026-11-25-release-catalogue.json) and its nine unknown
train/year denominators remain unchanged. No date or scope is silently promoted.

## Cisco: a useful public source, with narrower scope

The official ISSU page links a public XLSX with literal `Release` and `Release Date`
columns. The seven rows below were extracted from its **c9500h worksheet**, scoped
to Catalyst 9500 High Performance. The eighth comes from an explicit supplemental
release record in the page's inline script, whose selectable-platform set names
C9400/C9400X, C9500/C9500H/C9500X and C9600/C9600X.

| Version  | Publisher release-date value | Source scope                                           |
| -------- | ---------------------------- | ------------------------------------------------------ |
| 17.12.1  | 2023-07-28                   | c9500h worksheet                                       |
| 17.12.2  | 2023-11-15                   | c9500h worksheet                                       |
| 17.12.3  | 2024-03-21                   | c9500h worksheet                                       |
| 17.12.4  | 2024-07-24                   | c9500h worksheet                                       |
| 17.12.5  | 2025-03-18                   | c9500h worksheet                                       |
| 17.12.6  | 2025-09-01                   | c9500h worksheet                                       |
| 17.12.7a | 2026-03-25                   | c9500h worksheet                                       |
| 17.12.8  | 2026-08-05                   | Inline supplemental record, selectable platforms above |

The values are publisher ISO calendar-date strings, not Excel serial conversions,
page modification dates, fixed-release inference or HTTP metadata. Six fall in
2024–2026; two are outside that window. These sources do **not** name Catalyst
9200/9300 in the extracted applicability. All 16 existing target-model date rows
therefore remain unknown. The new dates can inform future work on the wider
switching study only with their exact source scope retained.

The target-model What's New chapters supplied no usable explicit release calendar.
Public software download availability did not establish the missing dates.
[Source facts, cell/code locators and fingerprints](2026-11-25-round4-coverage-cisco.json);
[investigation notes](2026-11-25-round4-coverage-cisco.md).

## Aruba: the navigation gap remains

The official 6200 index links to the 10.13 train. A literal link from the existing
TOC points to 10.13.1200, but the rendered target supplies no substantive release
history; the latest history URL was not established. The 6300 1001/1161 targets
also supplied blank substantive renderings; 1031 produced a tool cache miss.
These are recorded separately from HTTP statuses, which the tool did not supply.
None proves the pages are absent or that the releases were withdrawn.

Exact-version PDF discovery supplied no new eligible dates. Previously blocked
origin/robots routes were not retried, no login or challenge bypass was attempted,
and no dates were borrowed from other model families. The public notice-source
finding from the first delivery is unchanged. **Zero new dated observations** is
an investigation result, not a zero release or incident total.
[Access and navigation receipts](2026-11-25-round4-coverage-aruba.json);
[investigation notes](2026-11-25-round4-coverage-aruba.md).

## Arista: train start, not a binary release calendar

The public lifecycle policy links an original JPEG matrix. Its row `Arista EOS
4.33.x`, column `Initial Release Date`, states **10 October 2024**. The image footer
is dated 23 October 2026; that revision date is not the train release date.
The original image bytes are fingerprinted and cached outside Git.

The row does not identify 4.33.0F, enumerate maintenance releases or state
720XP/720DP applicability. It is retained solely as a train-level fact. The existing
two RSS announcement dates remain separate from unknown binary release dates.
The bounded official-source search did not establish a public per-release history
or explicit study-model train-support statement. This is a search outcome, not a
claim that no such source exists. Known gated routes were not retried.
[Source facts and fingerprints](2026-11-25-round4-coverage-arista.json);
[investigation notes](2026-11-25-round4-coverage-arista.md).

## Validation and decision

The prior packaging fix is green across Python 3.11, Python 3.13 and container CI.
For this follow-up, 33 unique new or reused cached public source/excerpt files
were independently rehashed. The lifecycle image was visually checked by both
implementation and review. Research code review does not mark facts as human
reviewed. Packet references use the portable external-cache directory variable;
full vendor documents are not stored in Git.

The origin-only production eligibility rule is an existing implementation policy,
not a new restriction introduced by this pass. Even if appropriately reviewed
rendered primary-source evidence were admitted, model binding and archive
enumeration gaps would still prevent a complete three-vendor denominator here.
Changing that eligibility policy is outside this follow-up.

Further repetitions of the same public-source searches are unlikely to resolve
these specific gaps efficiently. The next approved product delivery can present
observations, notices and staircase markers with coverage labels and unavailable
rates. A claim of comparable historical rates still needs additional public
vendor evidence with explicit dates, scope and complete enumeration. No rates,
automatic sources, schedules, permissions, secrets or publication changed.
