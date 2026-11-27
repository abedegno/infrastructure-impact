# Release reliability: evidence, coverage and upgrade context

The release-reliability view describes what vendors publish and what has been
collected. It does not rank vendor quality, measure exposure or count actual
customer upgrades. Independent human review is pending. Missing evidence stays
unknown rather than zero.

## Scope and sources

The initial configured trains are IOS XE 17.12 (Catalyst 9200/9300), AOS-CX 10.13
(6200/6300) and EOS 4.33 (720XP/720DP), 2024–2026. The observation-end year is
partial. The [first-delivery catalogue](RELEASE_CATALOGUE.md) retains exact dates,
source quotations, locators, fingerprints, retrieval times and model scope. It
contains original-document and labelled research-excerpt observations; neither
means a human has approved the classifications. Full documents remain outside Git.

The [targeted coverage follow-up](research/2026-11-25-round4-coverage-pass.md) found
Cisco dates for other Catalyst scopes and an Arista train-level start date. Those
facts do not establish the requested models' binary-release dates and are not
silently added to the shipped-release denominator. No source crawler or login is
enabled by this feature. More trains can use the catalogue configuration; a new
source layout still needs explicitly verified extraction and public access.

## Reading the annual table

Every train/year metric retains observed count, production-eligible numerator,
release denominator, rate, coverage, source class, unresolved-model count and a
reason. The site shows these qualifications alongside the figures. A missing
count or rate is unavailable. A legitimate zero requires explicit complete evidence.
Unresolved action inputs block completeness even when no annual incident can be
assigned. These scope/cohort blockers may repeat across years and must not be
summed as incident counts.

- **Publisher-dated releases:** distinct literal versions with a stated software
  release date. Multiple model/source rows do not become extra releases.
  Announcement dates, document updates and notice dates never fill release dates.
- **Explicit deferred/withdrawn releases:** literal publisher actions, assigned to
  the shipped-release cohort only when its release date is known. A separate
  deferral-notice count uses notice year. Notice year is not release year.
- **Possible follow-ups within 30/90 days:** configured rebuild candidates and their nearest preceding regular release on the same maintenance line,
  using their stated software dates. The numerator is distinct follow-up versions
  published in that year, divided by releases published in that year when coverage
  supports it. This is the share published as follow-ups, not the probability a
  release will later require a correction. Regular AOS-CX maintenance builds do not qualify.
- **Corrective follow-ups:** additionally require an explicit publisher statement
  connecting the versions and stating the reason. Timing never supplies a reason.
- **Software-defect and deferral notices:** classified publisher documents counted
  by notice date; hardware and configuration remedies remain separate context.

Each `config.trains` entry selects a `respin_rule`: `letter_suffix` for Cisco,
`non_decadal_build` for Aruba, or `subrelease` for Arista. AOS-CX regular builds
are divisible by ten; 1003 and 1005 are both anchored to 1000, not each other.
An absent expected regular build (such as 1100 for 1101) is flagged explicitly;
absence is not withdrawal evidence. Missing anchor/date inputs retain null
intervals, stay outside 30/90-day counts and block complete signal coverage.
EOS pairs retain the same F/M suffix. These are candidate rules, not claims
that a vendor called a release an emergency correction. Historical reports
without the optional rule retain their original derivation semantics.

New catalogues have one record per vendor/train/literal version, with a union of
stated platforms and evidence. Optional `observations` retain every original
model/date/source statement. Dates or original-source eligibility never transfer
between models. `release_identity: vendor_train_version` opts into strict
uniqueness validation; older archived catalogues remain readable. The review
packet includes the corrected candidates and unresolved anchors, all pending.

The [27 November phase-one correction report](research/2026-11-27-reliability-corrections.md)
records the phase-one recalculation and version-gap findings as a dated preview.
The subsequent [phase-two report](research/2026-11-27-reliability-staircase-delivery.md)
documents the bounded publication join and public-date investigation.

A rate needs a complete original, dated release denominator and explicit complete
signal history; respin rates also require enough preceding history for the stated
interval. Current data does not meet these requirements. **All current rates are
unavailable.** Cross-vendor rates are suppressed when any vendor lacks a supported
denominator. Rendered primary-source observations are useful research evidence;
the existing origin-only production admission rule is distinct from incomplete
archive enumeration and model applicability.

## Staircase markers

Load the existing optional upgrade analysis to see its date/target steps and
source-linked reliability context. Display controls select rows; reliability
catalogue totals remain independent of advisory, vendor, CVE and study-window
filters. Exports identify the accepted upgrade selection separately.

A distinct `(vendor, train, step date, target)` appears once even when multiple
scenario/policy rows contain it. Those references remain visible; they are not
additional upgrades. Matches use exact source-stated affected releases or the
previous release in a follow-up pair. Versions are not expanded into guessed
ranges. Unsupported target links remain unknown.

Each new marker distinguishes an **exact catalogue entry**, a **Cisco suffix-only
variant**, or **no observed entry**. `present` is true only for the exact literal;
the suffix lead is not a replacement recommendation. Notices/actions/respins still
require the exact target version, never a suffix transfer. Catalogue presence does
not establish model applicability or a software-release date. Related follow-up
version, release-to-release days and days after the step are separate fields.

Scientific publications carry a bounded default join for the configured three
trains and 2024–2026 in `upgrade_annotations`, with a declared
`upgrade_selection.kind: configured_staircases` and
`published_staircase_version: 1`. Pre-period walk state is retained; only in-period
steps are annotated. The writer checks this against its complete source frame.
Readers authenticate the generation and context without loading the full analysis.
Explicit user study selection replaces this default context and removes the
publication discriminator. Publications without optional analysis retain an empty
default join; this is unavailable analysis, not evidence of no upgrades. Older
untagged reports remain readable with their original annotation semantics.

A source must explicitly support model applicability. Existing compact upgrade
rows do not carry exact device model names, so their markers retain unresolved
model scope and source-stated platforms. They describe target-version context,
not proven impact on every device. A known nonoverlapping model scope is excluded.

Withdrawal/deferral chronology uses the **action date**. A later notice with an
unknown action date does not prove the release was withdrawn after the upgrade.
Respin chronology uses the follow-up software date; its release-to-release day gap
is separate from the upgrade-step date. Notice date, action date and software date
are displayed separately. Configuration/hardware notices never create additional
software upgrades, withdrawals or affected-device claims.

## API, files and exports

New publications expose generation-bound `release-reliability.json` and
`release-reliability-review.json`, plus a CSV download. The report includes the
catalogue, annual metrics, source evidence, candidate pairs, validation and pending
review items. The review packet lists each classified notice and explicit action
or corrective relationship, with source receipts and original/excerpt fingerprints.
CSV uses typed rows, including source receipts, coverage judgements, releases,
notices, statements, respins, pending review items and validation. The `payload`
column preserves each structured fact, allowing its source IDs, fingerprints and
rate-support inputs to be resolved within the same export.
New-version upgrade annotation rows include the complete joined object in CSV
`payload`, including catalogue matches, so JSON and CSV retain the same evidence.

Older publications without the optional root show unavailable evidence. A
publication predating the research capture cannot include those future facts.

Native read-only endpoint:

```text
GET /api/v1/release-reliability?format=json
GET /api/v1/release-reliability?format=csv
GET /api/v1/release-reliability?include_upgrades=1&vendor=cisco&window=2025&format=json
```

Without `include_upgrades=1`, study selection controls are rejected and the
published default join is returned when available. With it, the existing
source-owned analysis selection replaces the annotation context. Catalogue metrics
remain unchanged. This does not alter existing study/upgrade exports. The static
browser uses the equivalent accepted publication root and selected analysis.
Damaged or mixed-generation reports are rejected.

See [OpenAPI](../infrastructure_impact/resources/openapi.json) for exact endpoint
and root contracts. GitHub Pages serves immutable files and browser composition;
it does not host an external REST service.

## Validation and human review

Release checks are a separate section in switching validation. They cover schema,
provenance, monotonic maintenance-line dates, same-base pairs, date separation,
source-stated scope and public artifact boundaries. They do not modify advisory
extraction pass rates. Automated checks establish structure and consistency, not
complete source coverage or human approval.

For every pending review item, verify the publisher URL and quoted locator,
original or excerpt fingerprint, exact version/model statements, classification,
conditions, and separate dates. Record unresolved questions instead of approving
an inferred action. Review all observations independently before calling them
human-reviewed. This feature provides no automatic approval operation.

No collection schedules, hosted permissions or secrets change with this report.
Live publication requires a reviewed candidate and a concrete activation step.
