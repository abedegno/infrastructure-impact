# Release reliability views: second delivery

Implements the user's approved round 4 steps 5–8, using the first delivery and
its targeted follow-up. No new source collection or change to source permissions.
The original round 4 requirements remain the specification. Existing autonomous
execution and subagent-driven preferences apply; no repeated design approval loop.

## Approach and boundaries

Publish a small, generation-bound optional `release-reliability.json` root and a
standalone human-review root. Keep the new report independent of advisory/CVE
filters because it describes the configured release catalogue, 2024–2026. Upgrade
annotations use the currently accepted analysis selection, separately labelled.
The v2 reader materializes only this small root; do not hydrate all claims or
recompute the entire analysis matrix during publication. Legacy publications with
no root show unavailable evidence. A generation predating the packaged research
capture cannot publish future evidence; its reliability report is unavailable.

Alternatives rejected: hardcoded HTML statistics cannot be reproduced/exported;
changing affectedness or existing study counts would conflate disclosure and release
reliability. Adding source collectors would exceed the approved access boundary.

Package only the already normalized 51-observation catalogue and train config.
Coverage supplements stay separately linked research: dates for other Catalyst
models and an Arista train date must not become target-model binary dates.
All independent human review statuses remain pending.

## Metrics and rate method

Per configured train/year show publisher-dated observed releases, explicit
withdrawn/deferred releases, possible/corrective follow-ups within 30/90 days,
software-defect notices and deferral notices. Every metric carries observed count,
production-eligible numerator, denominator, rate, coverage, evidence class, model
unresolved count and reason. Unknown counts/rates are null. A documented zero is
possible only with complete evidence; a missing observation is not a zero total.
Research excerpts remain research-only under the existing admission policy.

Release counts use stated software dates. Notice counts use notice dates. A
withdrawn/deferred-release rate uses the shipped-release cohort's year and cannot
be assigned using a notice date. Respin counts/rates use the follow-up release's
year: the share of releases published as same-base follow-ups, not a prediction
that a release will later need a respin. Rate support requires a complete dated
original release denominator plus explicit complete signal coverage, and sufficient
prior-release history for the interval. Otherwise rates stay null. Current data
has no complete denominator or signal history, so all rates remain unavailable.
No cross-vendor rate is displayed when any denominator is unknown.

## Upgrade joins

Deduplicate `(vendor, train, step date, target)` across scenario/policy rows; retain
those scenario/policy references without counting them as extra upgrades. Match
exact source-stated affected releases or previous-release identities, never a
range guessed from an index. Source model scope is displayed. A step with no
explicit model names yields model-unresolved context, never proven applicability.
A source with explicit nonoverlapping step models is excluded. Current compiled
upgrade rows do not carry exact models, so markers must retain that limitation.

Withdrawal/deferral chronology compares an explicit action date to the step, not
notice date. Unknown action dates stay unknown. Respin chronology uses the stated
follow-up release date and separately reports the gap between software releases.
Field notices retain their classification, notice date and action date. Hardware
and configuration remedies do not become software withdrawals or additional code
upgrades. Annotation exports retain the original publication and selected analysis
context; changing the catalogue never changes upgrade counts.

## Delivery, validation and activation

Closed backward-compatible optional schema alongside advisory v2. JSON/CSV exports
and native API use the same report, with optional selected upgrade annotations.
The site loads the root from its accepted generation and fails closed on mixed
identity or damaged data. Tables and source-linked markers retain caveats and
review status. Update the narrative without losing the pinned earlier sample.

Extend switching validation with a separate release-reliability section rather
than altering advisory extraction pass rates. Checks cover provenance, chronology,
same-base pairs, date separation, model scope, schema and publication privacy.
Generate an unreviewed packet for every notice classification and explicit action
or corrective relationship. No automatic human approval.

Prepare a candidate generation and review the rendered output. Live source-pin
activation/deployment remains a concrete final operation after review. Schedules,
permissions, secrets and automatic vendor collection remain unchanged.
