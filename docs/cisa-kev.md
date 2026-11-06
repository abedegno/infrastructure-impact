# CISA KEV membership

The reader adds exact CVE membership from the [CISA Known Exploited Vulnerabilities
catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). The default
source is the [CISA-maintained CC0 JSON mirror](https://github.com/cisagov/kev-data),
retrieved from its reviewed `develop/known_exploited_vulnerabilities.json` raw URL.
There is no automatic transport fallback. CISA fields are publisher statements;
KEV membership does not establish product applicability, installed inventory,
vendor assessment, fix availability or timing, or disclosure intent. Vendor/product
names never create joins: only canonical CVE identities do.

## Availability and retained history

A successful complete catalogue contains 1–20,000 unique CVEs and fits an
8,000,000-byte raw-feed bound. An unchanged successful check refreshes verification
without creating a content revision. The report preserves the catalogue version,
released time, raw SHA-256, retained revision, source-observed time, parsed time,
latest attempt and checked time separately. A check time is not a content-observed
time. Failed or malformed retrievals preserve the previous validated catalogue.

Membership is `listed`, `not_listed` or `unknown`. It is unknown when verification
is more than 36 hours old, more than five minutes in the future, missing, disabled,
not configured, or followed by a failed latest attempt. The selector evaluates
freshness at `evaluated_at` without changing immutable publication identity or
`generated_at`. Retained details remain visible as historical context when current
membership is unknown. A fresh `not_listed` result means absent from this verified
catalogue, not safe, unaffected, or never exploited.

The complete sorted membership index supports arbitrary CVE lookup. Detailed
publisher entries are limited to imported and benchmark CVEs. A CVE outside that
scope can be listed without detailed fields. Due dates and required actions are
CISA fields, not this application's instructions or verified vendor fixes.

## Configuration and controls

Public root and bundled defaults enable `reference_sources` entry `cisa-kev` at
`https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json`.
An existing custom config is preserved. An absent entry is not configured and
triggers no KEV request; `enabled: false` disables it. Older publications lacking
KEV expose unknown context and no fabricated downloadable publication report.

The optional **KEV listed only** control intersects the requested CVEs with fresh
listed identities; vendor selection then narrows evidence for those CVEs. It never
creates vendor assessments. Unfiltered views remain usable when KEV is unknown.
An unavailable filtered selection returns HTTP 503 with `kev_unavailable` and
preserves the accepted view and controls. Only one `kev=listed` query parameter is
accepted; empty, duplicate or unsupported values return HTTP 400. No KEV parameter
preserves ordinary selection behavior.

## Reports and exports

`kev.json` is the immutable publication-time report;
`/api/v1/kev` evaluates the selected report and optional CVE/vendor/KEV controls.
`schemas/kev-v1.json` defines its strict contract. Full snapshot downloads contain
the publication report. Selected JSON and CSV exports carry the evaluated KEV
context; CSV adds membership, evaluation/check times, catalogue source/hash and
selected CISA publisher fields. The KEV report download retains publication-time identity and
selection even when the visible evaluated selection changes. Single-dossier JSON
and its schema remain unchanged; adjacent KEV context is separate.

The standard-library `checks/public_health.py` verifies report fingerprints,
source identity, strict structure, scope, sorted unique IDs, catalogue counts and
selection consistency. Unknown KEV alone does not fail site health. Malformed or
mixed-generation reports do. Existing static delivery bounds remain 512,000 bytes
target per part, 8,000,000 maximum part, 2,000,000 index, and 20,000,000 default
cohort bytes for monitoring. KEV does not authorize larger delivery budgets.

## Release and controlled verification

Run synthetic collection, contract, delivery, UI and monitor tests, source export,
installed wheel with an external plugin, formatting/lint and exact supported-runtime
CI before release. Keep browser receipts outside public source. Follow
[release instructions](RELEASING.md) for separate source release and authorized
runtime activation, then retain actual controlled hosted collection receipts.
Preserve schedules, observation anchors, recovery configuration, frozen research
resources and native custom config. Local synthetic acceptance does not prove a
live source check, hosted activation or scheduled reliability.
