# v0.10.0 coverage-repair activation proposal — 5 November 2026

Status: **candidate preparation; hosted activation requires approval**.
This document does not claim a release or deployment has occurred.

The existing hosted source pin was verified as
`11a4a9ed409a08285e7c9be1f6f87f4693fdf805` (v0.9.1). The proposed source
packages PR #23 and matching v0.10.0 release metadata. Approval must identify
the exact candidate commit and its independently verified source/wheel/checksum
assets; a moving branch name is insufficient. Keep prior release tags/assets
immutable. Source release publication does not itself change the hosted pin.

## Proposed controlled activation

1. Require independent candidate review, exact-head Python 3.11/3.13 and container
   CI, clean source/privacy checks, frozen dependency exports and installed-wheel
   external-plugin acceptance. Verify the candidate manifest and asset hashes.
2. After approval, publish the verified source tag/assets if not already published,
   then set only `IMPACT_SOURCE_COMMIT` to that approved full commit. Preserve
   schedules, workflow permissions, observation anchors, source defaults, vault
   profile, recovery mode/secrets and all budgets.
3. Dispatch one ordinary incremental collection with `reparse_limit=0` and no
   vendor override. Do not configure Cisco credentials, enable the opt-in source
   example, start history/backfill, or seed the hosted vault from local staging.
4. Inspect that run's source pin, timings, failures, generation and existing
   encrypted recovery readback/storage checks before accepting its publication.
   Parser support can improve ordinary future collection; this run does not
   promise a complete historical refresh or reproduction of the local stage.
5. Verify deployed strict publication/index/monitor checks and same-generation
   reader JSON/CSV parity. Record actual source/notice/unsupported counts and KEV
   state. Preserve coverage unknowns and pending human review.
6. Inspect public-health and operations results. Manual success proves that run,
   not scheduled reliability; do not reset cadence anchors to clear warnings.
   Write a separate dated receipt with actual run and generation identities.

## Stop and rollback

A migration, provenance, recovery-integrity, strict validation or budget failure
blocks acceptance. Preserve diagnostics and recovery history; do not repeatedly
dispatch. Check whether the previous Pages generation remains current.

The prior runtime pin above is the rollback target. Restoring a pin does not
restore a previous Pages generation or undo state changes. Verify the exact
v0.9.1 helper can read the resulting checkpoint before proposing any rollback
collection. The new document-only replay snapshot uses an existing internal
field, adds no migration and leaves page scope unchanged; this does not replace
checkpoint/readback validation. Any recovery repair, alternate checkpoint or
additional collection requires a separate concrete decision.

## Limits

The local public stage parsed 2/19 Aruba documents, two Arista advisories and two
notices. Seventeen Aruba layouts, authenticated Cisco history, exact-model
bindings and human review remain incomplete. Hosted activation does not authorize
new sources, private evidence, security rankings or release-history work.
