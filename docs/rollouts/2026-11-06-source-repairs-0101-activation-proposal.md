# v0.10.1 source-repair activation proposal — 6 November 2026

Status: **candidate preparation; publication and hosted activation require approval**.
This document does not claim a release or deployment has occurred.

The existing hosted source pin was verified as
`b61adddd81f63b1b143c5901dccbae7e65b85b48` (v0.10.0). The proposed source
packages PR #26 and matching v0.10.1 metadata. Approval must identify the exact
candidate commit and independently verified source archive, wheel and checksum
assets recorded in the external candidate manifest; a moving branch is
insufficient. Preserve prior tags/assets. Source publication and hosted activation
remain separate actions.

## Proposed controlled activation

1. Require independent candidate review, exact-head Python 3.11/3.13 and container
   CI, clean source/privacy checks, frozen dependency exports, wheel license
   inspection and installed-wheel external-plugin acceptance. Verify asset hashes
   against the candidate manifest and the reviewed commit.
2. After approval, merge the reviewed release PR and publish a source tag pointing
   to the approved candidate commit with those exact assets. Set only
   `IMPACT_SOURCE_COMMIT` to that approved full SHA. Preserve source defaults,
   schedules, workflow permissions, observation anchors, recovery mode/secrets,
   vault profile and every delivery/storage budget.
3. Dispatch one ordinary incremental collection with `reparse_limit=0` and no
   vendor override. Do not configure Cisco credentials, activate new sources,
   start backfill, or seed the hosted vault from local staging. Existing retained
   documents need not be reprocessed by this ordinary pass.
4. Inspect actual source pin, timings, failures, generation and encrypted recovery
   readback/storage checks before accepting publication. Report the actual result;
   the local two-source acceptance does not promise a historical hosted refresh.
5. Verify strict deployed publication/index/monitor checks and same-generation
   native/static JSON/CSV parity and browser controls. Record KEV state and source
   failures, retaining coverage unknowns and pending human review.
6. Inspect public-health and operations results without resetting cadence anchors.
   Record a separate dated receipt with actual run and generation IDs. Manual
   success proves that run only, not scheduled reliability.

## Stop and rollback

A provenance, migration, recovery-integrity, strict-validation or budget failure
blocks acceptance. Preserve diagnostics and recovery history; do not repeatedly
dispatch. Check whether the prior Pages generation remains current.

The prior source pin above is the rollback target. Restoring it does not restore
an older Pages generation or undo state changes. Verify the exact v0.10.0 helper
can read the resulting checkpoint before proposing any rollback collection. This
patch adds no migration; that does not replace checkpoint/readback verification.
Recovery repair, an alternate checkpoint or another collection requires a
separate concrete decision.

## Limits

The repairs cover one reviewed F5 PDF profile and one exact Juniper transport
route. They do not establish complete histories, model applicability, fix dates,
comparative security rates or intentional concealment. Official-CVE snapshot
reconciliation remains separate design work; it is not activated by this release.
