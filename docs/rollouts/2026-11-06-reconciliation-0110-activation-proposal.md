# v0.11.0 activation proposal — 6 November 2026

Status: **preparation only; approval is required for source publication and hosted
activation**. No tag, GitHub Release, runtime-variable change, workflow dispatch,
new source activation or normalization write is performed by this proposal.

The hosted `IMPACT_SOURCE_COMMIT` was read on 6 November 2026 as
`06839b5151c7bd7841a8719de41c93944fc878e1`, the published v0.10.1 source.
The v0.11.0 candidate packages the merged reconciliation, Arista fixes and
dependency updates, with matching version metadata and example-plugin support.
The exact candidate commit and asset hashes belong in the external candidate
manifest after the final build. Approval must name that immutable identity, not
the moving preparation branch. Existing releases and recovery drafts stay intact.

## Expected website behavior

| Area | Expected result after an ordinary controlled collection |
| --- | --- |
| Official CVE reconciliation | Available locally; no hosted discovery, API route, automatic backfill or cohort expansion. |
| Reviewed Arista URLs | New or reprocessed supported inputs use corrected CVE grouping and source selection. Contradictory alternates remain visible. |
| Old normalized revisions | Retained; old catalogue associations are not automatically migrated or deleted. |
| Comparison exports | Same evidence rules and conservative unknowns; less duplicate validation, without an interactive full-corpus latency guarantee. |
| Vendor/model comparison | Exact model evidence and historical completeness remain gaps; no ranking or equivalence conclusion. |
| Python | Reader container uses 3.15; the existing hosted workflow continues using 3.13. |

The local read-only maintenance preview uses a backup of the separately collected
public research stage. Its counts are an operator measurement of that stage,
not a forecast for the hosted vault. All built-in normalizer identities change
because the shared switching adapter changed. That can make records maintenance
candidates without changing their meaning. No broad replay is proposed.

The current public manifest and compressed snapshot are retained with verified
hashes as a baseline. They contain normalized public output, not all original
source captures, so they cannot support an exact hosted normalization dry-run.
The hosted recovery vault, keys and ciphertext remain unopened in this preparation.

## Observed preparation results

The verified public generation was `0f0e7be466ff47cfa9367d85cf80f20f`, with
952 records. Its expanded snapshot SHA-256 was
`b720bacb994442070df8b14a894b0928d42bb506c83ff5fc2977d2979c2715df`.
The exact SA-0099 HTML record still named only CVE-2024-27892, and the exact
SA-0103 CSAF record named CVE-2023-5501. These are observed retained associations,
not independently supported affectedness conclusions. The repaired HTML selects
CVE-2024-27890 and CVE-2024-27892 separately for SA-0099 and CVE-2024-6858 for
SA-0103; it does not rename the contradictory retained CSAF identity.

The separate local preview contained 186 Cisco, five Aruba and 32 Arista latest
records. All 223 were fingerprint candidates and would receive revisions, with
zero semantic changes, failures, remaining candidates, writes or network requests.
The Arista-only preview likewise had 32 candidates and zero semantic changes.
Original and backup database bytes were unchanged. This sample does not include
the two later, separately accepted corrected Arista documents and cannot predict
hosted maintenance counts or historical-cleanup outcomes.

## Proposed actions after separate approval

1. Verify final candidate CI, the clean source/privacy checks, both frozen
   dependency exports, wheel contents/licenses, installed version and external
   plugin. Match the source archive and wheel hashes to the candidate manifest.
2. With source-publication approval, integrate the reviewed release metadata and
   publish `v0.11.0` at the approved exact commit with the verified assets. Do not
   move an existing tag or publish private captures, stage databases or receipts.
3. With hosted-activation approval, recheck the current runtime pin and active
   publication before setting only `IMPACT_SOURCE_COMMIT` to the approved SHA.
   Preserve schedules, Python selection, workflow permissions, cadence anchors,
   source configuration, recovery mode, keys, vault profile and all budgets.
4. Run one ordinary incremental collection with `reparse_limit=0` and no vendor
   override. Confirm recurring replay is disabled before dispatch. Do not add
   Cisco credentials, enable local snapshot discovery, seed the hosted vault from
   local staging, or start a backfill. A pinned full CVE snapshot remains a local
   operator dataset rather than a scheduled hosted dependency.
5. Inspect actual generation, source failures, audit and recovery readback/storage
   results. Verify deployed publication hashes, strict health/monitor checks,
   same-generation exports and KEV freshness. Record actual run/generation IDs;
   manual success does not prove scheduled reliability.
6. If historical normalization is wanted, propose a separate bounded vendor-scoped
   pass after inspecting supported retained representations. A failed exact CSAF
   representation may need a fresh reviewed HTML selection, not repeated replay.
   Do not treat old-record retention as a silently completed cleanup.

## Stop and rollback

Stop acceptance on provenance, migration, recovery-integrity, strict-validation
or budget failure. Preserve diagnostics and recovery history; do not repeatedly
dispatch or relax validation to obtain a successful publication.

The previous pin above is the source rollback target, not a database or Pages
rollback. This candidate adds no collection database migration, but a collection
can still append evidence and revisions. Verify the old helper can read the new
checkpoint before any rollback collection. Restoring a source variable does not
restore the prior public generation or undo state changes. Recovery repair,
checkpoint selection, normalization maintenance and another publication require
their own concrete decision.
