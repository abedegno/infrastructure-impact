# v0.9.0 switching study activation proposal — 4 November 2026

Status: **prepared for approval; not activated**. This document proposes a source
release followed by one controlled hosted run. It is not an activation receipt.
The release PR identifies the exact reviewed candidate commit; its full SHA must
be recorded and approved before changing the runtime pin.

## Verified starting point

Implementation [PR 19](https://github.com/abedegno/infrastructure-impact/pull/19)
merged as `f34a16343dd329f4b5fb1c05cc0483355810b28e`. Its post-merge Python
3.11/3.13 and container checks passed. The release candidate adds version,
distribution-reference and release-documentation changes only.

Read-only checks on 4 November found:

| Setting | Current value / proposed treatment |
| --- | --- |
| `IMPACT_SOURCE_COMMIT` | `5f15a88a956d783190a70aa1b99a3138aca24f76`; change only after approval to the exact v0.9.0 release commit |
| `IMPACT_REPARSE_LIMIT` | `0`; retain, and explicitly dispatch the controlled run with `reparse_limit=0` |
| `IMPACT_REPARSE_VENDOR` | Unset; retain |
| `IMPACT_VAULT_PROFILE` | `large` (1 GiB); retain |
| `IMPACT_RECOVERY_STORAGE` | `github-draft`; retain |
| Secrets | Only `IMPACT_STATE_KEY` is configured; do not read or change it |
| Cisco credentials | Not configured; do not provision or wire them during this rollout |

The public v0.8.0 generation was `cc672063ffb04700a40cebc29f84f9e6`, generated
`2026-11-03T19:50:23.984990+00:00`. The current-code read-only monitor reported
fresh, KEV available, switching unavailable, 891 advisories and 19 source failures.
It checked 4,980,307 public bytes without downloading full history. This is a
dated baseline, not a promise that those source counts remain constant.

Metadata-only storage review at `2026-11-04T18:36:58.590175+00:00` reported
470,605,824 repository bytes against the unchanged 536,870,912-byte review budget
and a 25,753,228-byte latest encrypted archive against its 52,428,800-byte bound.
It required no storage intervention but retained 80-percent repository-growth
and logical-history warnings. It did not download/authenticate ciphertext or
independently attest recovery availability. Recheck these bounds before activation;
do not delete history, raise limits or perform a hosted full backfill to make them
pass.

## Proposed authorized sequence

1. Review and merge the v0.9.0 release-preparation PR. Require exact-candidate
   Python 3.11/3.13 and container CI, clean source-export verification and an
   installed-wheel/external-plugin probe. Record the reviewed source SHA and
   wheel/source SHA-256 checksums. Do not move an existing tag.
2. **After explicit approval**, tag the reviewed source as `v0.9.0` and publish
   the research-preview release notes, verified wheel and checksum manifest.
   Recovery drafts remain unpublished. No PyPI/container-registry push is proposed.
3. Change **only** `IMPACT_SOURCE_COMMIT` from the value above to that exact full
   release SHA. Preserve all schedules, workflow permissions, observation
   anchors, recovery settings, source defaults and replay variables.
4. Dispatch `collect.yaml` on `main` once with `reparse_limit=0`. This uses the
   existing ordinary incremental collector, not `switching-backfill`, historical
   replay or official-score enrichment batches. Do not seed the hosted vault
   from the native research vault or from the separate public-source staging vault.
5. Require successful authenticated recovery write/readback and unchanged size
   limits before accepting the new public generation. Inspect source failures;
   partial upstream failures do not establish complete coverage. A migration,
   provenance, budget or recovery-integrity failure blocks acceptance.
6. Verify the deployed manifest, current generation and code hashes, strict study
   summary/inputs, KEV state and independent reader controls. Compare selected
   JSON/CSV against native selection of the same downloaded public report.
   Exercise an empty model selection, evidence expansion, accepted exports and
   keyboard/mobile layout. Preserve source bytes and private receipts outside
   Git and release assets.
7. Dispatch the existing public-health and service-operations workflows on
   `main`, recording their actual run IDs, generation, source pin and findings.
   Preserve cadence/storage warnings; a manual run does not establish scheduled
   reliability or complete the observation window or human extraction review.
8. Write a separate dated activation receipt with measured results. Do not change
   this proposal into a claimed success before those results exist.

The existing monitor can read the old publication with switching unavailable;
the new public study assets become required only when the publication declares
them. The controlled collector's final health check uses its pinned source.

## Commands to execute only after approval

The release PR supplies the exact candidate SHA. Resolve and verify the approved
tag rather than copying a moving branch name:

```sh
RELEASE_COMMIT="$(git rev-parse 'v0.9.0^{commit}')"
gh variable set IMPACT_SOURCE_COMMIT --body "$RELEASE_COMMIT"
gh workflow run collect.yaml --ref main -f reparse_limit=0
```

Record and inspect that dispatch's run ID before starting monitors or attempting
another collection. Do not repeatedly dispatch to conceal a failed first run.

## Rollback and stop conditions

If deployment fails, first check whether the previous Pages generation remains
current; the collector's atomic publication and recovery checks remain in force.
Preserve failed-run diagnostics and all retained recovery history.

The proposed runtime rollback is to restore
`IMPACT_SOURCE_COMMIT=5f15a88a956d783190a70aa1b99a3138aca24f76`, retaining the
`large` profile and draft-storage mode, then perform one reviewed controlled run
with replay disabled. Merely restoring the pin does not redeploy old Pages assets.
New operational tables are additive, but a source-code rollback does not undo
migrations or certify a particular hosted checkpoint's recoverability. Verify
recovery and integrity before that run; stop if the old helper cannot read the
new checkpoint. Do not reset tables, discard history or replace the checkpoint
with the local stage. Recovery repair or a different checkpoint requires a
separate concrete proposal and approval.

A local synthetic rehearsal created a database with migrations 1–15, ingested
one project-authored Aruba fixture, then used the exact v0.8.0 source above to
build an old-reader publication. It succeeded and preserved all migration rows.
This tests additive-table/read-path compatibility only; it did not restore or
authenticate the hosted checkpoint and does not remove the rollback checks.

## Explicitly deferred

Cisco credential provisioning/secret mapping, hosted history/backfill modes,
schedule or permission changes, archive-parser expansion, target-model evidence,
human review and storage migration remain separate work. The release exposes
the current retained evidence and its gaps; it does not promise fair vendor
comparison data immediately after activation.
