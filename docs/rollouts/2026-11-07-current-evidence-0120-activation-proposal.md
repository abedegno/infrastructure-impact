# v0.12.0 activation proposal — 7 November 2026

Status: preparation only. PR #33 was merged at
`ca7dd46da17c63d0f694a74a325ca3fc63dd4f18`; its exact reviewed head and all six
GitHub quality checks passed. This proposal prepares release metadata and a
reviewable activation sequence. It creates no tag or release, changes no runtime
variable and dispatches no hosted workflow.

The hosted `IMPACT_SOURCE_COMMIT` was read on 7 November as
`57b76f7db3486588538dc93b3752327730643cce` (v0.11.0). Keep it unchanged until
activation is separately approved. The exact final candidate commit, clean source
archive and wheel/checksums belong in the external candidate manifest and PR
handoff. Approval must bind that immutable identity, not a moving branch.

## Expected behavior and limits

| Area | Expected behavior after activation |
| --- | --- |
| Current catalogue and analytics | Shared decisions can exclude the exact reviewed unsupported CSAF interpretation when retained proof is sufficient; missing proof remains visible and conservative. |
| Historical evidence | Original CVE identity, revisions and safe source-bound CVSS remain in labelled retained views and full archives. |
| Exact refresh | Only an explicit profile apply retrieves the two primary HTML targets and reviewed alternate; ordinary collection is not that operation. |
| Hosted preview | Authenticated restore, read-only checkpoint preview and fingerprint artifact; no collector acquisition, normalization, new recovery backup or Pages publication. |
| Expected CSAF conflict | Preserved as an alternate-source discrepancy; core completion may be reported operationally as partial. |
| Comparison research | No completeness, unaffectedness, ranking, fix-timing or concealment inference is introduced. |

The local stage's 11/1/12 partition and preserved historical score are evidence of
local implementation behavior, not hosted counts or production health. Human
review remains pending. See [release notes](../releases/0.12.0.md) and
[implementation acceptance](../research/2026-11-06-targeted-refresh-acceptance.md).

## Proposed controlled sequence

1. Verify exact candidate CI on Python 3.11/3.13 and the container, clean source
   allowlist/privacy checks, frozen dependency exports, wheel/resource/license
   hashes and the installed external plugin. Review the version metadata and
   byte-identical protected runtime/configuration inputs.
2. With separate source-publication approval, merge release metadata and publish
   `v0.12.0` at the approved exact commit with verified assets. Do not move an
   existing tag or publish operator packets, databases, captures or recovery data.
3. With separate activation approval, recheck the current public generation,
   runtime pin and active publication jobs, then set only `IMPACT_SOURCE_COMMIT`
   to the approved immutable source SHA. Preserve schedules, permissions, Python
   selection, source configuration, recovery backend/keys, cadence anchors and all
   budgets. No broad replay, backfill or Cisco source enrolment is included.
4. With hosted-preview approval, dispatch `collect.yaml` using
   `maintenance_profile=arista-reviewed-2024-0099-0103-v1`,
   `maintenance_mode=preview`, an empty apply fingerprint, `reparse_limit=0` and
   no vendor override. Inspect the authenticated restore/read-only result and
   download its preview artifact. Confirm no Pages or recovery writes occurred.
   Preview refusal is diagnostic; do not substitute generic replay or collection.
5. Review the actual hosted preview's selected targets, retained proof,
   current/excluded counts, unresolved issues and installed identities. Its
   fingerprint authorizes that checkpoint only. Never reuse a local-stage
   fingerprint. Scheduled collection can invalidate it.
6. With separate approval naming the actual accepted hosted fingerprint, dispatch
   exactly one apply with the same profile, `maintenance_mode=apply`, that
   fingerprint, `reparse_limit=0` and no vendor override. Refuse drift before HTTP;
   inspect both primaries and the alternate outcome, appended/unchanged records,
   historical-row preservation, audit, authenticated recovery readback and backup
   pointer promotion before accepting publication.
7. Verify the actual public generation, artifact hashes, strict health and monitor
   results, current versus labelled retained JSON/CSV/native/static output and
   KEV freshness. Retain expected alternate conflicts and unexpected failures as
   distinct outcomes. A successful manual run proves that run, not scheduled
   reliability, human review, complete vendor history or a fair comparison.

The pin takes effect for ordinary scheduled collection as well as manual runs.
That can publish policy decisions over existing facts before an explicit apply.
Do not promise the live catalogue stays identical between pin activation and the
profile apply; observe the actual generation and do not credit apply for a
preexisting exclusion. Schedules remain unchanged; arrange the bounded approval
and preview window with that existing cadence.

## Stop and rollback

Stop on provenance, candidate identity, preview drift, strict validation,
recovery-integrity or budget failure. Preserve diagnostics and last accepted
state; do not repeatedly dispatch, broaden source scope or weaken validation.

The previous source pin is not an automatic rollback instruction. Pre-policy code
can expose the retained contradictory CSAF as current. Review old-code checkpoint
readability, current/historical semantics and the public generation together
before any downgrade. Changing a source variable does not restore a database or
Pages generation. The monitor rejects invalid output but does not restore Pages.
Recovery repair, checkpoint selection and any replacement publication require
an explicit concrete decision.
