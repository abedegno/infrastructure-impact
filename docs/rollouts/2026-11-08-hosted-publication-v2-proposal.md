# Hosted publication v2 proposal — 8 November 2026

Status: default-off preparation for review. This patch does not activate hosted
publication. The reviewed source pin remains the sole source-code authority;
there is no branch, source override, alternate manifest or secret-bearing preview
bypass. The local full replay and complete hosted inventory are separate gates.

This is the historical proposal. See the [approved rollout record](2026-11-08-hosted-publication-v2.md)
for activation, the first cancelled apply and the orchestration repair.

## Local verification available

The [core retained replay](../research/2026-11-08-runtime-and-paging-verification.md#accepted-local-retained-replay)
passed all 174 retained targets using frozen code `ca27f6c`, within the existing
2,400-second worker limit. Audit, capacity, native parity and both HTTP monitors
passed; existing rows and capture dates were preserved with zero HTTP attempts.
Its [machine-readable proof](../research/2026-11-08-retained-import-acceptance.json)
records the exact software, input and accepted-generation identities.

The default-off hosted wiring passed 217 focused tests, including fresh workers,
legacy-helper compatibility, mirrored workflow equality and remote-recovery
failure handling. Its installed package also passed the synthetic worker and
both monitors. These checks do not cover live source reachability or certify the
complete hosted inventory. Independent human evidence review remains pending.

## Wiring and compatibility

`ops/hosted_job.py --publication-format v2` explicitly selects the existing v2
builder for ordinary collection, named maintenance and exact-target apply. The
helper and `worker.collect_once()` default to v1. Library publication selection
comes from explicit arguments, never an ambient library environment variable.
`collect.yaml` maps repository variable `IMPACT_PUBLICATION_FORMAT` to that flag;
unset or `v1` omits the flag so reviewed older helpers remain compatible.

The pre-secret static workflow check validates `v1|v2` and requires the reviewed
pinned helper's single literal `HOSTED_PUBLICATION_FORMATS = ("v1", "v2")`
declaration for v2. The existing `effects-v1` protocol and exact legacy-helper
checksum bridge remain in force. A legacy or older effects-v1 helper cannot accept
v2. The declaration is a compatibility marker within reviewed pinned source,
not permission to execute arbitrary source with recovery credentials.

The setting persists across ordinary daily collection and both named apply paths.
A one-off format override is deliberately absent: a following collection must
not unintentionally return the enlarged inventory to v1. Existing schedules,
workflow permissions, timeout, source configuration, recovery backend, encryption,
readiness gates and capacity limits are unchanged by this patch.

Preview remains format-independent: authenticate and restore a disposable hosted
checkpoint, compute the existing v1 preview binding, and upload only
`maintenance-preview/maintenance-preview.json`. It does not acquire publisher
sources, build a candidate, back up state or publish Pages. An accepted local
fingerprint cannot substitute for the current hosted fingerprint.

## Approval packet and controlled activation

Before any hosted change, obtain explicit rollout approval naming the final
reviewed immutable source SHA, the `IMPACT_PUBLICATION_FORMAT=v2` selection and
the exact-profile preview/apply sequence. Source merge/release and runtime pin
activation are distinct operations. This document authorizes none of them.

Prepare the source review, focused regression results, installed package checks,
full local retained-evidence acceptance and immutable artifact identities first.
Do not activate until these are accepted. Then, within the explicitly approved
rollout scope:

1. Recheck live source pin, current generation, recovery settings, active jobs and
   existing daily collection window. Activate only the reviewed source SHA and
   explicit v2 setting, keeping all other controls unchanged. The pin and format
   also affect ordinary scheduled collection before the exact import applies;
   record the actual intervening generation rather than attributing it to apply.
2. Dispatch the installed `campus-switching-public-gap-2026-11-07-v1` profile with
   `maintenance_mode=preview`, empty apply fingerprint, `reparse_limit=0` and no
   vendor override. Inspect authenticated restore and the bounded preview
   artifact. Confirm no acquisition, recovery retention or Pages publication.
3. Accept only the actual hosted preview's target identities and fingerprint.
   Stop on unexpected inventory, identity, configuration or normalizer changes.
   Bind the apply request to that fingerprint; scheduled collection can invalidate
   it. Do not replace a refused preview with generic collection or replay.
4. Dispatch exactly one matching apply within the approved scope. The stage must
   validate the complete hosted union, including unchanged historical data,
   provenance, native/JSON/CSV parity, full archive, browser representation,
   public-only monitor and all byte limits. A local replay result cannot certify
   these complete hosted checks. No recovery promotion or Pages readiness is
   allowed for a rejected stage.
5. Verify authenticated backup/readback and pointer promotion before public-copy
   readiness, then inspect the deployed generation and public fingerprints.
   Require v2 index/catalog, mandatory research roots and the self-contained
   `snapshot-v2.json.gz` archive. Retain the actual monitor receipts and capacity
   measurements. A successful manual apply does not prove scheduled reliability.

The v2-capable `checks/public_health.py` and `checks/switching_health.py` are
already present in the source milestone. The standalone monitor recognizes v2,
uses its 32 MB default-download safety ceiling, and verifies the v2 archive when
requested. It still checks the v1 20 MB default ceiling for v1. Existing artifact
names remain `public-health-<run_id>`, `reliability-review-<run_id>` and
`public-health.json`; preview remains `maintenance-preview`. The public-health
workflow uses the collector source pin; the operations workflow uses default-
branch control code. Both must contain the v2-capable monitor before publication.

## Stop and recovery

Stop on stale preview, source drift, strict-schema or parity failure, missing
mandatory roots, byte-limit failure, recovery/readback failure or public-copy
failure. Preserve diagnostic evidence and the previous accepted deployment. Do
not raise limits, discard evidence, change source selection or retry broader
operations to manufacture acceptance.

Recovery manifests, encrypted archive formats, storage profiles and restore-only
commands are independent of publication representation and remain unchanged.
A public-copy failure may leave a verified accepted recovery checkpoint while
Pages remains unready; record both facts. Public monitors detect failure but do
not restore Pages. Changing the format setting back to v1 is not an automatic
rollback: the complete imported inventory may exceed v1 capacity. Selecting an
older source pin is also not a checkpoint or generation restore, and may change
current/historical interpretation. Any recovery repair or replacement publication
requires a concrete reviewed decision.
