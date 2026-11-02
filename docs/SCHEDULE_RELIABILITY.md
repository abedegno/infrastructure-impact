# Scheduled-service observations

An active workflow and a successful manual dispatch do not establish that a
scheduled trigger ran. Monitor actual `schedule` events separately from
`workflow_dispatch` events. Manual publications can keep public data fresh while
scheduled collection is missing.

The reviewed public cadence is daily collection at **12:43 UTC**, health monitoring
at **00:23, 06:23, 12:23 and 18:23 UTC** (`23 */6 * * *`), and, after separation
activation, operational review at **00:53, 06:53, 12:53 and 18:53 UTC**
(`53 */6 * * *`). Native/Docker schedules are separate.
The collector receives `--schedule-utc 12:43`, so published schedule metadata uses
the same declared time rather than an old hard-coded label.

## Activation and observation

Both workflows were active on the default branch, but the inspected history on
27 October 2026 contained no scheduled collection and two scheduled monitors.
The repository was active and not archived. These facts do not identify a cause.

GitHub documents that schedule delivery can be delayed or dropped, requires the
default branch, and can stop when an associated actor is no longer active.
Changing the cron schedule under an authorized maintainer can re-register the
schedule. See [GitHub's troubleshooting guide](https://docs.github.com/en/actions/how-tos/troubleshoot-workflows).
The previous collection time was 08:37 UTC; monitoring used minute 17. The new
cadence provides an observable upcoming daily trigger and refreshes registration.
It is a repair attempt, not proof of the earlier cause or future reliability.

Set `IMPACT_SCHEDULE_OBSERVATION_START` once when this cadence is activated.
It is separate from the existing `IMPACT_RELIABILITY_START` seven-day service
anchor. Do not move either anchor on each deployment, and do not turn manual
runs into scheduled observations. A future or pre-service cadence anchor is
rejected. The original service review remains due 2 November 2026.

## Missing-trigger detection

`checks/operations_report.py` reports the last expected trigger, latest successful
scheduled run creation time and a two-hour grace period for each workflow. The
states distinguish no trigger yet due, a current grace period, a recently observed
scheduled success and an overdue successful-run observation. Missing success after
the grace period causes a nonzero operational exit even before the seven-day
review. Before separation this failed the combined monitor; after activation it
fails `Service operations` independently of public health. The JSON receipt and
other always-run operational checks are still retained.

The grace period is an operator expectation, not a GitHub delivery guarantee. A
late run's creation time cannot identify its original cron slot from these
metadata; the report makes no exact per-slot delivery or uptime claim. Run counts
exclude future timestamps and events before the service observation anchor.

After activation, inspect actual schedule events and their source commit,
publication, source failures and recovery receipt. Keep the seven-day review
pending until real elapsed time and sufficiently complete run history permit it.
A green manual smoke test cannot substitute for that observation.

## Dated activation follow-up — 27 October 2026

The cadence anchor remained **11:50:45 UTC**, and the original service anchor
remained **26 October at 11:53:57 UTC** throughout the deployment and release.
A separate local, read-only observer checked the public reader and actual Actions
history at the declared grace deadlines; it neither dispatched collection nor
changed the observation anchors.

| Observation | Result |
| --- | --- |
| Monitor, checked 14:23:16 UTC | No successful scheduled monitor after activation; the 12:23 trigger's two-hour grace period had elapsed. |
| Collection, checked 14:43:15 UTC | No successful scheduled collection after activation; the 12:43 trigger's two-hour grace period had elapsed. |

Both deadline public checks still verified fresh publication
`1043641ebcf548a6994c1c47975d6fd0`, generated at 13:44 UTC, with 774 advisories.
Fresh manual publication and passing software CI do not resolve the scheduling
gap. The local operations checks returned nonzero for the overdue observations,
while its separate public-health check passed. This identifies a missing
successful-run observation, not the cause of a delayed or absent trigger.

A subsequent [manual monitor run](https://github.com/abedegno/infrastructure-impact/actions/runs/40523871430)
retains hosted operational checks after both deadlines. Its `workflow_dispatch`
event is not a scheduled delivery or a replacement for either missing successful
run. Keep the next actual schedule events and the seven-day review open.

## Shared scheduler boundary

Collection and its six-hour monitor both use GitHub Actions. A missing monitor
cannot emit its own failure, so this is not an independent alerting service. The
read-only checks can also be run from another authorized environment without a
vault key. Inspect `schedule` events explicitly; repository activity and fresh
manual deployments cannot substitute for them.

The dashboard marks stale publications when loaded or rendered, but that requires
someone to view it. An external alert service or another host would need its own
operator setup and observation. No independent notification service is claimed
or silently enabled by this deployment.

## Operational separation — activation pending

The separation was approved on 2 November 2026. This is a candidate rollout
record, not an activation date. Deployment identity, independent health and
operations run IDs/results, receipt retention and unchanged protected settings
must be recorded in the operator's non-public rollout record after integration.
Append the evidenced activation date here then; do not replace earlier failed
observations. No live dispatch or scheduled-reliability result is established by
local tests or this documentation.

On 1 November, public-health checks passed in runs `41334146901` and
`41355786206`, while their combined operational checks failed the two-hour grace.
The declared 12:43 collection had no observed successful scheduled run until a
run created at 18:05:45. Later the collection observation was current but monitor
success observations remained overdue. Preserve those failed conclusions. These
creation times do not identify the original cron slots or GitHub's delivery cause.

The reviewed `Public service health` workflow now has only public-health checks;
`Service operations` separately reviews collection/monitor cadence and storage.
Operations runs are never counted as scheduled monitor observations. Health's
pinned checker root and separate `operational-control` event-SHA checkout preserve
the old collector pin; operations uses one reviewed default-branch event-SHA
checkout. See [source boundaries](HOSTED_SERVICE.md#operate-and-update) and
[stable failure codes and receipts](OPERATIONS.md#independent-health-and-operational-outcomes).
Both jobs reject non-default-branch manual events. Each retains its own honest
health receipt; failed pipeline checks remain failures even if `tee` succeeds.
Always-run steps retain available diagnostics, but runner, checkout, network or
upload failures may prevent evidence from being produced or retained. Inspect
actual steps and artifacts; unknown evidence cannot count as successful health.

The original anchors remain **2026-10-26T11:53:57Z** for service observation and
**2026-10-27T11:50:45Z** for cadence observation. Preserve the two-hour grace,
36-hour publication limit, 1,000-run per-workflow history bound and 100-commit
backup history bound, including truncation findings. Repository storage remains
512 MiB with the existing 50 MiB per-archive limit and 80% warnings. Neither this
rollout nor a manual success restarts the observation windows or establishes
continuous uptime. Later real `schedule` events remain necessary to assess cadence.

## Manual check, dispatch and recheck

1. From an authorized read-only environment, inspect the public HTML, publication
   age and fingerprint manifest with `checks/public_health.py PUBLIC_URL`. Run
   the existing `checks/operations_report.py` flags with the preserved service
   and cadence anchors, and the metadata-only `checks/backup_storage.py` report.
   Save their receipts; inspect real `schedule` versus `workflow_dispatch`
   histories, failed conclusions, truncation and storage findings. These checks
   need no vault key or recovery download.
2. After reviewed integration, dispatch `monitor.yaml` and `operations.yaml`
   independently on the default branch. Inspect each job's checkout identity,
   steps, result, summary and 30-day artifact. Health may pass while operations
   correctly remains red for overdue successful scheduled observations. Manual
   dispatch is a behavior check, not a repair of scheduling.
3. If collection itself needs a manual recovery pass, an authorized operator must
   first inspect the latest collection and its concurrency/state condition, then
   use the existing encrypted `collect.yaml` workflow with the unchanged runtime
   pin. Do not launch a second writer, run a plaintext collector, change key
   custody or reset anchors. Preserve the prior publication and recovery history;
   an all-failed collection must leave the previous generation readable. This
   procedure does not automatically dispatch collection.
4. Recheck public health, collection result, source failures, sanitized publication
   and the writer's recovery-verification receipt without downloading private
   evidence. Repeat the read-only operational assessment. Retain both before and
   after findings, including overdue schedule observations after a successful
   manual collection. Report website, storage or network failures honestly.

Keep the previous reviewed source/runtime available for rollback. Do not rewrite
history, delete retained evidence or use recovery downloads as routine diagnosis.
GitHub-triggered redundancy shares GitHub's failure boundary and cannot guarantee
delivery. An independent watchdog would require an agreed host/account, independent
freshness observation, scoped dispatch credentials with agreed custody, and an
operator-approved concurrency/recovery policy. None is provisioned here.

## Subsequent research proposal

Research expansion remains a separate source-led proposal after operational
verification. Preserve the frozen original studies and reviews. Prefer comparable
infrastructure roles and explicit product/build/CVE statements; retain missing
vendors and unknowns. New rates, denominators, vendor rankings, verified fix-delay
or intent/concealment conclusions require their own evidence gates. This rollout
changes none of those study definitions and needs no private inventory access.
