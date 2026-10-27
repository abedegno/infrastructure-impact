# Scheduled-service observations

An active workflow and a successful manual dispatch do not establish that a
scheduled trigger ran. Monitor actual `schedule` events separately from
`workflow_dispatch` events. Manual publications can keep public data fresh while
scheduled collection is missing.

The reviewed public cadence is daily collection at **12:43 UTC** and monitoring
at **00:23, 06:23, 12:23 and 18:23 UTC**. Native/Docker schedules are separate.
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
the grace period causes a nonzero monitor exit even before the seven-day review.
The JSON receipt and other always-run operational checks are still retained.

The grace period is an operator expectation, not a GitHub delivery guarantee. A
late run's creation time cannot identify its original cron slot from these
metadata; the report makes no exact per-slot delivery or uptime claim. Run counts
exclude future timestamps and events before the service observation anchor.

After activation, inspect actual schedule events and their source commit,
publication, source failures and recovery receipt. Keep the seven-day review
pending until real elapsed time and sufficiently complete run history permit it.
A green manual smoke test cannot substitute for that observation.


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
