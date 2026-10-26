# Operations

## Native workspace

Use `uv sync --group build` and `uv run impact --help`. Configuration defaults to
the working directory; packaged defaults are used only when no local source file
exists. An explicit missing configuration path is an error.

| Variable | Default / purpose |
| --- | --- |
| `IMPACT_HOME` | Working directory; private data, reports and native status. |
| `IMPACT_DATABASE` | `$IMPACT_HOME/data/intel.sqlite3`. |
| `IMPACT_SOURCES` | `$IMPACT_HOME/sources.json`; declared public vendor sources. |
| `IMPACT_PUBLICATIONS` | `$IMPACT_HOME/publications`; immutable public generations. |
| `IMPACT_SNAPSHOT` | `$IMPACT_HOME/site/dist`; separately exported static copy. |
| `IMPACT_DELIVERY_MODE` | `live_reader` in the service deployment; otherwise a static-copy workflow. |

On macOS, an optional user LaunchAgent can run the native checkout at 08:15
in the system's local timezone. After `uv sync`, run
`python3 ops/manage_schedule.py install`. The helper generates an ignored local
plist with this checkout's paths. Inspect or remove it with `status` / `remove`.
It requires the Mac and user session; it is not an always-on cloud scheduler.
Logs are `data/collector-scheduled.log` and `data/collector-scheduled-error.log`.
Do not install this alongside another writer for the same vault.

## Container service

```sh
docker compose up --build -d
docker compose logs -f collector
curl --fail http://127.0.0.1:8080/health/ready
```

The writer performs an initial pass, then schedules 08:15 Europe/London using
timezone rules, including daylight-saving transitions. Named volume `vault`
contains raw snapshots, SQLite/WAL and reports. Volume `publications` contains only
the sanitized reader artifacts. The reader's public volume is read-only and it
has no private-vault mount. Images run as UID 10001, with a read-only root
filesystem and temporary scratch storage. Source failures stay in run receipts.

The first pass can take several minutes. Readiness returns 503 until publication.
An all-failed collection retains the previous generation; stale data remains
readable but readiness becomes 503 after 36 hours. A partial source failure does
not itself prevent publication of successful evidence. Monitor `/api/v1/health`,
collector logs and publication age. No email/chat alerts are sent automatically.

## Remote deployment and HTTPS

Select a Linux host with persistent storage and Docker Compose. A small initial
installation should allow at least 2 GB RAM, with disk sized for retained raw
evidence and backups. Dependencies are hash-locked; Python/Caddy base image major
tags still receive OS updates. Record resolved image digests for a release and
review dependency/base-image updates rather than assuming a permanent binary hash.

Point DNS at the server, allow 80/443, set the actual domain and run:

```sh
export IMPACT_DOMAIN=cves.example.org
docker compose -f compose.yaml -f deploy/compose.production.yaml up --build -d
```

`example.org` is an illustration, not a provisioned endpoint. Caddy terminates TLS
and proxies to the reader. The base Compose file binds its diagnostic port only
to loopback. For review-only access, configure authentication at the reverse
proxy before opening access; a separately exported static preview is independent of this deployment.
Repository source alone does not provision a server, configure DNS or restrict
access to a remotely published service.

Install real external vendor plugins in a derived collector image, with locked
dependencies, and provide its source configuration. The reader can keep using
the core image. Restart the writer after changing installed entry points.

## Backup, recovery and upgrades

`impact backup DESTINATION` uses SQLite's online backup API and refuses to
overwrite an existing backup. In Compose:

```sh
docker compose run --rm --no-deps collector backup /var/lib/impact/backups/vault-2026-10-25.sqlite3
```

Copy backups off-host through the operator's approved storage path. Public
generations are reproducible; raw evidence and review records are not, so retain
the private vault. Back up configuration and installed plugin versions as well.

To restore, stop the writer, restore a backup to a **new** database path, point
`IMPACT_DATABASE` at it, run `impact migrate` and `impact audit`, then publish a
generation and restart the writer. Keep the old database until recovery is
verified. Do not overwrite an active database or copy only its main file while
WAL writes are active.

Before an upgrade: backup, run deterministic tests and build a wheel/container.
Apply append-only migrations, run `impact reparse` when parsers/schema require
it, audit, then publish. Roll back code only when compatible with applied schema;
otherwise recover into a separate restored vault. Never edit an applied migration.

Old immutable generations are retained for rollback. Monitor disk usage and
archive/prune under an operator retention policy; automatic deletion is not
enabled. Do not remove the active generation. This initial topology is one writer
on one host, not a distributed database or high-availability deployment.

## Source access diagnostics

Collection-health error codes distinguish `source_missing` (404/410),
`redirect_target_missing` (a followed redirect ended at 404/410),
`edge_access_denied` (403 with an Akamai server header and Access Denied body),
`access_denied` (other 401/403), and `access_verification_required` (a recognized
interactive verification page). Generic HTTP/network/layout failures remain
separate. These describe the observed response; none proves a particular bot
rule, a permanent move, or product affectedness. A 403 does not establish that the
requested document still exists behind the edge rule.

For a source visible in a normal browser, use the private
[browser-assisted capture workflow](BROWSER_CAPTURE.md). A manual capture does
not clear an HTTP error or satisfy the scheduled collector's freshness check.

## Initial seven-day reliability review

The public service's verified observation start is 2026-10-26T11:53:57Z, so its
initial seven-day window cannot complete before **2026-11-02T11:53:57Z**. The
repository variable `IMPACT_RELIABILITY_START` anchors that timestamp independently
of the retrieved workflow-list window. For another deployment, set it to that
service's evidenced first run; do not reuse this project's timestamp.

The six-hour monitor retains `operations.json` as a `reliability-review-RUN_ID`
GitHub Actions artifact for 30 days. It runs the operational report even if public
health verification fails. The first normal monitor scheduled after this project's
window is 2 November at 12:17 UTC, subject to GitHub scheduling delays. Until the
window elapses, the report remains `waiting_for_window`.

At eligibility, the automated review checks up to 1,000 runs per workflow, flags
truncation, distinguishes successful scheduled collections/monitors from manual
runs, includes the verified public-health receipt and source-failure count, and
checks repository storage against 512 MiB. Fewer than seven successful scheduled
collections or 24 successful scheduled monitors remains a finding. Failed,
cancelled and timed-out runs remain visible. A missing health receipt or truncated
history prevents automated review completion. A failed health receipt can complete
a review **with findings**, never as a successful availability claim.

`review_without_detected_operational_findings` is not a measurement of continuous
uptime or a claim of complete vendor coverage. Existing partial source failures
will yield `review_with_findings` if unresolved. Monitoring can complete an
operational evidence review; independent human sign-off is not manufactured.
