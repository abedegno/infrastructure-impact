# Hosted public service

Public dashboard: https://abedegno.github.io/infrastructure-impact-service/
Source repository: https://github.com/abedegno/infrastructure-impact

The deployment uses a separate **private** service repository. A pinned, reviewed
source commit supplies the collector. GitHub Actions restores its private vault,
collects official sources, audits evidence, creates an online compressed backup,
commits that state privately, then deploys **only** the sanitized publication to
GitHub Pages. No personal access token is stored in the workflow; its built-in
GitHub token is scoped to the service repository.

Collection runs daily at **08:37 UTC**, with manual dispatch available. GitHub can
delay scheduled jobs; the cadence is not an availability SLA. A separate scheduled
monitor checks the public HTML, snapshot age (36-hour threshold) and checksum
manifest every six hours. Failed Actions runs are visible to service maintainers;
notification delivery follows their existing GitHub notification settings.
No Slack or email integration is configured by this project.

The public UI supports cohort filtering and JSON/CSV exports in the browser. It
also serves `snapshot.json`, `catalogue.json`, `benchmark.json`, the schema and
source fingerprint JSON. **Pages is a static reader**: it does not run Python or
provide the Python service's query-string API routes. Use the documented Compose
reader on a persistent host when a live REST query service is needed. Neither
public deployment exposes raw source bytes, the private database or review notes.

## Backups and recovery

Private state keeps three current compressed SQLite recovery copies plus their
private Git history, with a SHA-256 manifest. Restore validates the archive hash,
limits decompression and checks SQLite integrity before collecting. The state and
public output directories must be separate. A failed collection retains evidence
privately and does not replace the public site when all source checks failed.
A damaged backup requires deliberate recovery from a prior private commit; it is
not silently discarded in favor of an empty vault.

The repository-backed vault is an initial deployment with explicit storage limits:
512 MiB uncompressed and 50 MiB per archive. Monitor private repository size and
migrate to persistent-host/object-storage backups before growth approaches platform
limits. Private Git history is retention, not an off-provider disaster-recovery
copy. Use the Compose backup/recovery procedure for independent archival storage.

## Operate and update

The templates are `deploy/github-service.yaml` and `deploy/github-monitor.yaml`.
Install them only in a private service repository with Pages enabled. Set repository
variable `IMPACT_SOURCE_COMMIT` to a reviewed full source commit. The writer refuses
a public service repository; never upload `state/` as a Pages or Actions artifact.
Update the pin only after source CI passes, then manually dispatch collection and
check publication freshness. The source repo does not itself schedule collection.

The existing Mac research schedule uses its own vault and is independent of the
hosted service. Existing private Sites previews are also separate and unchanged.
