# Hosted public service

Public dashboard: https://abedegno.github.io/infrastructure-impact/
Source repository: https://github.com/abedegno/infrastructure-impact

The active deployment uses public GitHub Actions runners. A reviewed source commit
is pinned by repository variable `IMPACT_SOURCE_COMMIT`. The writer starts from
its own hosted state, collects official public sources, audits evidence, creates an
authenticated encrypted recovery copy, and deploys **only the sanitized publication**
to GitHub Pages. The maintainer's existing local research vault and notes are not
uploaded or used to seed the hosted service.

## Scheduling and monitoring

Collection runs daily at **08:37 UTC**, with manual dispatch available. GitHub can
delay scheduled jobs; the cadence is not an availability SLA. A separate monitor
checks public HTML, snapshot age (36-hour threshold) and the checksum manifest
every six hours. Actions failures are visible to maintainers; notification delivery
uses their existing GitHub settings. No Slack or email integration is configured.

The UI supports cohort filtering and JSON/CSV exports in the browser. It also serves
`snapshot.json`, `catalogue.json`, `benchmark.json`, the schema and source fingerprint
JSON. **Pages is a static reader**: it does not run Python or implement the Python
reader's query-string REST routes. Use Compose on a persistent host for a live REST
query service. Neither public deployment exposes plaintext source bytes, the vault
or private review notes.

## Encrypted backups and recovery

The public `publication-state` branch stores only encrypted backup archives and
public manifests. Its three current compressed SQLite recovery copies use Fernet
from the maintained `cryptography` library, providing authentication and encryption.
`IMPACT_STATE_KEY` is a dedicated Actions secret, never a committed file or Pages
artifact. A local recovery copy is retained outside Git. Losing the key prevents
recovery; compromise could expose encrypted history. Keep a protected recovery
copy and plan key rotation deliberately. Ciphertext sizes and timestamps are public.
This is not forward-secret storage.

Restore verifies archive fingerprints, authenticates/decrypts before processing,
limits decompression and checks SQLite integrity. Public-runner mode rejects
plaintext backups and refuses to run without its key. Backup state and public output
must be separate directories. The workflow uploads only the sanitized output.
A failed collection keeps its evidence encrypted and does not replace the public
site when all source checks failed. Corrupt or missing recovery metadata requires
manual recovery; it is not silently replaced with an empty vault.

Restore a prior encrypted archive using the protected key and the hosted restore
helper, audit it, then test a collection before replacing the current state manifest.
Never paste the key in an issue, shell argument, log or source file. The repository
state is not an off-provider disaster-recovery copy; retain an independent protected
copy of the key and required archives using the operator's approved backup storage.

Storage limits are 512 MiB uncompressed and 50 MiB per archive. Monitor branch/repo
size and migrate to persistent-host or object-storage backups before growth reaches
platform limits. Removing old working-tree copies does not erase public Git history;
previous ciphertext remains retrievable and key rotation must account for it.

## Operate and update

Active workflows are `.github/workflows/collect.yaml` and `monitor.yaml`, with the
reusable public-runner template in `deploy/github-public-service.yaml`. Collection
triggers are schedule/manual dispatch, not pull requests. Only trusted maintainers
should modify these workflows, the source pin or Actions secrets. Update the pin
after source CI passes, manually dispatch collection, and verify public freshness.
The workflow uses its built-in repository-scoped GitHub token, not a personal token.

`deploy/github-service.yaml` remains a private-repository alternative. The separate
private service repo was configured, but its jobs were blocked by account billing
or spending limits and are disabled. Billing settings were not changed. Do not
interpret that alternative as the active service.

The Mac research schedule retains its own local vault and remains independent.
Existing private Sites previews are separate and unchanged.
