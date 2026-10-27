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

Collection runs daily at **12:43 UTC**, with manual dispatch available. GitHub can
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

The `publication-state` branch stores a recovery manifest and legacy encrypted
archives. Fernet from the maintained `cryptography` library provides authentication
and encryption. New deployments can set `IMPACT_RECOVERY_STORAGE=github-draft` to
store new ciphertext in unpublished draft release assets, leaving a small pointer
in Git. The default `git` mode remains compatible with earlier deployments.
See [draft-asset recovery](DRAFT_RECOVERY.md) for activation and rollback.
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

New backups use XZ compression before the same Fernet encryption. The public
manifest records `compression: "xz"`; older manifests without that field use
gzip and remain readable. XZ decoding has a 64 MiB memory limit, bounded output
blocks and the selected bounded expanded-vault profile (512 MiB by default). Truncated, concatenated or
trailing XZ streams are rejected. Recovery stages and checks a database privately
before linking it to a new target path; failed recovery leaves no partial target
and never overwrites an existing database.

Compression/encryption staging stays outside the tracked state tree. The workflow
authenticates all current ciphertext copies and checks the manifest before its
Git commit; filenames alone are insufficient. Each collection also restores its
new backup to a temporary private database and checks integrity before reporting
`private_recovery: verified`. This exercises the written format on that runner.
Earlier encrypted history remains retained. In `git` mode the current directory
keeps three copies; draft mode preserves those legacy files and retains new assets
without automatic deletion. Key custody is unchanged. The draft path downloads and
restores the newly uploaded object before advancing the manifest, rather than
checking only the local pre-upload copy.

The validation-only CLI is:

```sh
python ops/hosted_job.py --state-dir state --encrypted-state --validate-encrypted-state
```

It reads the dedicated key from the approved environment, performs no collection
or publication, and reports only authentication status. Draft recovery also needs
`GH_TOKEN` and an explicit `--recovery-repository OWNER/REPO` (or the runner's
`GITHUB_REPOSITORY`); it downloads the current ciphertext privately to authenticate
it alongside all retained legacy copies. The workflow runs it before committing
the recovery manifest. Do not run it against hosted state from an unapproved
local environment.

For compatibility export or a deliberate rollback to a pre-XZ collector, use the
current helper with `--backup-compression gzip`, or call
`backup(state, database, encryption_key, compression="gzip")` in an approved
private recovery environment. Older collector code cannot read XZ backups.
Restore and audit with the current helper first; retain a known-good compatible
copy before changing the source pin. A pre-draft-storage helper cannot follow a
remote pointer; use the current helper's `--recovery-storage git` to materialize a
compatible local archive before rolling back code. Never put the key in command
arguments.

Restore a prior encrypted archive using the protected key and the hosted restore
helper, audit it, then test a collection before replacing the current state manifest.
Never paste the key in an issue, shell argument, log or source file. The repository
state is not an off-provider disaster-recovery copy; retain an independent protected
copy of the key and required archives using the operator's approved backup storage.

The standard profile allows 512 MiB uncompressed; an explicit large profile allows
1 GiB. Both keep the 50 MiB per-archive limit. Monitor branch/repo
size and use draft assets or a persistent-host/object-store deployment before
continued Git snapshots approach the review budget. Removing old working-tree copies does not erase public Git history;
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

## Initial reliability observation

The six-hour monitor also writes an Actions job summary covering the last seven
days of collection/monitor workflow outcomes, scheduled versus manual runs,
elapsed observation time and repository storage budget. Workflow success is not
continuous uptime and may include partial source failures. The initial review
cannot be completed until seven real days have elapsed; its due time is reported
by `checks/operations_report.py`. A 512 MiB repository-size budget triggers operator
review without deleting history automatically.

## Capacity and cadence follow-up

The standard expanded-vault limit remains 512 MiB; an explicitly selected
`large` recovery profile supports 1 GiB with the same archive and decoder bounds.
The writer and monitor share `IMPACT_VAULT_PROFILE`. See [Capacity](CAPACITY.md)
for measurement, activation and downgrade limits. The public workflow cadence and
separate activation anchor are documented in [Scheduled reliability](SCHEDULE_RELIABILITY.md).
Current observations must not be replaced by manually generated success.
