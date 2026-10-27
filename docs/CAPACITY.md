# Evidence-vault capacity and recovery profiles

Retained evidence, normalized revisions and change details all contribute to vault
size. Measure them before choosing a capacity change:

```sh
impact audit --storage
```

This command uses a read-only snapshot and reports page/free-page bytes, row counts
and encoded payload lengths for fixed application fields. It returns no source
bodies, URLs, review values or arbitrary extension-table contents. Logical payload
bytes are separate from physical SQLite size: they exclude indexes, row overhead
and unlisted columns. A zero free-page count means `VACUUM` cannot be assumed to
recover meaningful space. No command here deletes or compacts evidence.

Hosted backups now record the same aggregate `storage_profile` alongside their
existing sizes and fingerprints. These metadata help distinguish retained source
bytes, repeated normalized revisions and change details. They are operator
accounting, not public CVE evidence or a content-authenticity certificate.

## Explicit bounded profiles

| Profile | Maximum expanded SQLite vault | Default |
| --- | --- | --- |
| `standard` | 512 MiB | Yes |
| `large` | 1 GiB | No; explicit operator choice |

Both retain the existing 50 MiB encrypted archive limit, 64 MiB XZ decoder memory
limit, bounded output blocks, authentication, SQLite integrity checks and atomic
restore. Repository storage review remains at 512 MiB. Expanding a vault profile
does not remove those separate warnings or reclaim legacy Git history.

A trusted operator selects a profile with `--vault-profile standard|large` on
`ops/hosted_job.py` and `checks/backup_storage.py`. The hosted workflows share the
repository variable `IMPACT_VAULT_PROFILE`, defaulting to `standard`. The manifest
records `vault_limit_bytes` for audit; it cannot enlarge the caller's selected
restore bound. Unknown profiles and budgets above 1 GiB are rejected.

For an approved recovery environment:

```sh
python ops/hosted_job.py --state-dir state --encrypted-state \
  --vault-profile large --recovery-repository OWNER/REPO \
  --restore-only /private/recovery/new-vault.sqlite3
```

Choose `large` only after checking ephemeral disk headroom for the live vault,
backup staging and independent restore checks. Archive size must still fit the
unchanged 50 MiB bound. This offers bounded headroom for the current single-writer
service; it is not unlimited retention or a replacement for object storage.

Once a checkpoint exceeds 512 MiB, an old/default-standard recovery helper will
refuse it. Keep a profile-capable helper with the required profile during rollback.
The SQLite schema and gzip/XZ/Fernet formats are unchanged; no source bytes,
revisions, capture times or recovery history are removed or re-encoded.

## Capacity decision — 27 October 2026

The inspected hosted checkpoint used 457,003,008 bytes (85.1% of the standard
profile), while its encrypted XZ archive was 18,547,724 bytes (35.4% of its existing
per-archive limit). Native read-only profiling also showed that normalized
revisions plus change details exceeded raw-capture bytes. These are different
corpora; the native breakdown is not substituted for hosted measurements.

The chosen immediate design is an explicit `large` profile plus retained storage
profiling. This preserves the data representation and recovery format while
providing headroom for the service observation period. Transparent payload
compression or external source-object storage needs a separate migration design,
backward-reader handling and byte-equality recovery tests. No historical data or
Git objects are deleted to make the current budget pass.

The first hosted run using `large` completed authenticated recovery readback at
11:55:52 UTC on 27 October 2026. Its database was 465,190,912 bytes (43.3% of
1 GiB), and its encrypted archive was 18,891,044 bytes. Hosted payload accounting
measured 266,845,605 raw-capture bytes and 179,411,489 normalized-revision bytes;
raw captures were the largest selected payload in that corpus. Free-page bytes
were zero. This is a checkpoint measurement, not a growth-rate forecast or an
independent operator recovery exercise.

The monitor continues to warn at 80% of the selected vault limit and tracks the
repository and archive budgets separately. Growth from archive backfill and
repeated current-source captures can differ; a few manual deployments cannot
establish a reliable daily growth rate or exhaustion date.

See [Draft recovery](DRAFT_RECOVERY.md), [Operations](OPERATIONS.md) and
[Hosted service](HOSTED_SERVICE.md).
