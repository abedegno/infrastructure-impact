# Retained switching fix preview and activation

PR54 merged as `1233ff93e0da27b8b2af8e36913b25caf3739a53`. The switching
research input is reconstructed from retained raw bytes by `query.state()` during
`publication.build()`. These fixes therefore need a new publication, with
`reparse_limit=0`; a core advisory reparse is unnecessary.

The default target-import certification remains available. The manual
`candidate-certification.yaml` workflow adds `retained_only` (boolean, default
`false`). Set it to `true` and provide the exact reviewed 40-character lowercase
`source_commit`. Leave `previous_capture_run_id` empty; combining it with
retained-only mode fails before checkout or authenticated restore.

After the existing private authenticated restore, retained-only mode skips
acquisition, import preview/staging, capture checkpointing and capture upload. It
runs the fixed offline helper through `ops/retained_preview_progress.py` without
recovery or GitHub credentials, with a 40-minute
step timeout matching the existing worker budget, then uploads only
the existing bounded `candidate-certification-result` artifact. The workflow does
not promote recovery, change the runtime source pin, or upload/deploy Pages.

## Offline helper

For an already restored private disposable database, the exact helper interface is:

```sh
python ops/switching_fix_preview.py \
  --database "$RUNNER_TEMP/private-home/data/intel.sqlite3" \
  --public "$RUNNER_TEMP/private-retained-public" \
  --output "$RUNNER_TEMP/retained-preview-result.json" \
  --source-commit "$SOURCE_COMMIT"
```

`preview(database, public, source_commit)` returns an ordinary dictionary;
`receipt_bytes(value)` freshly validates and encodes its closed metadata contract.
The CLI creates a new receipt file and exits nonzero for failure. Keep all input,
public-preview and log files private; only the sanitized metadata artifact is for
review. No caller manifest, source URL or alternate registry is accepted. The
helper establishes its own home, database and packaged source settings before
application imports, and removes credentials from its execution environment.

For each of the eight packaged reviewed-remediation sources, the helper uses
successful retained observation chronology (including A→B→A), hashes the actual
bytes, and requires a matching normalized source representation. Missing
normalization fails closed; the helper does not invent a representation or fetch
one. CSAF sources require their packaged complete-byte pins. HTML sources require
the registry's exact source identity, source format, affected tuples and owned
resolution clauses. Planned/contradictory fixes and source drift fail closed.
The known unchanged truncated affected context for Arista
`24074-security-advisory-0140` / `CVE-2026-10040` can pass only as fixed-only:
its unique original fixed sibling and single remediation must independently pass
the registry's exact ownership checks, and both baseline and current affected
claims must have zero remediations/events. The truncation issue remains intact.
A missing, duplicate or forged original, changed affected fields or attempted
copied fix fails. Other truncated affected contexts fail closed. Complete
untruncated 0140 claims use the ordinary validated-link path.

The old/new comparison uses the same bytes, normalized document and retrieval
lineage. The feature baseline disables only `apply_csaf` and `arista_assessments`;
it is **not a reproduction of the whole historical runtime**. Every original
affected field remains equal except approved added remediations and derived claim
IDs. Existing remediations remain intact, and additions must pass the registry's
cross-claim ownership validator.

The helper builds one complete v2 candidate from the read-only database. It freezes
the query/source-audit evaluation clock as the existing worker does, then reuses
SQLite/content audit, physical inventory inspection, default/archive loopback
monitors and native parity. Existing byte budgets and the
`/infrastructure-impact/` base path apply. The full database hash must remain
unchanged. No vendor transport, collection, ingestion or reparse occurs; loopback
monitor HTTP is the only network operation.

## Metadata contract

The helper receipt is at most 65,536 UTF-8 bytes, with no unrecognized fields:

- `schema_version: 1`, exact `source_commit`, `outcome` (`passed` or `failed`),
  and a closed `failure_code`.
- `network_requests: 0` (source/external requests), `revisions_written: 0`, and
  `database_unchanged`.
- `sources`: vendor/advisory/official URL, actual SHA-256, retrieval timestamp,
  `affected_fields_unchanged`, and `before`/`after` counts of claims, affected
  CVEs, fixed CVEs and reviewed links. No source bytes or extracted prose.
- `gates`: the existing strict v2 worker gate facts, including audit/capacity,
  generation and manifest identity, measured bytes, both monitor results and
  parity.
- `cohort`: compact validated-reader counts for Cisco, Aruba and Arista:
  advisories, affected CVEs, claims, remediation events and fixed-only claims.

Failure codes are `database_missing`, `database_changed`, `source_missing`,
`source_drift`, `affected_changed`, `audit_failed`, `candidate_failed`, and
`capacity_failed`; only success uses `none`. Exceptions, raw normalized objects,
private paths and source prose never enter the receipt.

The existing artifact's `result.json` embeds a receipt only after fresh validation
and exact source-commit matching, under `retained_preview`. Its
`retained_receipt_status` is `valid`, `invalid` or `missing`; `retained_step`
preserves the workflow step outcome. Malformed, oversized or unsafe receipt
metadata yields a bounded invalid status. Private preview logs are never copied
into this artifact. Default target-import receipt handling is unchanged.

## Bounded diagnostic supervision

The retained-only workflow uses the following fixed driver interface (the direct
helper interface above remains available without instrumentation):

```sh
python ops/retained_preview_progress.py \
  --database "$RUNNER_TEMP/private-home/data/intel.sqlite3" \
  --public "$RUNNER_TEMP/private-retained-public" \
  --output "$RUNNER_TEMP/retained-preview-result.json" \
  --source-commit "$SOURCE_COMMIT" \
  --progress "$RUNNER_TEMP/retained-preview-progress.json"
```

The driver accepts no command or alternate worker. It launches only its sibling
helper with the current Python executable and internal diagnostic opt-in. Worker
stdout and stderr stay in a private temporary directory; only fresh closed
metadata appears in driver notices. Cancellation terminates the owned worker,
then kills and reaps it if necessary. The 40-minute step and 60-minute job limits
remain unchanged.

`retained.sources` and `retained.audit` bracket source proof and audit. The
existing publication phases retain their meanings. An opt-in worker thread
samples its own main Python thread every 30 seconds, at most 80 times, reading
only code filename and line number. Trusted public first-party package/allowlisted
ops code and installed `jsonschema` Python files map to relative paths with line
bounds. Every other frame becomes `external`, line 0. No values, function names,
source text or arbitrary log text enter progress.

The parent reads at most 65,536 private log bytes per poll. It rejects unknown
fields and events, deduplicates phase/state pairs and refreshes one cumulative
top-three sampled-location aggregate at most every 120 seconds, plus a final
flush. Progress holds at most 32 events; one slot is reserved for samples. At
most 32 bounded notices are emitted, while the private progress file stays
current. `progress_bytes(value)` freshly validates the closed
`{schema_version: 1, events: [...]}` form before notices, atomic writes and
artifact projection; the file is at most 16,384 bytes. Existing, symlinked,
hardlinked, stale or oversized progress files fail closed. Progress never writes
or substitutes for the helper result.

The existing artifact adds `retained_progress` only after fresh bounded validation
of the private progress file. A missing or invalid progress file adds no progress.
Only the complete validated helper receipt and mandatory gates establish preview
acceptance. Partial diagnostics do not authorize activation or publication.

## Pending activation

1. Merge the reviewed preview implementation, then dispatch
   `candidate-certification.yaml` with `retained_only=true` against that exact
   merged source commit and no prior-capture run.
2. Inspect only `candidate-certification-result` locally. Require the step and
   receipt to pass, all eight source proofs/counts, unchanged affected fields and
   database, all candidate gates, and full-cohort counts. For known truncated
   0140, require its authenticated fixed-only state and zero affected copies/events;
   other rejected/truncated sources remain blockers. Do not weaken the registry
   or sanitizer to pass them.
3. Confirm no collector is active before activating that tested source pin.
   Dispatch ordinary collection with `reparse_limit=0` through the existing
   activation path.
4. Verify the new live public generation, affected counts, source errors,
   source-bound fix history, and JSON/CSV exports. Record actual hosted and live
   evidence separately; implementing this helper does not claim activation.
