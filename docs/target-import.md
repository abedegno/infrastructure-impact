# Exact Cisco/Aruba target import

The installed `campus-switching-public-gap-2026-11-07-v1` profile contains exactly
174 pinned documents: 173 Cisco CSAF advisories and one Aruba text bulletin.
This operator CLI adds no HTTP API. Discovery URLs are provenance; only the
manifest's exact fetch URLs may be requested. The profile cannot be replaced by
an operator-supplied manifest or repurposed Arista refresh.

## Local preview and stage

Use a checkpoint with no nonempty WAL or rollback journal. Preview copies it
without opening the source through SQLite, migrating, taking the writer lock,
making HTTP requests or writing to the source vault. It binds latest records,
all vendors' latest source selections and referenced facts, exact-target cache
and observation state, installed source configuration, manifest and normalizers.
Changing a bound input requires a fresh preview.

```sh
impact target-import preview --database "$collector_home/data/intel.sqlite3" \
  --profile campus-switching-public-gap-2026-11-07-v1 --output "$preview_receipt"
impact target-import stage --database "$collector_home/data/intel.sqlite3" \
  --home "$collector_home" --profile campus-switching-public-gap-2026-11-07-v1 \
  --preview "$preview_receipt" --output "$new_stage" --base-path /infrastructure-impact/
```

Preview output and stage output must not exist and must not overlap the database,
its sidecars or symlinked paths. Stage output must be outside the lock home.
The canonical lock pair is `--home HOME` and `--database HOME/data/intel.sqlite3`.
A custom database path also requires explicitly set `IMPACT_HOME` and
`IMPACT_DATABASE` matching both supplied paths. The CLI never reads an operator
source configuration to infer ownership. `--base-path` defaults to `/`; a custom
prefix consists only of slash-delimited letters, digits, underscores or hyphens
with both leading and trailing slashes. It controls rendering, independently of
the logical preview binding.

Stage validates the full accepted preview and rechecks its binding on a private
copy under the shared collector lock. It validates every target before ingesting
any of them. Source SHA drift, advisory/CVE disagreement, an existing conflicting
identity or selected representation, source-access failure, or an exhausted
budget rejects the batch. A pinned-source drift requires evidence review and a
separately reviewed manifest change; there is no fallback, alias inference or
force option. Existing rows, exclusions, pending reviews and unrelated source
errors remain preserved. Only exact fetch-URL HTTP cache rows may update during
genuine acquisition; this exception does not permit rewriting old evidence.

Limits are 3,000,000 bytes per document, 40,000,000 distinct input bytes including
cached content, 80,000,000 received body bytes including retries/errors/partial
responses, two attempts per target and 348 attempts total. All redirects are
refused. Attempts are sequential and spaced by at least one second; ordinary
25-second transport timeout and retry classification remain in force. Reaching
the received-byte cap without proven EOF is refused. These are acquisition
bounds, independent of the hosted 40-minute job timeout.

Stage writes only a new private laboratory tree:

- `private/data/intel.sqlite3`: disposable staged database;
- `private/home/`: bounded worker request/context/result, private diagnostics,
  reports and intermediate publications;
- `public/`: candidate public files if construction reaches that phase;
- `result.json`: CLI receipt when the stage directory was created; stdout always
  carries the operational receipt when staging returns normally.

The installed fresh-interpreter worker receives explicit staged paths, the
trusted base path and bounded parent-authored profile metadata before application
imports. It audits, builds the whole candidate, verifies provenance, JSON/CSV and
full-bundle parity, then runs the installed byte-identical standalone monitor
pair over public-only loopback HTTP. Node is optional at runtime. Loopback
validation has its own unchanged budgets and is not vendor acquisition traffic.
The expanded archive limit remains 128,000,000 bytes, compressed archive
8,000,000 bytes, and default monitor traffic 20,000,000 bytes. Total public bytes
are measured separately. Capacity failure is a release blocker; never raise a
limit or drop evidence to turn rejection into acceptance.

Exit status is `0` for preview or completed stage, `1` for failed stage or lock
contention, and `2` for malformed input/parser errors. Inspect the overall
`outcome` and `failure_code`, not only per-target imported counts. Failed output
has null accepted database/public paths even if diagnostic files exist. No local
stage promotes recovery or publishes. A completed result requires a non-null
passed candidate summary and every audit/capacity/parity/monitor gate. The single
scoped pipeline row describes ingestion timing and counts; candidate acceptance
is the separate stage result. On candidate failure only that new isolated row
is marked failed. Preview/final JSON receipts include their newline in the
2,000,000-byte bound and are never silently truncated.

Keep stage databases, raw captures, worker logs and operator receipts outside Git
and release exports. Receipts expose factual target metadata but no machine paths
or raw evidence. Treat the entire stage as private operator state; only the
validated public subtree is suitable for the existing publication process.

## Opt-in local publication v2

Local `snapshot` and `target-import stage` accept `--publication-format v2`.
The default remains `v1`; there is no environment setting or hosted activation
for this option. Use the same preview, ownership and stage arguments above and
add the format flag to the stage command. A different representation does not
waive any audit, native parity, monitor or capacity gate.

V2 publishes `publication-v2.json`, content-addressed bounded parts and a
self-contained `snapshot-v2.json.gz`. The archive reconstructs every field in
the original full snapshot's scope. Full research evidence and comparison
inputs remain mandatory logical roots in the publication; they are not silently
added to or removed from that archive scope. The catalog lists those roots and
binds their ordered logical bytes to hashes.

Browser JSON downloads are selected summaries. To export complete research
inputs without materializing the whole document, use a new output file outside
the publication directory:

```sh
impact publication-export --publication "$candidate_public" \
  --root switching-evidence.json --output "$new_json_export"
```

`switching-comparison.json` and `snapshot.json` are also available as logical
root names. Root exports enforce a 1,000,000,000-byte logical ceiling and a
300-second operation deadline. Selected materializations remain bounded to
128,000,000 bytes, including requested encoding expansion. Exporting a logical
root can therefore succeed when loading it as one in-memory object would fail.
Browser cohort reconstruction also budgets intermediate ordinary-part envelopes
and rows. This conservative allowance can reject a selection whose final
deduplicated JSON would be smaller than the limit; rejection remains explicit,
and complete logical roots remain available through streaming export. The
existing archive, part, index, default-read and complete-site limits remain
unchanged. No local v2 result certifies the distinct hosted inventory or enables
publication automatically.

## Retrieval, replay and activation

Normal stage performs fresh bounded source acquisition, which records actual
HTTP observations separately from retained capture dates. Offline acceptance
may replay verified retained bytes through current normalizers in a disposable
lab; it must preserve original capture dates, add no HTTP successes and explicitly
say **offline retained evidence**. The public CLI has no offline acquisition
switch. Authored synthetic distribution tests do not certify real sources.

Source review/merge, source release, runtime source-pin activation, authenticated
hosted preview, exact-profile apply, recovery readback and publication/monitoring
are separate gates. A local fingerprint is never a hosted fingerprint. Hosted
apply obtains a fresh disposable authenticated preview, checks the requested
fingerprint, passes the full preview to core stage, then checks staged vault
capacity before verified backup/readback and public copy readiness. Failures
before backup do not promote rejected state. A public-copy failure can truthfully
leave verified recovery saved while publication remains unready. The existing
workflow controls, helper compatibility, schedules and permissions are unchanged.

The local public research stage is not the complete 966-record hosted inventory.
Its measurements cannot certify the proposed 1,140-identity hosted union. The
rough 141 MB union warning is an estimate, not a measured complete candidate.
Complete authenticated hosted union validation remains a separately authorized
check; do not reconstruct missing raw histories from public snapshot rows.
Independent human review, partial-history caveats, source conflicts and fair
vendor-rate prerequisites remain unresolved by this import. See the
[dated acceptance record](research/2026-11-07-exact-target-import-acceptance.md).

The closed Pages-target import route also rejects a complete public file tree above
1,000,000,000 bytes, before artifact inspection or recovery promotion. This is a
conservative enforcement of the existing GitHub Pages site-size limit; the
receipt retains generation and byte measurements on rejection. It does not
change the other archive, part, index or monitor budgets.
