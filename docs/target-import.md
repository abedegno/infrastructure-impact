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
bounds, independent of the 40-minute worker bound and the 60-minute outer
hosted job allowance.

Stage writes a new private laboratory tree and durable private capture state
under the collector home (or an explicitly supplied cache path):

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

See the [retained-data runtime and paging checks](research/2026-11-08-runtime-and-paging-verification.md)
for the measured query improvements and optional indexed source/diagnostic pages.
Existing publications remain readable through the fallback path.

Local `snapshot` and `target-import stage` accept `--publication-format v2`.
The default remains `v1`; library calls select the format explicitly rather than
reading an environment setting. Use the same preview, ownership and stage arguments above and
add the format flag to the stage command. A different representation does not
waive any audit, native parity, monitor or capacity gate.

The hosted helper also accepts an explicit format flag. Hosted selection is
default-off and requires the separately reviewed source and persistent workflow
setting described in [Hosted service](HOSTED_SERVICE.md#publication-format-selection).
Preparing this support does not activate a hosted import.

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
deduplicated JSON would be smaller than the limit. Native study reducers also
reserve intermediate construction space before growth, then check final output
size separately. These conservative guards can reject below final JSON-only
capacity; rejection remains explicit, and complete logical roots remain
available through streaming export. The existing archive, part, index,
default-read and complete-site limits remain
unchanged. No local v2 result certifies the distinct hosted inventory or enables
publication automatically.

## Retrieval, replay and activation

Local stage defaults to `HOME/captures/PROFILE_FINGERPRINT.sqlite3` under
`--home`; `--capture-cache PATH` selects a different private cache file outside
the source database and stage output. Successful exact URL/SHA captures persist
under the collector lock even when later target acquisition or candidate gates
fail. A retry reuses verified bytes through current normalizers without
inventing a new HTTP observation or changing the original capture time. The
cache holds raw private evidence, not accepted normalized results; every stage
still validates all targets and the complete candidate before acceptance.
A retained capture can also be reused from the source vault. Missing captures
require fresh bounded source acquisition, which records actual HTTP observations
separately from retained capture dates.

The hosted helper's `--acquisition-cache` is an explicit opt-in restricted to
exact target-import apply with `--encrypted-state`. It restores and checkpoints
a separate encrypted acquisition recovery stream; rejected candidates gain no
accepted-vault recovery or publication readiness from these captures. Without
that flag, a hosted run may reuse its local captures during that runner's
lifetime, but they are not backed up for subsequent runners. The collector
workflow exposes the manual boolean `acquisition_cache`, defaulting to false;
scheduled runs always leave it disabled. Enabling it requires a named installed
target-import profile in explicit apply mode and a pinned helper advertising
`--acquisition-cache`. Protocol preflight rejects other requests before the
state key or repository token is made available to the helper.

Encrypted acquisition checkpoints live in the separate sibling tree
`acquisitions/PROFILE_FINGERPRINT/`, alongside accepted `state/`. Retention can
run after a rejected apply with `acquisition_ready=true`, but first authenticates
the accepted recovery manifest and every acquisition sub-state with the pinned
helper. Only managed 64-character lowercase hexadecimal profile directories
containing encrypted archives and their manifest may be staged; links, plaintext
and unexpected entries fail retention. Acquisition readiness alone authorizes
neither accepted recovery nor public artifacts or Pages publication. This wiring
does not activate a new source pin or dispatch an import; source-pin approval,
a hosted preview and an explicit apply remain separate activation steps.

Offline acceptance
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
change the other archive, part or index budgets. The opt-in local v2 monitor uses
a 32 MB default-download safety ceiling; v1 retains 20 MB. This download budget
is separate from GitHub Pages' site-size limit. Further compression is deferred
once the complete candidate fits, so import correctness and coverage take priority.

## Manual full hosted certification

The maintainer approved installation and a read-only certification run on
8 November 2026. `.github/workflows/candidate-certification.yaml` is the manual
workflow; keep it byte-identical to the canonical copy at
`deploy/github-candidate-certification.yaml`. It has no schedule and does not
publish or promote a candidate. It inherits the existing recovery vault profile
(`IMPACT_VAULT_PROFILE`, currently `large`) rather than using a different restore
limit.

The first two hosted attempts failed before staging: GitHub returned HTTP 403
while restoring the draft recovery release. GitHub documents that viewing draft
releases requires push access ([release API documentation](https://docs.github.com/en/rest/releases/releases#list-releases)).
The proposed workflow therefore requests `contents: write` solely to read that
private draft, plus `actions: read` for optional capture reuse. This is a
write-capable credential even though the workflow performs no remote writes.
**Activation of this broader permission requires separate maintainer approval.**
The installed main-branch workflow remains read-only until that approval.

After permission approval, to run the check:

1. Review the proposed source commit and installed workflow. The proposed
   `contents: write` and `actions: read` permissions must have been explicitly
   approved. The existing `IMPACT_STATE_KEY` secret and `publication-state`
   accepted pointer must be available. The GitHub token is passed only to the
   recovery download and optional prior-artifact download steps; the stage step
   receives neither that token nor the recovery key. Checkout credentials are
   not persisted. There are no recovery promotion or Pages deployment steps.
2. In Actions, select **Certify full hosted candidate**, then **Run workflow**.
   Enter the reviewed full 40-character lowercase hexadecimal `source_commit`.
   Leave `previous_capture_run_id` blank for normal exact acquisition on the
   first run. The source commit must include this CLI and hosted helper support.
3. To reuse a prior certification's captures, enter that run's numeric ID while
   its `candidate-certification-captures` artifact remains available (14 days).
   Download or authentication failure rejects the run; it never silently falls
   back to fresh acquisition. Each cache lookup rehashes bytes against the fixed
   installed profile's target SHA before reuse.
4. Review the workflow conclusion and `candidate-certification-result` artifact.
   Only a successful stage with `outcome: completed` certifies the full restored
   hosted baseline plus `campus-switching-public-gap-2026-11-07-v1` under the
   explicit v2 format and `/infrastructure-impact/` base path. A failed job and
   its failure code/timings identify a blocker, not an accepted candidate.

The job restores accepted encrypted state to a temporary private home, previews
that exact inventory, and stages a new isolated candidate through the existing
full audit, capacity, parity and standalone monitor gates. This measures the
complete authenticated hosted inventory; a smaller local research sample cannot
establish those facts. Source commit and preview fingerprint bind the result to
that run, not future accepted checkpoints.

Capture persistence is a separate encrypted **acquisition** checkpoint, produced
with the existing local backup/authentication/readback facilities after stage,
including a failed stage when a cache exists. It never replaces accepted recovery.
Only that encrypted directory and a separate bounded, allowlisted result summary
(including validated acquisition counters, checks, phase resource measurements
and terminal worker classification when emitted) are uploaded. Plaintext
SQLite files, publisher bytes, worker logs, full receipts and the candidate tree
remain private temporary files. A hard kill before the always-run checkpoint
step can lose new captures; cancellation and runner loss cannot guarantee an
artifact. Metadata may be absent if execution fails before stage.

Installation or a passing certification does not change the live runtime source
pin, accepted recovery, publishing workflow, schedule or live permissions. Source
activation and any promotion/public deployment still require separate approval;
this template contains no promotion or publication step.
