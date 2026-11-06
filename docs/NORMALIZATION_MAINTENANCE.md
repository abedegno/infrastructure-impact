# Retained advisory normalization maintenance

A new parser does not automatically rewrite every historical record. Each retained
revision carries the code identity that produced it. Preview and apply current
normalizers to the latest retained representations without fetching sources again:

```sh
impact reparse --dry-run --limit 1000
impact reparse --vendor aruba --dry-run --limit 100
impact reparse --limit 1000
impact audit
```

Preview uses a read-only database connection, performs no migrations and does not
create a writer lock. Run migrations separately when required. Apply shares the
collector's exclusive process lock and refuses to overlap that writer. Source
configuration, the original independent-review kit and historical revisions are
not changed. Publication is a separate step.

## Selection and outcomes

The default selects latest records whose stored normalizer identity differs from
the installed vendor plugin. An earlier identity does not by itself prove that a
claim is wrong. `--force` also checks current identities. A vendor filter applies
before the bounded attempt budget. The default limit is 1,000 records; supported
limits are 1–10,000. Results report selected/current/candidate/attempted counts,
changed and unchanged results, failures and remaining candidates. Success and
failure examples are independently bounded to 20 each, with truncation flags.

Failures do not delete the previous interpretation or block independent valid
records. A missing installed vendor plugin, unsupported document, missing or
ambiguous feed identity, and a changed stable advisory identity require review.
The tool never silently creates a differently named advisory or merges aliases.
Storage read/write errors remain fatal rather than being mislabeled as source
layout failures.

Parser results without explicit CVEs must satisfy the vendor plugin's approved
unlinked-notice policy before storage. An invalid result remains a per-record
failure. Records backed by the same captured feed share one parsed index during
the invocation; different captures and source URLs remain separate. Missing or
duplicate advisory identities still require review.

The CLI returns status 1 for partial work, remaining candidates or writer-lock
contention, after printing its JSON report. This does not mean successful records
were rolled back. An apply operation appends valid revisions individually. Repeat
the preview after a batch: successfully refreshed records are skipped by default,
while unresolved records remain candidates. Use the report to review or install
the missing parser rather than treating a failed record as unaffected.

`would_reparse` counts records that differ under the current normalizer;
`reparsed_revisions` counts actual writes and stays zero in preview. The
`semantic_changes` count follows the repository's difference rules, including
provenance locators and scope context. It is not a count of new vulnerabilities,
changed exposure or publisher edits. Metadata-only code-identity updates create
no publisher-change event. Differences based on the same captured bytes are
recorded as parser reinterpretations.

## Provenance and source choices

Replay uses the exact latest retained source representation and its immutable
evidence identity. It validates fresh output under the advisory schema before
writing. Raw fingerprints, first capture times, earlier revisions and source-choice
receipts remain intact. Feed metadata is matched to its exact retained advisory
identity; unrelated feed entries cannot broaden it.

No HTTP requests, retrieval observations or collection-health successes are
created. Offline reinterpretation cannot clear an HTTP failure or make a source
fresh. Earlier HTML/CSAF comparison receipts retain their own analysis fingerprints;
they are not relabeled as fresh counterpart analysis without parsing those bytes.

## Hosted maintenance

`ops/hosted_job.py --reparse-limit N` optionally runs bounded maintenance after
recovery and before ordinary collection. Add `--reparse-vendor VENDOR` to restrict
selection to one installed vendor before applying that attempt budget. An unknown
vendor, or a vendor scope without a positive budget, fails before recovery state
is opened. Omitting the scope preserves the existing all-vendor selection.
It prints the partial/full report and
includes it in the final recovery receipt. Independently valid records can proceed
to collection and audit while unresolved records remain retained for review.

For one controlled dispatch, the workflow accepts `reparse_limit` and
`reparse_vendor` string inputs. Nonempty inputs override the corresponding
repository variables for that run only:

```sh
gh workflow run collect.yaml --repo OWNER/REPO --ref main \
  -f reparse_limit=20 -f reparse_vendor=aruba
```

The helper validates the budget and installed vendor before opening recovery
state. Use a reviewed source pin that supports both controls. Single-run inputs
leave repository variables unchanged.

For default or deliberately recurring maintenance, the workflow appends the
budget flag only when repository variable
`IMPACT_REPARSE_LIMIT` is positive; its default is `0`. Optional variable
`IMPACT_REPARSE_VENDOR` adds the vendor scope. Both workflow copies pass quoted
array arguments; an unbudgeted vendor scope is rejected rather than ignored.
First pin a CI-verified
source commit that supports the option, then set a controlled budget and dispatch
collection. Inspect the report, benchmark, audit, recovery and public output.
Reset the limit to `0` and clear the vendor variable after the maintenance pass
unless recurring replay is deliberate. The reusable workflow template has the same gate.

Hosted maintenance operates only on the runner's existing public-source vault.
Do not upload a private native vault or review worksheet to perform it. Keep the
independent human-review status and vendor comparison prerequisites pending.

## Preview-bound reviewed Arista refresh

An explicit profile refreshes only the reviewed SA-0099 and SA-0103 HTML pages
and the SA-0103 advertised CSAF counterpart. It never enumerates feeds, archives,
CVE records or KEV. Run against an explicitly selected public-source staging
vault, keeping receipts and raw captures outside Git and public output:

```sh
impact maintenance preview --database /public-stage/intel.sqlite3 \
  --profile arista-reviewed-2024-0099-0103-v1 --output /operator/preview.json
impact maintenance apply --database /public-stage/intel.sqlite3 \
  --profile arista-reviewed-2024-0099-0103-v1 --preview /operator/preview.json \
  --output /operator/apply.json
```

Both output paths must be new regular-file destinations with no symlink
components. Preview uses a read-only consistent database snapshot, performs no
migration or HTTP request, and creates no writer lock. Its fingerprint binds the
ordered latest record inventory, normalized payload digests, relevant latest
selection facts, and installed profile, policy and normalizer identities. Its
observation time does not affect the binding. This is a consistency check, not
file authentication. Missing retained inputs appear as bounded issue codes.

Apply validates the closed preview receipt before opening the writer database,
then owns the same single process lock as collection. A changed latest revision,
normalized payload, source selection, or installed identity requires a new
preview; refusal happens before HTTP. The core `apply_profile` function expects
its caller to own that lock and does not acquire a nested lock.

Retrieval is limited to the three exact profile URLs, including every redirect,
with an inclusive 2,000,000-byte per-document bound and the existing two-attempt
transport limit. Each approved URL has one invocation cache entry for either
bytes or failure. Both HTML primaries must independently validate their exact
advisory identity and CVE set before any normalized write. SA-0099 retains
CVE-2024-27890 and CVE-2024-27892; SA-0103 retains CVE-2024-6858. The fetched CSAF
must independently prove the expected literal CVE-2023-5501 scope conflict during
this invocation. A prior retained proof cannot hide a current HTTP or layout
failure. No CVE identity is renamed or transferred between representations.

Only `outcome: completed` accepts cleanup: it requires successful primary imports
or unchanged results plus the reviewed policy's actual exclusion decision and no
unresolved proof issues. With no exact reviewed legacy CSAF record in the vault,
valid primary imports can still append, but the result is `failed_cleanup_proof`;
zero exclusions never establish cleanup. A failed primary or alternate validation
writes no normalized revisions. Source captures and failure observations may
remain. Later storage failures return `failed_storage`; already committed
independent revisions remain and require a fresh preview before retrying.

Receipts contain primary and alternate outcomes, import/unchanged counts, before
and after record keys, public decisions and proof fingerprints. They contain no
source bodies or private policy context. `validate_receipt` and `receipt_bytes`
provide the strict local apply-receipt boundary; decision counts over 1,000 or
serialized receipts over 2,000,000 bytes fail instead of truncating. CLI apply
returns 1 for failed cleanup or writer contention; its contention receipt has
only `outcome: skipped_writer_lock` and the profile ID. No publication, hosted
operation, release, source-pin activation or schedule change is performed by
these commands.

To keep preview strictly free of input-vault writes, it reads a disposable copy of
an operator-provided stable, checkpointed database. It checks source file
identity, size and modification/change times and journal presence before and
after one streaming copy; concurrent changes fail without retrying or waiting.
A nonempty WAL or rollback journal is rejected with
`maintenance_checkpoint_required`. Provide a consistent checkpointed backup of a
live vault before previewing it. Preview never opens the source with SQLite,
creates source SQLite sidecars, performs a checkpoint, or takes the writer lock.
The authenticated hosted restore supplies this checkpointed input. Apply still
recomputes the same logical inventory binding under the caller's writer lock.
