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
