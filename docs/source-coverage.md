# Source coverage inventory

`impact coverage-gaps` produces a separate, versioned operator JSON artifact from
an explicit SQLite vault and source configuration. It makes no network request,
reads no credentials, acquires no writer lock, runs no migration and does not
publish a report. Both input files must already exist. Output may not alias either
input, including through a symlink or existing hardlink. Reserved SQLite
`-wal`, `-shm` and `-journal` sidecar paths and their aliases are also protected,
even before those sidecars exist.

```sh
impact coverage-gaps --database /absolute/path/to/staging/vault.sqlite3 \
  --config /absolute/path/to/staging/sources.json --limit 32 \
  --output /absolute/path/to/staging/coverage-gaps.json
```

Omit `--output` for UTF-8 JSON on standard output. `--vendor ID` selects any
installed vendor plugin, rather than a fixed switching-vendor list. `--limit` is
an integer from 1 to 200, default 32, shared across the entire selected scope.
Missing inputs, malformed configuration, unknown plugins, invalid limits,
incompatible databases and output collisions fail with a sanitized CLI error.
An explicit `{"vendors": []}` stays empty; it never loads bundled or personal
source defaults. Persisted unconfigured sources remain observable in that vault.
The Python interface is
`application.coverage_gaps.report(db, config, *, vendor=None, limit=32) -> dict`.
Callers supply the connection; the CLI uses `connect(path, read_only=True)` with
SQLite `mode=ro` and `PRAGMA query_only=ON`.

## JSON version 1

The installed resource is `infrastructure_impact/schemas/coverage-gaps-v1.json`.
All defined objects are closed. The producer validates its output against that
schema. The existing public advisory/study/scorecard/API schemas are unchanged.
Only selected metadata, controlled outcomes and error categories are emitted;
raw captures, normalization notes, collection details and exception text are
excluded. URL query strings and fragments are omitted, so query-specific source
rows may display the same URL. Keep invocation and archive IDs when inspecting
such rows; displayed URLs alone are not unique identifiers.

The root fields are `schema_version`, `generated_at`, `scope`, `last_run`,
`sources`, `triage` and `limitations`. `scope` contains `vendor` (or null) and
`sample_limit`. `last_run` is the persisted **global** pipeline summary or null;
its `scope` is `global_persisted_pipeline_run`. Its imported/failure counts are
never allocated to a selected vendor or added to source failures.

Each source row has:

- `vendor`, `source_url`, `kind`, `configured`, `configuration_sections`,
  `budgets` (`feed_limit`, `page_limit`, `document_limit`), `archive_id` and
  `invocation`. A missing seed has a null source URL and `kind=unknown`.
  Persisted invocation metadata includes `run_id`, `study_id`,
  `requested_window`, start/check timestamps, `enumeration_state`, a controlled
  `error_code`, `enumerated_identities`, `duplicate_entries`, `expected_total`
  and `diagnostics`. `expected_total` preserves the nullable publisher-reported
  denominator observed by this source/enumeration invocation. Requested bounds
  do not prove that the publisher total is filtered to that window. It is
  separate from the unknown vendor-wide total; instability diagnostics
  remain visible when publisher totals change.
  Requested windows describe the invocation; they are not inferred publisher
  history. `listing_duplicate_links` is a discovery diagnostic, not a document
  retrieval or parser failure. Missing seed runs remain `not_configured`.
- `observed_window` is the latest retained root RSS/index/reviewed-listing
  inventory, or null when unobserved or not supported by that inventory parser.
  It records observation time, entries, unique links and entries without links.
  It never means the entire publisher archive. Publisher historical availability
  remains `unknown`. Null does not prove that no source bytes exist.
- `queue` contains exact persisted document counts: `discovered`, `pending`,
  `done`, `not_applicable`, `error`, `retrieved`, `retrieval_failures`,
  `unsupported` and `other_errors`. Retrieval means retained evidence exists,
  including unusable evidence. Queue completion and retrieval do not certify
  parsing, affectedness or review. A not-applicable flag alone does not prove a
  notice. Invocation queues use that run's linked representations; ordinary
  archive rows use the source's additive queue.
- `current` counts retained normalized CVE-bearing identities in
  `parsed_advisories` and their representations in `parsed_representations`.
  Known duplicate advisory IDs are deduplicated within a row. A single retained
  response can contain several persisted advisory identities; those remain
  separate advisory/response pairs rather than an invented one-record total. Existing retained
  zero-CVE notice records have their own `retained_unlinked_notices` count.
  Current evidence selection respects the HTTP cache pointer before retained
  fallback. Wrapper aliases require either a matching bounded retained-only preview or
  an explicit persisted source selection linking both current captures. The same
  proof applies to unqueued configured wrapper pins and feed links. Successful
  previews count as parsed current evidence only when a matching normalized
  revision already exists in the vault. An
  unproven mapping remains uncertain, including after cache A → B → A reversions. `unknown_aliases` counts document representations without a usable
  persisted identity for that evidence; it does not guess which other advisory
  they represent. `publisher_date_range` uses usable publisher dates from these
  CVE-bearing records, never retrieval time. Missing dates remain null.
  `publisher_total` is always null, `portfolio_completeness` and `human_review`
  are `not_established`, and `model_classification` is `unknown`.
- `health` is the latest persisted collection observation for the exact source
  URL or null. `history.collection_attempts` and `collection_errors` describe
  that exact URL's history, not all descendants or the requested window.
  `history.parser_replays` counts append-only receipts for the linked queue
  items, separately from health/current evidence. A historical replay receipt
  does not override current bytes. Same-parser source-only processing can have
  `reprocessed` health without a new parser-version receipt.
- `evidence` has `available`, at most 20 whitelisted `retained` references and
  `truncated`. References contain local evidence ID, official source URL, SHA-256
  and observation time, never bytes. `triage` contains sampled/unsampled counts
  and the controlled preview dispositions described below.

Source rows are **nonadditive** across source representations, configured feeds,
archives and overlapping invocation windows. Do not sum them into disclosures,
collection failures or portfolio totals. Shared advisory IDs establish only
known normalized identity, not equivalent claims across representations.

## Bounded parser preview

Root `triage.available`, `sampled`, `unsampled` and `truncated` describe one global
set of vendor/request URL candidates. It includes all archive document states,
unqueued configured pins, retained root listing links and standalone observed
advisory sources. Queue errors are sampled first, then not-applicable, pending
and completed queue items; remaining candidates follow source order. There is
one preview per candidate across overlapping source rows. Per-row sample counts
can overlap and must not be summed as a global total.

`triage.documents` contains bounded outcomes with official requested/resolved
URLs, selected-byte SHA-256, nullable CVE/assessment counts and a controlled error
code. It reuses the retained-only resolver; missing linked bytes stay missing.
Outcomes are:

| Outcome | Meaning |
| --- | --- |
| `parsed_preview` | Current installed parser validates retained CVE-bearing bytes; no ingestion occurs |
| `recognized_notice` | Plugin positively recognizes an excluded zero-CVE informational notice |
| `retained_unlinked_notice` | Existing plugin policy permits a retained zero-CVE advisory record |
| `other_not_applicable` | Plugin explicitly excludes the document without positive notice proof |
| `not_retained` | Required retained bytes are unavailable |
| `error` | Retained resolution/parsing failed; inspect the controlled error code |

A preview does not change the queue, insert an advisory, create a recovery
receipt, establish model applicability or confer human review. Unknown aliases,
unsampled sources and unavailable captures stay unknown. New automated checks
remain pending the maintainer's independent human review.

## Opt-in switching source example

[The example configuration](../examples/switching-coverage-sources.json) uses empty
ordinary feeds, the reviewed Aruba 2021 listing, an explicit Arista listing and
three explicit current/notice Arista document URLs. It does not change installed
source defaults. Its `switching_sources` is deliberately empty. Pins are consumed
by ordinary explicit-config collection; switching backfill enumerates configured
archive/API seeds. Loading or inspecting this configuration does not collect it.

The Aruba directory is a reviewed year-specific layout, not a full-history
claim. Text extraction preserves literal AOS-CX statements, but family prose does
not establish 6300M/6410 model applicability or product-bound remediation events.
Arista's reviewed current applicability and advance notice formats, and Cisco's
reviewed informational schedule format, remain source-specific. A future layout
may need further review; an excluded notice is not an affectedness result.

## Cisco openVuln readiness

The existing isolated Cisco transport remains in use. Before an authorized
collection run, the operator registers an application through
[Cisco PSIRT authentication](https://developer.cisco.com/docs/psirt/authentication/)
and obtains authorized client credentials. Supply them only through the existing
`CISCO_OPENVULN_CLIENT_ID` and `CISCO_OPENVULN_CLIENT_SECRET` environment variables
in the intended process. Do not put values in source JSON, command arguments,
reports, logs, commits or chat. The coverage inventory never checks whether these
variables are set.

For a separately authorized authenticated stage, copy the opt-in example to an
explicit staging source file and replace `switching_sources` with:

```json
[
  {
    "vendor": "cisco",
    "kind": "openvuln",
    "url": "https://apix.cisco.com/security/advisories/v2/all/firstpublished",
    "page_size": 100
  }
]
```

Supported configuration seeds are that exact `/all/firstpublished` route,
`https://apix.cisco.com/security/advisories/v2/all`, and the exact
`https://apix.cisco.com/security/advisories/v2/year/YYYY` year family. The existing
collector constructs date/pagination queries; arbitrary configuration queries
and OSType/version enumeration are not supported. `/all`, `/year/YYYY` and
`/all/firstpublished` have distinct publisher scopes; a requested study window
does not make them interchangeable. The supported
[all-advisory endpoint](https://developer.cisco.com/docs/psirt/all/) provides
enumeration, not a guarantee that linked documents can be retrieved.

Missing either credential, including a partial pair, yields
`auth_not_configured` without a request or reservation. Rejected credentials
produce `auth_rejected`; quota/backoff and unresolved reservations remain
controlled states. Token responses and reflected secret material are rejected
or redacted before retention. Authentication sessions reject redirects.
Persistent quotas reserve requests before I/O: five per second, thirty per
minute and five thousand per day. Token requests consume quota too. Interruptions
leave durable pending reservations; do not erase them to force a retry.

Authorized bounded collection uses the existing `impact switching-backfill`
interface, an explicit `--config`, explicit staging `IMPACT_DATABASE` and all
other `IMPACT_*` paths for a separate public-only vault. See the
[staging instructions](switching-comparison.md) for paths and invocation syntax.
Repeating the same source, study/window and enumeration revision resumes its
persisted run. Changed page size creates a separate API invocation; changed batch
budgets do not. Bounds remain at most 20 pages and 200 documents per invocation;
no storage or runtime budget changes accompany this report.

Successful enumeration can still leave document access errors, unsupported
normalization, unresolved aliases/models and unknown historical coverage. Do not
interpret it as successful retrieval, parsing, platform classification or a
complete Cisco portfolio. Real authenticated Cisco history remains blocked until
authorized credentials exist. This implementation performs no live credential
probe, hosted secret wiring or history run. Hosted activation, publication,
release and source-default changes require their own approved concrete proposal.


## Reviewed inputs and acceptance limits

The opt-in example adds Aruba's exact 2021 directory and reviewed Arista source
routes without changing ordinary defaults. Reviewed Aruba signed-text structures
preserve shared product scope and per-CVE CVSS candidates; incomplete or invalid
candidates remain diagnosed and cannot become valid public numeric metrics.
Literal family/platform statements do not establish exact model applicability.
Aruba prose fix guidance can remain visible with
`remediation_product_scope_unresolved`; it does not become a counted, independently
bound remediation event or an inferred software release date.

Arista affected, unaffected and triage lists retain their local software and
configuration context. In SA-0203, a configuration-based non-exploitability
statement does not establish absence of vulnerable underlying component code.
Slash labels and model-family labels stay literal. A positively reviewed advance
notice has zero own CVEs and assessments, even if it links separate advisories.
The resolver preserves such an HTML notice before following an advertised CSAF
representation. Unrecognized articles still use the existing structured resolver.
Rediscovery and retained-source replay can process a later advisory revision;
parser receipts and earlier source evidence remain immutable.

The [dated acceptance observations](research/2026-11-05-coverage-repair-observations.md)
record actual denominators, source dates, errors and replay labels. The new gap
inventory describes one explicit vault and configuration; source rows overlap,
preview is bounded and read-only, and unknown completeness stays unknown. Counts
are extraction and availability observations, not security quality or vendor
rankings. Independent human review remains pending. The next research milestone
is the [release-history work in the backlog](research/2026-11-05-source-coverage-backlog.md);
these repairs do not implement it or establish complete Cisco/vendor history.
