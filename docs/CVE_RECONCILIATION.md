# Local official CVE reconciliation (unreleased)

This local feature compares a pinned official CVE List V5 snapshot with an explicit,
immutable collection baseline. It discovers Cisco IOS XE, Aruba AOS-CX and Arista
EOS statements and ambiguous leads. The reference-only class is reserved but inactive
until reviewed advisory-route and family-context rules are available. It neither ingests
advisories nor fetches their references. Human review remains pending. The released
website source pin remains 0.10.1; publishing this source is a separate action.
There is no hosted activation, API route, schedule or default-source change.

## Acquire and verify a complete snapshot

Acquire source explicitly from the full official repository:

```sh
git clone https://github.com/CVEProject/cvelistV5.git /absolute/source/cvelistV5
```

Cloning is an operator action, not a side effect of any reconciliation command.
Use the complete tree at a full 40-character commit ID. Hourly/daily delta archives
are updates, not complete snapshots. Do not scan a moving branch name. Keep the
receipt, workspace, baseline and exports separate from the source repository and
collection vault. Prefer a read-only copy of the intended public collection vault;
never select a private/customer vault by accident.

Plan substantial free disk space for the Git checkout and retained scan state.
The measured 2026-11-06 source had 420,073 records. A 1,000-record ordered sample
consumed 5,544,144 raw record bytes. These source-size observations are not
universal capacity estimates and do not describe discovery coverage; the source
checkout, Git history, temporary files and reports need additional space.

```sh
impact cve-reconcile verify \
  --repository /absolute/source/cvelistV5 \
  --commit FULL_40_CHARACTER_COMMIT \
  --receipt /absolute/run/verified-snapshot.json
```

`verify` is the only network mode: one bounded anonymous request to the exact
GitHub official commit route, without redirects. It validates the local commit/tree
against the retained response and writes a verification receipt plus its raw
response sidecar. It never clones, pulls or fetches Git objects. The receipt binds
the exact official commit and tree; its digest is carried into scan/report identity.
Local hashes detect inconsistent edits, not a hostile rewrite of all evidence.

## Scan and resume offline

```sh
impact cve-reconcile scan \
  --repository /absolute/source/cvelistV5 \
  --commit FULL_40_CHARACTER_COMMIT \
  --receipt /absolute/run/verified-snapshot.json \
  --workspace /absolute/run/workspace \
  --start-date 2021-01-01 --end-date 2026-11-06 \
  --record-limit 5000 --byte-limit 250000000
```

Repeat the identical command to resume from the committed inventory cursor.
The complete pinned tree is enumerated, including older CVE identifier years.
The inclusive window classifies the literal registry publication calendar day;
outside-window and unknown-date findings remain in the report. Changed source,
receipt, selector, scanner or date-window identity refuses resume.

Each invocation allows at most 5,000 attempts and 250,000,000 raw bytes; each record
allows 2,000,000 raw bytes. Smaller explicit limits, including zero, are accepted.
Tree inventory is bounded at 2,000,000 entries and 128,000,000 serialized bytes.
The workspace allows at most 100,000 candidate findings and 1,000,000,000 retained
bytes, with inventory/journal/staging headroom. Existing reports count toward that
budget. Limit stops preserve committed progress. Invalid, unsupported, rejected,
oversized and missing-object outcomes remain visible. Unsupported format records
are not silently treated as irrelevant. No reference retrieval occurs.

## Freeze an explicit baseline and export

```sh
impact cve-reconcile baseline \
  --database /absolute/public-copy/intel.sqlite3 \
  --config /absolute/public-copy/sources.json \
  --output /absolute/run/baseline.json

impact cve-reconcile report \
  --workspace /absolute/run/workspace \
  --baseline /absolute/run/baseline.json \
  --json-output /absolute/exports/reconciliation.json \
  --csv-output /absolute/exports/reconciliation.csv
```

All parents must already exist. Baseline export opens one read-only SQLite
snapshot, supports only the exact reviewed collection schema, performs no migration
and refuses an existing output. It projects all vendors and revision history,
actual fetched evidence bindings, source checks, configuration and queues without
raw source bodies or private configuration/error prose. Its fingerprint excludes
only the export observation timestamp. `generation` is null; no live publication
is consulted.

Report generation needs only the workspace and baseline, not the Git source,
receipt file or vault. Both generation and export validate committed state and
retained capture integrity. Captures may be framed/compressed: use
`open_workspace(...).read_capture(sha256)` to obtain original bytes; do not parse
capture files directly.

## Interpret JSON and CSV

`schemas/cve-reconciliation-v1.json` is closed at every report object. Use
`validate_report(report)` as well as JSON Schema: semantic checks recompute report
and finding IDs, unique-CVE dimensions, counter arithmetic, completion state,
source/container relationships, date classification and membership implications.
Reports embed receipt/commit/tree, selector, scanner, window and baseline identity;
no local paths are exported.

Each finding retains one attributed CNA or ADP branch. Literal product, provider,
matching-rule, CPE and registry-date objects are canonical JSON **strings** in the
`*_json` fields. Decode those strings for the original typed evidence. This preserves
publisher keys and malformed/unknown date values without allowing arbitrary keys
in the closed report contract. Reference `literal_json` preserves its entire row.
Status strings are literal publisher evidence, not an affectedness conclusion.

`cve_anywhere`, `cve_vendor` and `cve_family` describe **latest normalized revisions**.
Family presence requires the matching CVE assessment, vendor and reviewed family;
another vendor's CVE or another CVE's product cannot substitute. Revision ID lists
support these flags. `historical_revision_ids` provides separate older-only context.

Reference collection is independent: missing references stay `missing_reference`;
unsupported URL identities stay `unknown_identity`. Exact reviewed identities
preserve meaningful query parameters and never match null to null. States use this
priority: `normalized`, `retained_unparsed`, `error`, `pending`,
`observed_without_retention`, `configured_unobserved`, `unobserved`. Corresponding
revision, evidence, queue, observation, check and selection IDs remain available for examination
against the frozen baseline. Presence flags never imply reference collection.
Only actual fetched revision/evidence/cache, queue or source-observation evidence
pointers, or persisted selected-source view bindings establish collection; a normalized `advisory_url` hyperlink does not.

Registry dates are separate from fetched vendor publication dates. A normalized
CVE API record's `published_at` remains registry chronology, including when that
record links to a vendor advisory that was never fetched. No patch date, exposure,
version applicability, silent fix, concealment, ranking or rate is inferred.

`counts.findings` counts attributed rows. `counts.unique_cves` and each dimension
bucket count distinct CVEs, so duplicate container branches do not inflate CVE
totals. Buckets may overlap: one CVE can have conflicting statuses or multiple
families. Do not sum buckets as a total. Unknown publication dates have an explicit
`unknown` year bucket. Findings sort by committed inventory position then branch
ordinal; reference rows retain literal container order; count buckets sort by value.

`scan_complete` means the entire accepted tree has terminal outcomes.
`coverage_complete` is always JSON null (unestablished), even for a complete scan.
All scan counters remain visible; read-only reports use stop reason `complete` or
`incomplete`. Invocation budget-stop reasons are in the scan command's output.

CSV has one row per finding/reference, including an explicit missing-reference
row. A zero-finding report has one `row_type=summary` row. Every row carries
`report_id`, scan completion, null coverage completeness, attempted/remaining and
stop reason. Blank finding/reference cells on a summary row mean no finding;
`collection_state` disambiguates missing reference URLs. JSON retains original text;
CSV prefixes a single quote to formula-sensitive publisher cells (including leading
whitespace before `=`, `+`, `-`, `@`, and leading tab/newline characters). JSON-in-cell
columns retain original product/date/reference evidence. Identical semantic content
has identical canonical SHA-256 `report_id`; finding IDs exclude baseline collection
state, so baseline changes do not rename the same discovery finding. There is no
export timestamp. Retained-byte metadata is the observed pre-export workspace size.

## Export safety and failure policy

`write_report(report, *, json_path, csv_path, workspace, baseline_path)` requires
explicit writer context. It revalidates state and baseline under the exclusive
workspace lock and refuses a stale report. Existing JSON, CSV, mixed existing pairs,
symlinks, hardlink aliases, input aliases and protected workspace paths are refused;
there is no overwrite option. For outputs inside a workspace, create and use its
`reports/` directory. State/capture/identity/lock paths and SQLite sidecars are never
export targets. Inside-workspace stages and final bytes share the workspace budget.
Other report writers and scanners must honor the same lock.

Both outputs are staged and fsynced before publication. CSV publishes first and
JSON last, using exclusive no-clobber publication. JSON is the commit marker: accept
a pair only when both files exist and every CSV row carries the JSON `report_id`.
Caught errors remove this invocation's stages and published outputs. Abrupt process
death can leave a CSV-only orphan or hidden `.reconciliation-*` staging files;
that is an incomplete export, never success. Retry refuses existing output names.
Inspect/remove only the abandoned export/staging files or use fresh names. Never
remove workspace state or captures to recover an export. Two arbitrary filesystem
paths cannot be atomically renamed as one operation; this policy makes partial
publication detectable and prevents mixed-generation overwrites.
