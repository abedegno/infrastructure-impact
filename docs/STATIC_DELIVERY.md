# Static cohort delivery

The full `snapshot.json` remains available for exports, integrations and the Python
reader. The static browser uses `data/index.json` and content-addressed evidence
parts. The normalized advisory schema and comparison policy are unchanged.

Published bundles also contain `snapshot.json.gz`, linked as **Full archive
JSON.gz**. It decompresses to the exact UTF-8 bytes of `snapshot.json`, including
all published records regardless of the selected browser cohort. Compression
happens after public projection; private evidence and review notes are excluded.
An empty gzip filename and fixed timestamp make identical public bytes produce
identical compressed bytes. Both files have SHA-256 entries in `manifest.json`.
The Python reader serves the download as `application/gzip`.

## Publication contract

`schemas/static-index-v1.json` defines the index: publication ID, generated time,
bootstrap descriptor, per-CVE part descriptors, deferred change-history parts and
a full-archive descriptor. Each descriptor carries a relative path, SHA-256 and
exact byte count. Parts wrap their data with schema version, publication and time.
No vendor requests occur in the browser. Integrity verification requires HTTPS or a loopback development origin with Web Crypto support.

Shared metadata includes the complete retained vendor roster and product-label
catalogue. Fetching a narrow CVE cohort must not narrow the available exact-product
selection, remove vendors without a statement, or change the comparison policy.
Each cohort's records retain original document context, assessment order and shared
bulletin qualifiers. Coverage, scorecard cases and timeline events follow the
same selected CVEs. Source-change history loads when its view is opened.

Parts target 512 KB and have an 8 MB hard limit; an oversized row blocks publication
rather than producing truncated evidence. The index has a 2 MB limit. The browser
checks byte counts, SHA-256, publication and generated time, caches successful
parts in memory and limits parallel retrieval to six requests. Failed requests do
not become an empty successful result. A missing known-CVE index entry fails.
Unknown valid CVEs retain the explicit not-checked/no-retained-statement behavior.

Scripts and styles also use content-addressed paths. Old root asset URLs remain
available for integrations. A cached index whose parts disappeared during a
Pages deployment yields a reload message; it cannot silently mix generations.
There is no local storage, telemetry, or automatic exposure inference.

## Loading and verification scope

The default benchmark and custom cohorts fetch their evidence parts. Custom lists
are bounded to 200 CVEs. Selecting the entire imported archive explicitly downloads
the full snapshot; large exports are not represented as small transfers. The full
snapshot is still generated, so this change addresses browser startup and selected
cohort transfers, not unlimited collector memory or artifact storage.

On the retained 203-advisory preview, the index, metadata and default cohort parts
used 2,240,513 bytes versus a 23,691,641-byte full snapshot: 90.5% fewer JSON bytes,
across 26 requests with bounded concurrency. This is a dated payload measurement,
not a latency benchmark or a guarantee for every cohort. The hosted publication
has a different archive size and is measured separately.

The public monitor verifies the index, bootstrap, default cohort parts and linked
quality reports against the manifest, with a 20 MB default-part budget. Its receipt
also reports `static_marker_verified` when the declared `.nojekyll` file is fetched
and matches its manifest hash. The Pages uploader includes hidden files only from
the generated public bundle, so this marker is delivered with the other declared
assets. A missing or changed declared marker fails monitoring.
The receipt
states `full_archive_download_verified: false` for cohort delivery. When a compressed
archive is listed in the manifest, it also verifies that file's fingerprint and
that its decompressed SHA-256 equals the full JSON fingerprint. This extra check
has separate 8 MB compressed and 128 MB expanded budgets and receipt fields
`compressed_archive_verified` and `checked_compressed_archive_bytes`; it does not
inflate the default browser-transfer measurement or claim per-record privacy review.
Older publications without the gzip file remain supported. Collection-side schema audits and publication manifests
continue to cover generated output. Reports remain dated and vendor rates and
fix-timing metrics remain suppressed.

Tests compare cohort-delivery results with the Python reader for comparison,
product groups, exact-product filters, coverage, scorecards, timeline, case files
and exports. Fault checks cover tampering, missing files, mixed generations,
missing known-CVE index entries, deferred history and atomic publication failure.
