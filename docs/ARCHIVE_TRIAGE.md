# Review historical sources in bounded batches

`impact triage` groups a pending/error archive sample by source structure, current
parser format and outcome. It does not ingest records or change archive queue
states. A matching layout key is a review aid, not proof of equivalent product,
version, CVE or configuration scope.

```sh
# Resolve only from retained evidence, including linked CSAF dependencies.
impact triage --vendor arista --limit 64 --output data/arista-triage.json

# Retrieve official sources and retain bytes in the private vault first.
impact triage --vendor arista --limit 64 --fetch --output data/arista-triage.json

# After reviewing failures and qualifying the parser, use normal ingestion.
impact backfill --vendor arista --page-limit 1 --document-limit 64
```

The limit is 1–200 distinct pending/error document URLs across the selected vendor
or all installed vendors. Errors are selected first, then queue discovery order.
The report states how many URLs were available and whether the sample was truncated.
Examples in each group are capped at five; the bounded document list retains each
resolved URL, source hash, parser counts and error classification. No raw source
body is copied into the report. Keep operator reports in the ignored private data
directory; they are not automatically published.

Default operation makes no network requests and can use older retained bytes;
it does not establish current access or freshness. Retained access-challenge pages
keep their access-error classification. Missing linked-source bytes produce
`not_retained`, rather than silently switching to a different extraction path.
`--fetch` uses the same official-route allowlist and document resolver as normal
collection, retaining evidence and HTTP cache data. It takes the writer lock.
Neither mode resets retry backoff or treats a successful parse as human review.
A source outside a vendor's authorship scope is `not_applicable`, with no vendor
product assessment. Mixed or missing identity fields remain errors.

Review each failed layout group, inspect version and platform bindings, add a
synthetic regression case, and repeat retained-evidence triage before running the
normal bounded backfill. A later backfill fetch can still encounter changed
publisher bytes, so its failures remain authoritative and visible. Queue exhaustion
and a clean sample do not establish a complete historical archive.
