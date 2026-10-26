# Retrieval checks and content history

Successful HTTP checks are a different event from a new source body or a changed
component statement. Migration 007 adds an append-only `source_observations`
table with the requested vendor URL, check timestamp, evidence reference and
HTTP status. It does not modify earlier migrations or invent historical checks.

The transport records ordinary successful responses and HTTP 304 validations of
retained bytes after screening for known access challenges. HTTP 304 adds a check,
not a new body. Equal bytes reuse the existing evidence row. A body reverting from
A to B to A is recorded as two transitions, not one unchanged check. Source body
reversions and parser reinterpretations remain distinct from semantic fixes.

The fix-lead report includes a bounded `retrieval_history` for each configured
release/component source: total logged successful checks, distinct raw fingerprints,
same-as-previous checks, HTTP 304 count, first/latest logged check and the latest
twelve check descriptors. Truncation is explicit. The UI shows whether the latest
logged retrieval has the same fingerprint as the analyzed component snapshot.
The retained revision sample is bounded to two and is labelled accordingly.

## Meaning and limits

- Successful retrieval is not successful product normalization. An unrecognized
  HTTP 200 document can be logged while collection health reports a parser gap.
- Known access-verification shells are retained as evidence but excluded from the
  successful retrieval log. Other failures remain in collection health. The log
  cannot supply a request-success rate or uptime denominator.
- A body fingerprint change may concern navigation, rendering tokens or editorial
  content. It does not establish a component, security or CVE change.
- A capture or cache-validation timestamp is a local observation. It does not
  establish the first public availability of a document, release or fix.
- No earlier checks are reconstructed from the evidence row's first capture date,
  a publisher date or an existing collection-run summary. Old read-only archives
  without the table report that no checks have been logged.
- The public projection allows only check metadata for configured official sources.
  It excludes headers, cookies, response bodies, private operator fields and local
  database identifiers. Source hashes identify the exact retained bytes.

The vault audit verifies foreign-key relationships and that each observation points
to evidence from the same requested URL. The logging change stores small references;
it does not duplicate raw response bodies for unchanged checks.
