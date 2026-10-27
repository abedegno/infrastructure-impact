# Recovering retained archive captures after parser changes

A parser upgrade can make a previously unsupported source usable without another
network request. Archive recovery reprocesses those retained bytes and records a
separate receipt. It does not shorten HTTP backoff, reconstruct old availability,
or make an old capture look newly retrieved.

## Eligible work and budgets

Only document items with `unsupported_or_invalid_document` are eligible. The
normalizer fingerprint must differ from the version recorded for the last parser
failure. Legacy errors that predate fingerprint tracking are eligible once.
Transport denials, rate limits, bot verification and missing remote documents are
not retried through this mechanism.

Each source's normal document budget covers both retained reprocessing and new
network document work. If five retained items consume five of an eight-document
budget, at most three new documents are processed. A failed retained attempt
records the current parser version and is not repeated under the same version.
The fingerprint is the same code identity used on normalized advisory revisions.
Installed extension maintainers must update their plugin version when a changed
external dependency changes normalization behavior.

The resolver reads only retained official-route captures, checks access-challenge
responses, and validates the normal plugin/schema path. No browser script or bot
challenge is executed. A missing dependency is reported as a local retained-source
gap, not as proof that the remote publisher omitted or removed anything.

Success creates the normalized revision and marks the queue document processed.
Failure preserves the original HTTP attempt count and retry deadline. Even an
exhausted parser error can recover from its retained bytes after a code change;
this does not grant another HTTP attempt. A later explicit normal network retry
continues to use the ordinary queue policy.

## Distinct chronology

Migration 010 adds a parser fingerprint to archive items and append-only parser
replay receipts. Successful receipts link the exact retained evidence capture.
Failed receipts can have unknown selected-capture metadata; no hash is invented.
Repeated analysis does not create HTTP observations or new content captures.

The source's collection-health outcome is `reprocessed` when retained bytes pass
the newer parser. Its description says no network retrieval occurred. This
outcome is usable for publishing a parser correction but does not count as a
successful current source retrieval in vendor freshness calculations. If network
checks also fail, the pipeline remains partial. Old capture timestamps remain
unchanged, and vendor dates stay publisher claims.

An explicit source selection may also be recorded as analysis provenance during
reprocessing. That does not clear an alternate representation's latest live HTTP
error or manufacture an HTTP success. Read-only triage only inspects captures; it
creates neither selection history nor collection-health records.

The public archive audit includes cumulative logged outcomes and the latest ten
replay examples, with parser version, processing time and available capture
fingerprints/timestamps. Earlier unlogged activity remains unknown. The vendor
catalogue shows these receipts alongside archive progress. Counts describe
software processing, not independent adjudication, portfolio completeness, or
historical first disclosure.

## Verification

Synthetic tests cover no-network recovery, unchanged capture times, absent HTTP
observations, same-parser idempotence, retained missing/unsupported cases, HTTP
error exclusions, exhausted errors, shared processing budgets and preservation of
alternate HTTP failures. Evidence audits check successful replay/evidence edges.
The external-plugin wheel probe includes the additive migration and uses the same
normalization interface.

Source-led parser additions such as the [older Arista layouts](research/arista-legacy-applicability-20261027.md)
remain separately reviewed and tested. A recovery receipt is not a replacement
for independent human review.
