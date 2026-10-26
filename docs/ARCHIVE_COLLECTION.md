# Resumable historical collection

The scheduled collector runs an additional bounded backfill after normal feed
collection. Configured sources include the official HPE Aruba Networking CSAF
text index (110 listed links across 2022–2026 directories at review), Arista
Security Advisories, Palo Alto’s public advisory form and Fortinet’s default
infrastructure product-filtered PSIRT listing. See the
[dated source review](research/vendor-archives.md) for access and historical limits. This is an index of publisher documents, not an inventory of every
product, every affected release or every historical disclosure.

## Operator commands

```sh
impact migrate
impact backfill --vendor aruba
impact source-audit
impact snapshot
```

`backfill` collects into the vault; it does not publish. The regular `impact collect`
command performs backfill and publication under the same process lock. `sync`
retains its existing bounded current-feed behavior. Repeated backfill invocations
resume unfinished documents and skip successfully processed ones. The root index
is refreshed on every invocation when eligible; links removed from a later index
never delete retained documents or normalized revisions.

Each configured source has independent page and document budgets. Defaults are
2 pages and 8 documents per pass; bundled new listing sources use 4 documents; valid ranges are 1–20 and 1–200 respectively.
The root counts against the page budget and gets a reserved first slot when the
page budget is at least two. With a one-page budget, refresh can be deferred while
unvisited continuation pages remain. An unvisited continuation page takes
priority over refreshing an already visited root, so a one-page budget can still
make progress. Documents discovered on a page are queued before retrieval.

```sh
impact backfill --vendor aruba --page-limit 2 --document-limit 16
impact backfill --vendor aruba --refresh-pages
impact backfill --vendor aruba --retry-errors
```

`--refresh-pages` revisits completed non-root pages within the same budget. It
retains old page fingerprints and discovery links. Normal passes do not rescan
unchanged historical continuation pages, so changes on those pages require this
refresh. Normal current feeds still refresh their sample; completed historical
documents are not periodically fetched by the backfill. A subsequent parser
correction can use `impact reparse` on retained evidence.

Failed pages and documents retry after 24, 48, 96 and 168 hours, up to five failed
attempts. A success resets the attempt count. Exhausted failures stay visible;
`--retry-errors` explicitly resets failures for the selected configured source(s),
including access denials. It does not solve access challenges. Each item is
attempted at most once per invocation. Deferred failures do not count as new
failed attempts, so consult the queue and source health as well as the command's
exit status. The CLI exits nonzero for a newly failed attempt.

## Configuration and extensions

```json
{
  "vendors": [],
  "archives": [
    {
      "vendor": "aruba",
      "kind": "index",
      "url": "https://csaf.arubanetworking.hpe.com/index.txt",
      "page_limit": 2,
      "document_limit": 8
    }
  ]
}
```

The optional `archives` section is additive. Any installed vendor plugin with a
reviewed document parser can use an official CSAF text index (`index`) or RSS/Atom
feed (`rss`). RSS/Atom follows only advertised `rel="next"` links. Seeds, documents,
continuations and redirects must use HTTPS on the plugin's official domain
allowlist. Duplicate queue URLs are ignored; pagination cycles terminate. Rejected
links and entries missing a document link are counted as discovery gaps.

Plugins with a `parse_feed` metadata/record API are deliberately excluded from
this document-link mechanism. Juniper's RSS metadata and Check Point's active
record API need a separately reviewed historical enumeration path. Reviewed pure `parse_archive` hooks support `kind: "listing"` for Arista, Palo Alto
and Fortinet. They return the shared `ArchivePage` contract and record observed
product filters. Guessed page parameters and automatic CSAF provider-directory
discovery are not implemented. Enabling another vendor requires reviewing the official endpoint,
its historical scope and access constraints, then adding synthetic regression
coverage for its supported layout. Do not treat an ordinary RSS window as a full
archive merely because its listed links have been processed.

## Evidence, recovery and public reporting

Migration 005 adds sources, queued items and discovery edges. Migration 006 adds
per-page scope strings. Every discovered
item links to the exact retained page evidence that advertised it, including old
page revisions. Page queue updates and discovery edges commit together. Each
document uses the normal resolver, schema validator, revision store and vendor
parser. After interruption between ingestion and queue completion, the next pass
replays the item; identical normalized evidence does not create duplicate revisions.
The existing encrypted hosted backup includes these tables without a new secret.

The source audit and Vendor catalogue show:

- Discovered documents, successful normalization, non-CVE notices, pending work and failures.
- Page traversal, link gaps, exhausted retries and latest retained page fingerprints (up to 20).
- Observed listing scopes and dated review decisions, including disabled candidates and access limits.
- The earliest/latest usable publisher dates among current normalized records matched to processed resolved URLs, and a count without usable dates.
- Whether all currently known pages and documents have been processed without link gaps.

`known_queue_exhausted` means only the last condition. The legacy audit field
`archive_enumerated` is true only for an exhausted configured **text index**;
`portfolio_completeness` remains `not_established`. Pagination flags describe
successful processing of more than one page for the matching source. Per-feed
response counts still describe only that retained response, not accumulated pages.
Publisher dates remain distinct from the collector's observation times and do not
prove that a fix or document was available at that historical date. No vendor
ranking, exposure inference or concealment finding follows from a backfill.

Raw responses, error bodies, credentials and private research are excluded from
public progress metadata. Limits still apply to individual retrievals (15 MB,
25-second requests, one bounded retry). Budget each additional source against the
hosted job's 40-minute limit and encrypted-state storage limits.
