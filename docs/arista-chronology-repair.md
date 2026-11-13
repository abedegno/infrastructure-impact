# Explicit offline Arista chronology repair

The default collector and generic CSAF normalizer are unchanged. An explicit local
replay can pair an Arista CSAF capture with its owned HTML article to use the HTML
revision 1.0 day as the advisory's initial publication date. CSAF creation/current
and revision dates, HTML revision dates, and observed RSS publication dates remain
separate labeled events. The CSAF primary source, product scope, remediation facts,
and `updated_at` remain unchanged.

Run from an installed environment or checkout with public source captures:

```sh
python -m infrastructure_impact.application.arista_chronology_repair \
  --manifest public-captures/source-manifest.json \
  --output-json chronology.json \
  --output-csv chronology.csv \
  --database new-public-scratch.sqlite
```

The database argument is optional and must name an absent scratch database. Without
it, the same ingest and study projection checks run in memory. No default database
is opened, no HTTP requests run, and no published generation is changed. Outputs
are explicit paths; exported source receipts omit local capture paths. Database
observations use the new local ingestion time; chronology receipts preserve the
caller's original capture times.

The manifest is a JSON array with `number` (advisory number, or null for RSS),
`kind` (`html`, `csaf`, or `rss`), `url`, `path`, `status`, `bytes`, `sha256`, and
`retrieved_at` per capture. Every capture's successful status, hash, and byte length
is checked before ingestion. Unsupported or incomplete pairs remain explicit.
SA184's reviewed informational HTML notice produces no affected-product claims.

`adapters.arista_chronology.reconcile(record, *, html_raw, html_source, csaf_raw,
rss_raw=None, rss_source=None)` is pure and returns `status`, `corrected_record`,
`chronology`, and `issues`. Receipt arguments contain exactly `url`, `sha256`, and
`retrieved_at`. The input is a fresh normalized CSAF record, optionally carrying
`source_observed_at` for the CSAF capture; materialized revision/evidence identities
are rejected. Missing CSAF capture time remains null. It requires an owned article
heading/download link, matching CSAF self-reference and advisory identity, exact
introductory CVE membership, an unambiguous day-precision initial revision, and an
agreeing HTML Date header. Ambiguous inputs return unchanged copies with diagnostics.
A CSAF current/history disagreement remains an issue without redefining the HTML
initial event or the CSAF current event.

The optional typed advisory-v2 field `publisher_chronology` activates the Arista
research hook's pure `apply_claim_chronology` helper. It copies claim templates and
adds `initial_date_provenance` before the ordinary projection computes claim IDs.
It refuses finalized claims and requires exact CSAF bytes, advisory/CVE ownership,
and original date agreement. Both Python and browser validators enforce the field
bindings. Original records and accepted/public generation artifacts are never edited.

`resources/arista-chronology-validation.json` contains three supplementary,
source-pinned cases (SA165, SA183, SA188). `validate_cases` checks the actual replay's
HTML initial, CSAF initial, RSS observation or absence, claim dates before and after
finalization, and unchanged scope/fix fields. Different captures are reported as
`different_capture`, not as successful validation. Human review stays pending.
