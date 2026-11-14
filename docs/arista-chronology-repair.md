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

## Manual hosted batch and reviewed SA178 source refresh

The finite installed profile `arista-reviewed-sa0137-chronology-0165-0198-v1`
uses maintenance preview/apply. Curation revision 3 keeps receipt schema version 1
and the profile ID; its profile version is `3`. Earlier revisions did not complete
an apply. The revision, HTML comparison pins and declarative
`reviewed_owner_refreshes` metadata change the profile fingerprint, so an earlier
accepted preview cannot authorize this apply. Obtain a
fresh hosted preview and retain the existing publication v2 analysis profile
`campus-switching-openvuln-2026-11-14-v1` and its pinned input hash.

The scope remains 34 normalized primaries and 69 pinned captures (68 required and
one optional retained-only RSS), with the same 4,061,372-byte accepted-capture
ceiling and 2 MB document ceiling. All other required CSAF captures must already
be retained. Missing HTML can use the existing bounded official transport.

The additional prerequisite applies only when authorizing a fetch of the missing
new SA178 structured capture. An exact current new owner remains accepted through
the existing cache-only path. To authorize the transition, the latest old SA178
owner must be on the exact existing CSAF URL, advisory identity `Arista Networks Security
Advisory 178`, CVE `CVE-2026-73440`, document status `interim`, and old source SHA256
`192901b6a2f6352f5ff2dd2540e52bd4d732e0201a4c5881d626e38dcd34b8da`.
Preview reports `reviewed_owner_refresh` for that tuple and binds its actual old
capture bytes and receipt even when newer captures exist. That diagnostic denotes
a prerequisite; it does not bypass apply-time source verification.

Apply verifies the old raw capture on the existing hosted connection: exact
source URL/hash, bounded bytes, SHA256, document title, tracking ID/status and CVE
membership. It then validates every other retained structured capture before any
retrieval. Only that verified old owner may fetch the missing 7,237-byte new SA178
capture with SHA256
`08041ea904a15e30fe60790e83c8061a833ff220b22826dfdab351069f9525bc`.
An exact retained new capture is preferred. Unknown owner hashes, URL/CVE/status
changes, corrupt old evidence and changed new bytes fail closed.

This is a vendor source revision: fixed releases change, including EOS 4.34.8 to
4.34.9. It is not a cosmetic date repair. After every required pair has passed
preflight, ingest retains a fresh SA178 vendor-source revision before the existing
chronology repairs. The old raw capture and revision remain; only the chronology
step preserves the fresh source's other facts. The receipt still counts the 34
prepared normalized primaries. Repeating with the new exact current owner uses
the unchanged cache-only path.

Runner capture timestamps are preserved; new retrievals use their real retrieval
time. Failed isolated applies can retain captures or revisions, while publication
still requires the existing full-source report/audit/build limits and authenticated
recovery readback. No workflow, schedule, permission, secret or budget changes are
part of this transition. The actual old raw capture is verified on the hosted
connection, never by exporting private recovery state.

## Exact HTML binding with a rotating Joomla token

Hosted apply 43641297108 stopped at the first HTML input, SA165. The reviewed
capture and two independent official responses differ only in a 32-character
lowercase hexadecimal `csrf.token` inside the document head's Joomla JSON options
script. Every other original byte matches. Replacing the full-page raw pin on
each request would not produce a stable input.

Curation revision 3 adds `joomla_csrf_sha256` to each of the 34 HTML reference pins.
Registration checks each reviewed reference's existing raw SHA and exact byte
count first. The comparison projection requires one head, one Joomla options
JSON script inside that head, unique JSON keys, and one valid top-level
`csrf.token` with exactly 32 lowercase hexadecimal characters. It masks only
those 32 original bytes with ASCII zeroes, then hashes all remaining original
bytes. It does not reserialize HTML or JSON, accept a matching article inside an
arbitrary changed page, or change advisory, link, whitespace or other page bytes.
Missing, duplicate, malformed and non-head token contexts fail closed.

The exact retained reference capture remains preferred. Otherwise the latest
retained same-URL HTML capture must pass actual raw-SHA integrity, exact length
and projected-digest checks; missing supporting HTML can use the same checks on
a bounded official retrieval. Any existing HTML primary owner is checked using
its actual evidence ID, source URL, raw hash and comparison pin. Preview also
binds that evidence row when it is neither the reference nor the latest capture.

Evidence always keeps the unmodified raw bytes, their actual SHA and original
retrieval time. Chronology and selection proofs refer to that actual capture.
Structured JSON, the reviewed SA178 source transition, and optional RSS retain
their exact raw-SHA requirements. Capture counts, byte ceilings and hosted
publication/recovery gates remain unchanged. Obtain a fresh revision-3 preview
after review and CI.
