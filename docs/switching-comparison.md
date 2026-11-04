# Staging campus/branch switching discovery

The study starts on **2021-01-01**. Supply an explicit observation end; 2026
remains a partial year and 2026-04-07 belongs to the post period. Discovery does
not establish model applicability, complete vendor exposure, equivalence, a
security ranking or causality. Classification remains pending for later typed
evidence extraction and independent human review.

Use a separate staging directory and vault. This command never publishes:

```sh
IMPACT_HOME=/absolute/path/to/staging \
IMPACT_DATABASE=/absolute/path/to/staging/vault.sqlite3 \
impact switching-backfill --config /absolute/path/to/staging/sources.json \
  --start-date 2021-01-01 --end-date 2026-11-04
```

`--config`, `--start-date` and `--end-date` are mandatory. `IMPACT_DATABASE` must
explicitly select the staging vault. Optional `--vendor` selects `cisco`, `aruba`
or `arista`; omission selects all three. Defaults are **2 listing pages and 8
documents per vendor per invocation**, shared across that vendor's seeds. Caps
are **20 pages and 200 documents**; zero, Boolean, oversized and invalid date
inputs fail before network I/O. Existing part/index/monitor limits are unchanged.

For example, a staging configuration can contain:

```json
{
  "vendors": [],
  "switching_sources": [
    {
      "vendor": "cisco",
      "kind": "openvuln",
      "url": "https://apix.cisco.com/security/advisories/v2/all/firstpublished",
      "page_size": 100
    }
  ],
  "archives": [
    {
      "vendor": "aruba",
      "kind": "index",
      "url": "https://csaf.arubanetworking.hpe.com/index.txt"
    },
    {
      "vendor": "arista",
      "kind": "listing",
      "url": "https://www.arista.com/en/support/advisories-notices"
    }
  ]
}
```

Cisco also accepts the exact `/all` and `/year/YYYY` route families on that API
host. No arbitrary queries, OSType/version enumerators, credentials or token
configuration fields are accepted. `page_size` is 1–100. The collector constructs
one-based page indexes and date query parameters itself. `/all` traverses the
published listing, `/year/YYYY` only that publisher year, and `/all/firstpublished`
the supplied date range. Requested study windows do not make these different
listing scopes interchangeable. At the documented 100-page boundary a full page
produces `publisher_page_limit`, never a completeness claim. An operator can
configure separately reviewed year routes; no guessed partitions are generated.

The `CISCO_OPENVULN_CLIENT_ID` and `CISCO_OPENVULN_CLIENT_SECRET` environment inputs
are handled only by the isolated Cisco transport. Missing inputs yield
`auth_not_configured`. Missing seeds yield `not_configured`. Unsupported actual
API envelopes yield `unsupported_response`; synthetic pagination tests do not
establish live authenticated API availability. The collector recognizes the
transport's advisory-array shape; optional `total`, `pageIndex` and `next` fields
are checked conservatively when present. No expected total is inferred from
page size, filenames or queue exhaustion.

Repeat the command to perform the full logical backfill in bounded invocations.
Matching source, window, study definition and enumeration revision resume the
same run. Page-size changes create separate API runs because pagination offsets
would otherwise change. Batch-budget changes preserve run identity. Different
observation ends or study definitions create independent enumeration manifests
while reusing the additive archive queue. Completed roots are not refreshed on
every invocation. Revisions observed during traversal remain evidence; overlapping
pages, changing or disappearing totals, total/count mismatches and pagination
cycles mark enumeration `unstable`. This detects observed inconsistencies; it
cannot prove an unversioned publisher listing did not silently move between
requests.

Listing bytes, discovered document queue links, per-occurrence identities and the
next checkpoint commit atomically. Every advertised representation remains linked
to its identity across duplicate occurrences, including missing-then-restored and
changed URLs; migration014 repairs earlier orphaned queue memberships. An
interruption replays the unfinished page.
Document ingestion uses the existing reviewed archive path and is idempotent
across interruption after ingestion. Failed items stay in queue counts; deferred
and exhausted failures are not reset. Listing failures also persist queue
attempts and backoff; a known successful page clears its completed retry state.
Reaching the API enumeration ceiling stops listing requests while subsequent
invocations continue bounded processing of already discovered documents. Cisco
cooldowns stop vendor I/O for the invocation. An unresolved request marker blocks
indefinitely, including after
reopening the vault; this command never clears or recovers it automatically.

The JSON receipt is operational staging data, separate from the strict public
switching report schemas. `manifest(db, study_id="campus-branch-switching")`
returns the same stored run inventory. Each entry includes:

- Source/kind/window, definition digest, enumeration revision and checkpoint.
- `coverage_state`: `not_configured`, `blocked`, `partial`, `enumerated` or
  `unstable`. `enumerated` means only the declared listing was traversed. Failed
  documents and historical gaps remain visible in that state.
- Nullable publisher `expected_total`, unique discovery identities, duplicate and
  withdrawn identities, retained/pending page counts and document queue states.
- Retained/retrieved/parsed, retrieval-failed and parse-failed counts; zero
  classified and explicit classification/model uncertainty pending later work.
- Unknown publisher dates, exhausted errors, stable error codes and retry time.
- Every retained listing URL/hash/retrieval time; literal publisher identity,
  revision/status/date and locator, advertised alternate URLs and all duplicate
  occurrence evidence. Successfully parsed document identity is exposed separately
  as `normalized_identity` when representations agree, with all parsed IDs in
  `normalized_identities`; it never changes discovery into model applicability.

Public archive links initially use exact URLs as discovery identities. Parser
identities are reconciled separately; alias merging and model qualification are
not inferred. Public listing dates and statuses remain unknown until a retained
parser result supplies them. No inaccessible document claims come from titles.

## Bounded source feasibility, 2026-11-04

Direct public captures were restricted to five successful Cisco samples and one
failed Aruba lead. Local staging receipts retain retrieval times, byte sizes and
SHA-256 values; these are source observations, not a full historical run.

| Category | Official source and observation | Remaining limit |
| --- | --- | --- |
| Catalyst-specific | [DHCP/endpoint analytics advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dhcp-dos-T3CXPO9z), initial 2024-03-27, Final 1.0; explicitly names Catalyst 9000 with feature conditions | Does not identify every target chassis/model; fixed software uses a checker rather than a complete static fixed-version table |
| Conditional family statement | [OpenSSH advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssh-rce-2024), initial 2024-07-02, updated 2024-09-13, HTML 1.16; conditional IOS XE/NETCONF row and release 17.15.1 | Family statement cannot automatically qualify named Catalyst models |
| Scheduled bundle | [ERP-75056](https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056), 2024-03-27, 1.0; explicit membership table and 13 advisories covering 14 vulnerabilities | Membership derives from this page, never same-day inference |
| Version branches | [Advertised Catalyst CSAF](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dhcp-dos-T3CXPO9z/csaf/cisco-sa-dhcp-dos-T3CXPO9z.json), matching identity/date, 1.0.0; 13 version branches | Version leaves require later product-ID-aware parsing; no automatic model/version matching |
| Alternate representation | [Advertised OpenSSH CSAF](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssh-rce-2024/csaf/cisco-sa-openssh-rce-2024.json), matching identity/date, 1.16.0 | Contains three SD-WAN families and generic remediation, omitting the HTML's IOS XE row; representations cannot be assumed equivalent |

The [known Aruba index](https://csaf.arubanetworking.hpe.com/index.txt) currently
starts in 2022. Exhausting it leaves `pre_2022_history_not_enumerated` visible.
The [2021 primary TXT lead](https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2021-019.txt)
is readable in a cached web view but direct current retrieval returned an HTTP
error. The historical bulletin page redirects to an HPE application shell. One
lead is not a complete 2021 archive; no guessed sequence-number crawl was added.

The [Arista public listing](https://www.arista.com/en/support/advisories-notices)
and its advertised `start=200` terminal page were inspected. The current root
includes advisory 0204 as an advance announcement. Discovery retains it without
inventing CVE/model applicability. Synthetic 21-page traversal tests preserve 52
exhausted failures and pending/draft candidates. The subsequent [staged run summary](research/2026-11-04-switching-backfill-summary.md)
records actual enumeration, parser failures, typed qualification and remaining
access limits. Reviewed core formats were bridged only at exact approved routes;
unsupported documents remain visible.

## Reading the published study

Choose **Vendor comparison → Campus/branch switching study · descriptive disclosure**.
The initial selection covers the full study from 2021-01-01 through the publication's
explicit observation end, all three vendors and OS-family context. Its scope,
vendor and year/pre/post/undated controls are independent of the older 24-CVE
benchmark, global product controls and KEV-only filter. The cutoff 2026-04-07 is
included in post; 2026 and the observation-end year remain partial.

**Counts measure disclosure, not vendor security quality; higher disclosure can reflect more scrutiny.**

Affected advisory/CVE totals require documented affectedness. Observed identities,
scoped drafts, fixed-only claims and explicit remediation-publication events remain
separate. Drafts lacking family/model context may be outside scoped rows; scoped
zero does not mean a vendor has no drafts. OS-family context and the named-model
subset overlap. Named-model zero means no qualifying observation, not no exposure.
Latest retained claims are grouped by the publisher's initial publication date;
revisions do not create a new disclosure. Explicit bundle membership and its initial
date determine bundled events. Events are publisher statements, not actual upgrades.
No fix-delay estimate, equivalence verdict, vendor ranking, causal interpretation or
automatic no-difference conclusion is provided.

Declared models are unequal sets: Catalyst 9200, 9300/9300L, C9407R/C9410R, 9500,
C9606R; CX 6300M/6410; and Arista 7050X3/720XP/750. The 7050X3 has a broader
data-center role; inclusion does not establish equal campus exposures. Arista 750
is not 7500. Lifecycle, release-train coverage and historical inventories remain
unresolved. Models and versions are never matched automatically.

Year, severity and scope sets are **nonadditive**. CVSS facets preserve reported
version, provider, origin and preferred status; values are structurally checked,
not independently rescored. Missing, invalid or incomplete scores remain unknown.
Vendor SIR/advisory ratings are separate advisory context, not CVSS conversions.
`publisher.sequence` is a publisher revision label, not an advisory SA number.
Explicit conditional affectedness is separate from null/unclassified conditionality.
Generic condition notes are context, not proven prerequisites or deployed settings.
KEV is evaluated against documented affected CVEs; stale/unavailable membership is
unknown under the existing freshness policy. Re-evaluate KEV freshness uses the
browser clock and retained inputs, without an upstream request or timer.

Source observation windows retain dates, nullable publisher totals, enumeration
state, queue/retrieval/parse errors and gaps. These are not exact per-year coverage
or historical completeness denominators. An exhausted listing does not prove a
complete exposure inventory. Unknown dates remain in the undated selection.
The separate **16-case switching extraction validation set** is automated checking;
independent human review remains pending. The original global extraction set does
not validate this new study.

The UI accepts selection counts, traceability, publication identity and downloads
together. Pending, failed, old or foreign-generation responses keep the last accepted
report and its controls/downloads. JSON downloads contain that exact selected report
with complete immutable inputs; CSV is its summary. A visible error is not an empty
successful study. Older publications without study assets explicitly show unavailable.

## Schema, browser adapter and native API

The closed v1 contracts are `switching-study`, `switching-evidence`,
`switching-comparison`, `switching-summary` and `switching-inputs` under `schemas/`.
A full comparison contains complete typed `{evidence, kev}` inputs; a summary has
`representation: "summary"` and excludes those inputs. Summaries must be hydrated
before reselection. Sources retain URLs, retrieval times, SHA-256, locators and
literal publisher identities/statuses. Trace selected claims shows the exact claim,
remediation, score and bundle context rather than inferred model applicability.

Native reader `GET /api/v1/switching-comparison` accepts optional single nonblank
`vendor=cisco|aruba|arista`, `scope=os_family|model_qualified`,
`window=all|pre|post|undated|YYYY`, canonical comma-separated `cves`, and
`format=json|csv`. Defaults are the full study/all vendors/OS-family/JSON summary.
Invalid, duplicate or unknown parameters return 400; unavailable old assets return
503. The endpoint reads immutable publication files without collection or vault access.

GitHub Pages is static hosting, not a native REST server. Its installed browser
fetch adapter provides the same selection/summary/CSV semantics to the reader from
fingerprinted assets; external REST clients cannot call that endpoint on Pages.
External clients can explicitly download `switching-comparison.json` (complete
inputs), `switching-evidence.json` and `switching-study.json`. The browser hydrates
verified study parts through `createStaticDelivery(fetch, siteBase).switchingReport()`;
normal bootstrap does not load the full study. Existing part/index/monitor byte
limits stay unchanged. JSON/CSV buttons create local Blobs from the accepted report.

CSV uses fixed columns, CRLF rows and quoted data cells; leading spreadsheet formula
controls are escaped. `totals_basis=repeated_totals_nonadditive` warns that totals
repeat per severity facet. `kev_basis=documented_affected_cves` identifies the KEV
denominator. Null historical denominators remain blank. Source-window states/errors
are descriptive metadata, never summed into per-year completeness.

## Staging, resume and cooldown

Keep all staging paths explicit, including publications, and use a separate reviewed
configuration; default source configurations are unchanged:

```sh
export IMPACT_HOME=/absolute/path/to/staging
export IMPACT_DATABASE=/absolute/path/to/staging/vault.sqlite3
export IMPACT_SOURCES=/absolute/path/to/staging/sources.json
export IMPACT_PUBLICATIONS=/absolute/path/to/staging/publications
impact switching-backfill --config /absolute/path/to/staging/sources.json \
  --start-date 2021-01-01 --end-date 2026-11-04 \
  --page-limit 2 --document-limit 8 --score-limit 0
```

Cisco authentication uses only `CISCO_OPENVULN_CLIENT_ID` and
`CISCO_OPENVULN_CLIENT_SECRET` environment inputs. Do not put their values in
configuration, commands, receipts or public assets. Re-run the identical backfill
command to resume a matching run; it does not publish. On cooldown, retain the
receipt's safe state/retry time, wait until eligible, then run the same command.
An unresolved persistent request marker remains blocked and needs separate operator
investigation; do not clear it to bypass quota safety. Keep operational receipts
private. No schedule, production ingest or deployment is required by this workflow.


## Release and monitor checks

The standard-library monitor reads the compact study summary and fingerprinted
schemas through the existing content-addressed index. It checks the study
identity, definition fingerprint, publication generation, selected counts, source
identities and declared part descriptors within the existing 20,000,000-byte
budget. Explicit incomplete or unknown coverage is healthy data. Older indexes
without the study report `switching_availability: unavailable`.

Ordinary monitoring does not download `switching-comparison.json`, the full
snapshot, compressed history or study detail parts. Detail bytes are verified
when the native/browser readers load them. Use `checks/public_health.py ORIGIN
--verify-archive` only for an explicit compressed-archive check. The manifest's
descriptors are checked without claiming unloaded detail bytes were verified.
Public CVSS metrics pass a closed-field monitor allowlist; private notes or added
metric fields fail the check. These gates do not independently rescore CVSS.

The unreleased evidence contract also records `reviewed_source_sections`
remediation bindings for Arista advisory 0100. The existing core parser checks the
reviewed section hashes; the bridge requires the exact affected EOS branch,
CVE-specific fixed EOS branch, source identity and locators. The retained fixed
claim and affected claim must agree on revision and publisher identity. This
records the explicit OS-family remediation publication, without deriving model
applicability, product IDs, an availability date or installed software state.
A fixed-only statement still cannot establish affectedness. Python and browser
contract checks reject mismatched source, CVE, product or revision links.
