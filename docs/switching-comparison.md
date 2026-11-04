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
next checkpoint commit atomically. An interruption replays the unfinished page.
Document ingestion uses the existing reviewed archive path and is idempotent
across interruption after ingestion. Failed items stay in queue counts; deferred
and exhausted failures are not reset. Cisco cooldowns stop vendor I/O for the
invocation. An unresolved request marker blocks indefinitely, including after
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
  as `normalized_identity`; it never changes discovery into model applicability.

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
exhausted failures and pending/draft candidates. A fresh live audit of all those
historical failures and the full real staging backfill remain subsequent work;
no parser route was widened to make an error disappear.
