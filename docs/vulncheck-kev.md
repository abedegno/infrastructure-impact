# VulnCheck KEV: optional private comparison

VulnCheck Known Exploited Vulnerabilities adds a second, independently attributed
exploitation signal alongside CISA KEV. This first integration collects an official
backup into an explicit private SQLite file and compares exact CVE IDs. It does not
change advisory affectedness, product/model binding, frozen studies or public KEV counts.

## Collect and compare

Create a Community API token through VulnCheck. Set `VULNCHECK_API_TOKEN` in the
collector environment, using a private credential file outside the repository or
your secret manager. Do not put the value in command arguments or commit it.
The CLI does not load `.env` files automatically. For example, if your credential
file contains a shell assignment for this variable:

```sh
set -a
. "$HOME/.config/infrastructure-impact/vulncheck.env"
set +a
impact vulncheck-kev collect --state /private/path/vulncheck.sqlite
impact vulncheck-kev report --state /private/path/vulncheck.sqlite \
  --cve CVE-2026-10001 --cve CVE-2026-10002
```

The CVEs above are synthetic examples. Use `--scope scope.json` for a JSON array
of exact CVE IDs, such as a separately extracted study cohort. Add
`--cisa-report /path/to/kev.json` to compare an existing published `kev-v1` report.
It is validated and its freshness re-evaluated at report time; a stale report
does not count as a verified CISA negative. Supply a fresh public report for a
current comparison. Without it, CISA membership and overlap counts remain unknown.

## Use the website research panel

Expand **Exploitation sources · private VulnCheck research** and choose the JSON
produced by `impact vulncheck-kev report`. Generate it for all CVEs you want to
investigate; CVEs outside that file's scope remain **unknown**, not “not listed”.
The panel accepts at most 8 MB, validates the report, and keeps it in browser
memory. It makes no upload or API request and does not use browser storage. Reload
the page or choose **Clear local evidence** to remove it. Do not select an `.env`
or credential file.

The research panel offers independent CISA-listed, VulnCheck-listed, both-listed and
unknown filters. They affect that panel only. Product-impact and assessment detail
views also show attributed VulnCheck context when local evidence is loaded, with
listing/reference dates and safe citation links. Malformed citation URLs remain
inert text. Use **Recheck freshness** after leaving the page open; stale or failed
collection turns membership into unknown while retaining historical evidence.

In the customer/switching comparison, vendor counts are intersections with the
accepted study's exact `affected_cve_ids`, deduplicated per vendor. They follow its
vendor, period and model-scope controls. No vendor mapping is inferred from the
VulnCheck product label. A partially covered scope has an unknown total with a
separate unknown-CVE count; it is not displayed as a verified zero. CISA membership
comes from the site's complete CISA report when available, otherwise from a fresh
CISA source in the imported CLI report. If neither is available it remains unknown,
even if another published view contains historical CISA counts.

The local overlay is separate from the accepted publication. It does not alter
cohort controls elsewhere, frozen studies, JSON/CSV downloads, public KEV counts or
normalization schema v2. Source verification times and study publication identity
remain visible so current catalogue membership is not confused with past exposure.

Reports go to stdout and include prominent VulnCheck attribution, source URL,
ZIP SHA-256, retrieval and verification times, backup timestamp, revision identity,
publisher labels, listing dates and reported-exploitation references. Treat redirected
output as private research data. Labels identify what the provider says; they do
not establish that a specific switch, release or configuration is affected.
Missing labels remain explicit in `missing_labels` and do not discard exact-CVE
membership. Citation URLs retain the publisher's literal text: HTTP and HTTPS
references may include fragments; malformed references carry
`url_status: publisher_url_unresolved`. No citation is fetched or silently repaired.

## Collection and evidence

The official [backup endpoint](https://docs.vulncheck.com/api/v3/backup) returns a
signed download URL and SHA-256. Authentication is sent only to the fixed API
endpoint. The download accepts only HTTPS `serve.vulncheck.com`, without forwarding
the bearer token. Redirects are rejected. Signed URLs and remote exception bodies
are never stored or printed.

Successful collection is cached for 24 hours. `collect --force` rechecks backup
metadata; an identical hash reuses the retained ZIP without downloading it again.
Changed backups append revisions, retaining raw ZIP bytes, hash, initial retrieval
time, publisher backup date and normalized membership. Collection attempts retain
verification time and stable outcome codes. A later return to an older backup hash
selects that verified revision rather than whichever revision has the largest ID.
No automatic pruning removes evidence.

HTTP 429 and service failures defer subsequent attempts; integer and HTTP-date
`Retry-After` headers are honored between 60 seconds and one day. Otherwise backoff is 60 seconds.
`--force` never bypasses persisted backoff. There is no retry loop or background
schedule. Re-run the command after the returned `retry_at`. A collect command
returns nonzero on failure or deferral.

ZIP input is bounded to 32 MB compressed and one JSON member of at most 128 MB,
with at most 100,000 normalized CVEs. No archive member is extracted to disk.
Duplicate CVEs, malformed identities/dates and ambiguous JSON are rejected as a
whole, rather than creating a partially populated catalogue. The dedicated SQLite
file is mode 0600 and separate from the evidence vault and publication machinery.
Keep it outside the repository, static site and artifact-upload paths. Do not use
the main vault as `--state`.

## Meaning and limitations

- Membership is `listed`, `not_listed` or `unknown`, separately for each provider.
  Latest collection failure, missing evidence, future verification or verification
  older than 36 hours makes VulnCheck membership unknown. Retained positive evidence
  remains visible with that qualification.
- Verification freshness describes our latest successful backup check; the
  publisher backup timestamp is shown separately. It is not a guarantee of feed
  completeness or publisher update latency.
- Listing and reference-added dates are not exploitation start dates. Canary
  observations are kept distinct from public reported-exploitation references.
  XDB/PoC availability is not treated as exploitation evidence; exploit repositories
  are never downloaded or cloned.
- Missing membership is not proof that exploitation has not occurred. Source
  overlap measures coverage, not detection quality or vendor security quality.
- Coverage improvement must be measured with a token-backed collection and an
  explicitly identified cohort. A successful local run does not activate hosted
  collection or change public counts. Tests use authored synthetic fixtures only.
  Independent human review remains pending.

## Publication boundary and licensing

The code is Apache-2.0; that does not relicense VulnCheck data. VulnCheck's
[attribution guidance](https://docs.vulncheck.com/community/vulncheck-kev/attribution)
describes free integration with prominent attribution. Its
[service terms](https://www.vulncheck.com/service-terms) also contain restrictions
on making Service Data freely available and on AI use. Confirm the terms applicable
to this deployment before publishing derived fields, reports or raw feed records.
Do not supply licensed feed contents to an AI agent for analysis.

The feed is deliberately absent from the public source registry, default collector,
snapshot/API/CSV exports and hosted workflows. The website reader supports local
imports only; it does not ship a VulnCheck dataset. Report output is labelled
`private_research_only`. Hosted credentials, activation and public export require
separate decisions; adding the reader does not authorize them. After terms are
confirmed, hosted collection and an attributed published signal can use the same
membership semantics, keeping CISA and VulnCheck distinct.
