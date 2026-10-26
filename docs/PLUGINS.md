# Adding a vendor

A CSAF/CVE JSON vendor can use the existing shared parser. The complete example is
in `examples/vendor-plugin`; its `.example` domain is synthetic and must not be
used as a real feed.

```python
from infrastructure_impact.plugins import VendorPlugin
from infrastructure_impact.plugins.shared import structured

def plugin():
    return VendorPlugin(
        id="acme", name="Acme Example Networking",
        domains=("acme.example",), parse_document=structured,
        version="0.1.0", capabilities=("csaf", "cve-json"),
    )
```

Register its factory in the extension distribution:

```toml
[project.entry-points."infrastructure_impact.vendors"]
acme = "acme_impact_plugin:plugin"
```

Install it into the writer's environment/image, add its source configuration and
restart the writer. `impact plugins` shows the discovered catalogue. No core,
database-table or frontend change is needed. The publication carries vendor names
and assessments, so a reader need not install normalization plugins.

```json
{
  "vendors": [
    {"vendor":"acme","kind":"index","url":"https://security.acme.example/csaf/index.txt","limit":4}
  ],
  "pinned": [],
  "release_documents": []
}
```

## Interface

`parse_document(raw, url, vendor)` returns a fresh normalized advisory dictionary.
The registry canonicalizes JSON, assigns an adapter fingerprint and validates it.
Parsers must not fetch URLs, write databases, send messages or execute source
JavaScript. Preserve publisher expressions, platform/configuration qualifiers
and evidence locators. Unknown layouts must fail explicitly.

| Optional hook | Purpose |
| --- | --- |
| `parse_release(raw, url, vendor)` | Return release-asset metadata under schema v1; no CVE claims or firmware fetches. |
| `parse_feed(raw, url, limit, cohort)` | Return `FeedBatch`: selected records, all referenced CVEs, exact inspected scope, outcome. |
| `canonicalize(url)` | Map known official URL forms to a canonical official source. |
| `resolve(raw, url, fetch)` | Locate another representation using the supplied allowlisted fetch callback. |
| `prefer_existing(old, new)` | Prevent a short index row from replacing a detailed article. |
| `non_cve_notice(record)` | Recognize a valid informational notice outside CVE scope. |
| `reference_filter(url)` | Disambiguate upstream references for vendors sharing official domains. |

Generic discovery supports RSS/Atom and newline-separated CSAF indexes. Special
feed semantics belong in the plugin. Feed kinds are `rss`, `index` and
`advisory_index`; the old `checkpoint` kind remains a compatibility alias. Unknown
vendors, misspelled configuration keys and explicit missing paths fail before
fetching. HTTPS/port/domain/redirect rules are enforced by transport. The
`upstream` identity is reserved.

## Acceptance and deployment

Retain provenance and suitable fixtures. Test affected, unaffected, investigating
and unresolved examples as applicable; exercise CVE/product/OS/configuration
boundaries. Shared bulletin tables must remain shared. Planned, partial and
vendor-reported fixes are different assertions. Verify idempotence and that parser
changes cannot manufacture publisher-disclosure alerts.

Run `uv build --wheel` and `uv run python checks/distribution.py` for an actual
out-of-checkout extension proof. The probe installs a separately packaged ninth
vendor and exercises normalization, persistence, publication and HTTP without
changing production data. For real deployments, lock the extension distribution
and its dependencies in the writer image; do not rely on an untracked editable
installation. Installed plugins are trusted application code, not sandboxed code.

`parse_release_history(raw, url, vendor)` is an optional pure parser for reviewed
browser-rendered release-history articles. It returns the strict
`schemas/release-history-v1.json` contract. It must validate document, product and
branch scope and reject changed or incomplete row layouts. Capture-envelope
validation, evidence persistence, duplicate/conflicting date checks and the
operator's expected-version query belong to the application layer. This hook
does not enable scheduled browser retrieval. See [BROWSER_CAPTURE.md](BROWSER_CAPTURE.md).

Document-link archives reuse the existing resolver and normalized advisory schema.
Plugins without a metadata/record `parse_feed` hook can configure reviewed official
RSS/Atom or CSAF index seeds without changing core dispatch. See
[Archive collection](ARCHIVE_COLLECTION.md) for budgets, pagination, provenance and
unsupported historical enumeration paths.

`parse_archive(raw, url, vendor)` is an optional pure discovery hook for reviewed
HTML listings. Return the immutable `ArchivePage(urls, entry_count,
entries_without_links=0, next_pages=(), scope="")` contract, using tuples of URLs.
Use `kind: "listing"` in the archive configuration. The orchestrator enforces the
same official-domain, page/document budgets, retries and evidence edges as RSS
and text-index sources; the hook must not fetch or execute JavaScript. Missing or
changed pagination controls must fail, rather than pretend the archive ended.
`scope` records any publisher product filters in the source audit. Listing text
never becomes a product assessment. The separately installed example plugin and
wheel probe exercise this extension boundary.

`parse_document_history(raw, url, vendor)` optionally returns `product`, `version`
and `events` for a reviewed documentation change-log source, or `None` for a source
outside its supported layout. Each event has a publisher calendar date, kind
(`initial_document_release` or `cve_references_added`), CVE IDs and exact source
locator. This hook is distinct from `parse_release_history`, which describes
release trains in a reviewed lifecycle panel. Documentation dates never establish
firmware availability. Invalid supported layouts raise a parser error and appear
as an unresolved history document. Public output uses the shared publisher-history
schema and configured release-source boundary.

Product-role classification is data-driven and vendor-specific. External vendors
receive unmapped classification until reviewed family rules are added; see
[Product groups](PRODUCT_GROUPS.md). Installed plugins still require no core parser
dispatch or database changes.

## Bounded feed follow-ups and route guards

`FeedBatch.document_urls` optionally supplies up to 20 document URLs (an immutable
tuple, empty by default). The collector checks each against the plugin allowlist
and runs the normal document fetch, resolver, normalization, schema and evidence
pipeline. A feed title alone never establishes product applicability. Juniper
emits at most eight selected Security Bulletin registry routes; reference titles
are discovery metadata only.

`VendorPlugin.url_filter` optionally narrows approved domains to reviewed routes.
It applies to configuration, transport and redirects. Juniper permits the exact
CVE registry host and `/api/cve/CVE-YYYY-NNNN...` route, without query or fragment.
Its parser additionally requires Juniper's configured CNA organization in both
metadata and the CNA container, matching record identity, published state and
Juniper product rows. Generic upstream and ADP enrichment cannot supply a Juniper
impact assessment. Publisher configurations and solutions remain attributed
context; they do not independently prove firmware availability.

## Explicit retention of notices without CVE identifiers

`retain_unlinked_notice(document)` is an optional plugin hook, false by default.
A reviewed parser may opt in a stable, schema-valid notice with an empty CVE list
and no product assessments. The bundled opt-in is restricted to the exact reviewed
Arista 0146 and 0141 identities, source URLs and format. When an advertised CSAF
file contains no product dispositions, the resolver can retain a reviewed HTML
notice only through this explicit hook; an arbitrary empty envelope is insufficient. Unknown empty records still fail
storage validation. This is distinct from `non_cve_notice`, which excludes known
non-CVE material from advisory ingestion. No GHSA-to-CVE association is inferred.
Unlinked retained notices appear in the global Vendor gaps report; they do not
appear as CVE impact claims in cohort exports or comparisons.

## Repeated CNA release branches

The shared CNA adapter can combine repeated product/platform blocks when other
scope metadata and version-status sets agree. It retains distinct version objects,
change points, CPEs and contributing row indices. Conflicting scope, defaults,
statuses or same-start range expressions fail closed. A warning records that
version overlap and ordering were not inferred. This does not turn release branches
into independently verified inventory applicability.

## Vendor-authored registry delivery

Cisco, Juniper, HPE and Check Point plugins accept only exact HTTPS CVE registry
record routes on `cveawg.mitre.org`. The shared adapter checks the requested CVE,
publication state, pinned assigner/provider organization IDs, product-vendor names
and an official publisher reference. It retains the English descriptions,
configuration, solutions and workarounds as attributed context. Title references
and ADP containers cannot broaden product/CVE scope.

A published record consistently authored by another CNA raises
`SourceNotApplicable`. The normal collector records this exclusion without
creating a vendor advisory or counting a failed fetch. Missing or contradictory
identity metadata remains an error. The source is not proof that the requested
vendor is unaffected. This exception is part of the plugin contract; it is distinct
from retaining a no-CVE security notice.

Cisco RSS retains its selected primary advisory URLs and adds up to eight registry
follow-ups. Check Point's selected active-index records similarly add up to eight.
Every follow-up needs independent publisher verification. HPE's new OneView sources
are curated pins; a general HPE discovery feed is still absent. Existing blocked
SK and Cisco archive/release checks remain separate gaps.
