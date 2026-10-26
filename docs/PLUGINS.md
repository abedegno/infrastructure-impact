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
