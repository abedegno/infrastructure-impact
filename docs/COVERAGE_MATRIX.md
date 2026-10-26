# Evidence coverage matrix

Open **Vendor gaps** in the dashboard. Its first table shows operational evidence
coverage for every installed vendor, with the same vendor and gap filters as the
collection/review table below it. Download `vendor-gaps.json` or use
`GET /api/v1/vendor-gaps` on a Python deployment for the full report. Pages serves
the JSON file directly. The report covers the whole publication regardless of the
selected CVE cohort.

The optional additive `coverage` field in each version-1 vendor row contains:

| Field | Meaning |
| --- | --- |
| `configured_sources` | Feed, pin, release-document and archive URLs with source kind, role and configured document budget. Configuration does not prove successful retrieval. |
| `declared_product_families`, `declared_history_scope`, `declared_gaps` | Maintainer-reviewed coverage profile, not an observed portfolio census. |
| `capabilities` | Installed plugin interfaces; HTML capability does not mean every HTML layout is supported. |
| `observed_formats` | Source formats and document counts among retained normalized advisories. Discovery metadata and no-CVE notices can be included. |
| `archives` | Configured archive sources, per-pass page/document budgets, queue states and retained publisher date ranges. |
| `publisher_date_range` | Earliest/latest usable publisher dates among retained documents, not first disclosure dates or continuous historical coverage. |
| `documents_without_publisher_date` | Retained documents with no usable publisher date. |
| `unsupported_sources`, `access_blocked_sources`, `other_error_sources` | Latest retained failed-URL classifications. Unknown and legacy errors remain counted. These reconcile with the existing source-error total. |

Queue exhaustion describes discovered items only; it does not establish complete
archive enumeration or complete product coverage. Reposted advisories can retain
an older publisher date from a previous vendor. Sparse pins, active indexes and
bounded feeds have different discovery scopes. Dates alone cannot establish a
vendor's historical disclosure timing or whether a security update was concealed.

Coverage and gap fields are projected explicitly from configuration, public
coverage profiles, retained normalized records and source-audit metadata. Raw
source bytes, private review submissions and arbitrary archive fields are not
copied. Existing reports without the additive field remain schema-valid; older
publications display the existing gap view without a coverage table.

Source review and independent human review remain separate. Comparison rates
remain suppressed until coverage and evidence support them.
