# Comparison eligibility

The Vendor comparison view and `/api/v1/comparison-eligibility` use one explicit
period and CVE cohort, with an exact product-label scope for each vendor. The
canonical derived contract is `schemas/comparison-eligibility-v1.json`;
`comparison-eligibility.json` contains the default report for a static generation.

## Reporting window and product scope

The default is 365 inclusive calendar days ending on the publication's UTC date.
Operators can choose valid `start` and `end` dates from 1900 onward; end cannot
exceed publication date. The current day can be partial. Date-only publisher
values retain their calendar date; timezone-qualified timestamps use their UTC
date. Missing dates, invalid dates and timezone-unspecified timestamps do not
enter period counts. Future timestamps and drafts are excluded and counted.

The window groups **latest retained statements by the initial publication date
of their advisory**. It does not use update or collection dates as a substitute.
This is not an as-of historical exposure reconstruction. A CVE or product claim
may have been added after the advisory was first published; the initial date does
not date the individual statement. Outside-window and unusable-date exclusions
remain visible, alongside all current source and archive limitations.

By default each vendor's scope includes its retained non-draft product labels.
The optional `products` mapping selects exact publisher labels for each vendor.
A missing vendor key keeps all retained labels; an empty array selects none.
Unknown labels/vendors are errors. Selections allow up to 20 labels per vendor
and a total JSON encoding of 4096 UTF-8 bytes. Version, hardware, deployment and
configuration qualifications stay attached to the underlying normalized evidence;
a label selection is not automatic appliance applicability or a full inventory.
Declared product families are context, not certified portfolio denominators.

The web selector displays publisher family context beside literal labels, which
can otherwise be only a version number. Labels used by multiple families are
marked as shared; missing family context remains explicit. These display names
do not split or merge filter identities: selecting one label still includes its
matching statements across those families. Static cohort delivery builds this
context from the whole public publication, so narrowing the CVE selection does
not hide a label's other retained family contexts. Draft statements are excluded.

## Eligible observations and suppressed conclusions

Distinct CVE counts describe the selected retained evidence. A CVE may have
statements for multiple products and appear in several columns. The report
separates CVE-specific affected/partially mitigated, shared-bulletin affected,
CVE-specific unaffected, fixed, explicit unknown and missing product statements.
It also counts CVEs without a CVE-specific affected/unaffected assessment.
A fixed-only statement does not establish previous affectedness. Absence of an
assessment is never turned into unaffectedness or a disclosure failure.

The UI shows **Unavailable** for affected/unaffected/fixed count cells when no
usable product statement exists in the period and scope. Zero explicit-unknown
statements and zero unaffected statements have different meanings. Investigating,
recommendation and conflicting states remain in the JSON and per-CVE inspection.

Every vendor row includes source-error URLs and check times, stale or unchecked
configured URLs, declared history scope, product filters, archive progress and
queue failures. Successful collection or exhausting known links does not certify
full historical coverage. These operational counts are not tested product coverage
or a percentage of a vendor's estate. Source checks can include historical URLs.

Version 1 deliberately suppresses vendor-rate rankings, first-disclosure delays
and fix-delay metrics. No comparable portfolio denominator, verified individual
CVE statement date, complete disclosure history, or independently verified
fix-availability/product-CVE linkage is certified by this dataset. These metrics
stay suppressed even if a queue is exhausted or every URL is healthy. Private
review candidates, planned releases, fixed-only statements and release listings
cannot unlock them. Future verified-event/denominator policies require an explicit
reviewed contract; no such certification or override is implemented in v1.

## Paired document metadata

The inspection panel can show individual advisory/upstream publication pairs for
CVE-specific statements in the selected period and scope. Both timestamps must
be timezone-qualified and no later than the generation; both source URLs and
retained SHA-256 fingerprints are required. Date-only values are insufficient
for numeric offsets. Conflicting statements suppress the case's pairs.
`offset_seconds` is the signed difference at whole Unix-second resolution; the UI
shows an approximate number of days. Negative offsets are retained as metadata,
not interpreted as disclosure speed. There is no earliest/average vendor score.

Even a precise, fingerprinted date pair does not prove when that CVE was first
mentioned. `first_disclosure_days` and `verified_fix_delay_days` remain null for
every case. Other known undated statements are reported without implying that
the dated pairs are an earliest disclosure. The deprecated unscoped `delays`
array is empty in publications and exports; use these qualified observations.

## API, static site and exports

```text
GET /api/v1/comparison-eligibility?cves=CVE-2024-6387&start=2024-01-01&end=2024-12-31
GET /api/v1/comparison-eligibility?vendor=arista&products={"arista":["EOS"]}
```

URL-encode the JSON product mapping in a real request, and obtain exact labels
from normalized records rather than assuming the illustrative `EOS` label exists.
Native query routes require the Python reader. GitHub Pages calculates the same
report locally from its immutable public snapshot; it never contacts vendor sites.
Python/static parity tests cover controls, dates, scopes, missing evidence and
suppressed conclusions. An external installed plugin uses the same policy.

The dashboard's **Download scoped comparison JSON** contains the selected period,
cohort, product controls, cases, source limits and generation identity. The global
JSON/CSV record exports remain cohort-filtered evidence, including records outside
the comparison window. Legacy `comparison` counts remain an unscoped cohort
summary for compatibility. `start`, `end` and `products` on `/api/state` and the
bulk JSON export affect `comparison_eligibility`, not the underlying record scope.
Use the dedicated endpoint or scoped download for the qualified comparison.

The publication boundary rebuilds this report after removing private review
material, validates its strict schema, and exports no private fix-candidate notes
or raw evidence. No database migration or additional network collection is needed.

## Product-role filtering

A shared `group` control narrows statements using the versioned source-linked
[product taxonomy](PRODUCT_GROUPS.md). Exact labels intersect the role filter.
Unmapped and ambiguous labels are excluded from a specific group and remain
visible in grouping coverage. Role classification does not establish equivalent
portfolios or remove any existing metric suppression. The downloaded report
includes the group ID and taxonomy version.
