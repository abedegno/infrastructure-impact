# Vendor evidence scorecards and revision timelines

Scorecards summarize publisher statements within a selected CVE cohort. They are
not security scores or a ranking. There is no denominator for fleet size, installed
base, total portfolio or tested components. A vendor with missing statements does
not appear safer because it has fewer observed affected products.

Each vendor card preserves the selected cohort size and reports overlapping
counts of affected, unaffected, fixed, investigating, partially mitigated,
conflicting, unknown and recommendation states. One CVE can count in several
states across products or version branches. Explicit unknown claims are separate
from CVEs with no product statement. Draft advisories are excluded. CVE-specific
and shared-bulletin statement counts remain separate.

CVE details link to the product matrix, where original product/version expressions,
configuration scope, source hashes and evidence locators can be inspected. Product
labels are publisher labels, not normalized fleet inventory or unique devices.

Source-health counts use distinct configured URLs for that vendor. Historical
checks for sources no longer configured do not inflate that denominator. Errors
for discovered or historical URLs outside it are shown separately, so configured
feed success cannot hide a failed advisory fetch. Failed,
partial, stale and unattempted sources remain visible alongside coverage profiles
and known gaps. Stale check counts can overlap error counts. A fresh successful
feed check does not establish comprehensive product coverage or a recent review
of every assertion retained from that feed.

## Timeline clocks and limits

The timeline is ordered by local revision observation. Publisher publication,
update and reported fix dates are shown separately as retained claims. A first
observation may be years after the vendor's first publication. Fix dates retain
single-CVE-document or shared-document scope; they are not automatically assigned
to every product branch or verified as historic download availability.

Events distinguish first observations, source assessment revisions, parser
reinterpretations, source-view changes and refreshes without a scoped semantic
change. General source revisions are distinguished from assessment changes;
previous retained status sets are available without collapsing product branches. Added CVE references are flagged only under the existing source-change
checks. Removed references are represented explicitly and never become unaffected
claims. Draft document status remains visible in history.

The public timeline contains only revision IDs, source URL/hash, observation and
publisher dates, document status, CVE/status summaries and changed field names.
It excludes raw documents, publisher narrative timelines, private notes and browser
capture contents. Older timeline events remain identifiable by retained source
hash even if their source is revised again.

The default publication includes at most 5,000 newest revisions and 5,000 newest
CVE events. `history_truncated` and `events_truncated` identify those limits;
`revision_limit` and `event_limit` give the configured bounds. A cropped window
must not relabel its first included revision as the first observation. Filtering
an exported cohort operates within that retained window, not the full vault.

## Read-only contracts

`scorecards.json` and `timeline.json` contain complete derived metadata for the
publication. The self-hosted API additionally supports:

- `GET /api/v1/scorecards?cves=CVE-2024-6387&vendor=arista`
- `GET /api/v1/timeline?cves=CVE-2024-6387&vendor=arista`

Both return `schema_version: 1`, generation time and the immutable publication
identifier; the standalone static files carry the same publication metadata. CVE
queries follow the existing 200-ID limit; unknown vendor IDs return HTTP 400.
Scorecards contain a `vendors` array with per-CVE `cases`, `status_counts`,
statement totals, configured source outcomes and coverage context. Timelines
contain an `events` array and explicit window-limit metadata. Dates retain their
original precision; timezone-unspecified publisher times are labelled in the UI.

GitHub Pages uses the static files and browser cohort filtering. There is no Python
API backend on Pages. Native and browser selection are checked against the same
synthetic datasets, including requested CVEs absent from the collection. JSON
exports follow the current selected cohort; CSV continues to export product claims.

Disclosure leads remain in Disclosure review, with their existing evidence and
review requirements. These views do not auto-register a silent fix, assert
concealment, or convert absence of a disclosure into affectedness.
