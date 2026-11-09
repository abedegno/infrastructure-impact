# Switching remediation, release history and customer comparison

The maintainer authorized all three recommended steps: source-owned Aruba/Arista
fix links, dated release/bundle history, and a customer comparison page. Routine
planning questions were previously waived. Execute in that order using existing
plugins, schema v2, publication readers and browser controls. Hosted schedule or
permission changes remain separately gated; never read the original operator
configuration, private vault/key or private worker logs locally.

## Goal and boundaries

Make the customer's operational question inspectable: observed affected CVEs,
severity/KEV, explicit fixes/releases/bundles, model applicability and coverage.
CVE totals, advisory/remediation publications, reported software releases and
actual customer upgrades are different quantities. No vendor security ranking,
concealment finding, causal AI inference, automatic version arithmetic or model
applicability inference. Missing dates, sources and links stay visible as unknown.
Independent human evidence review remains pending.

## Approach

Extend source-specific adapters and the existing typed switching evidence model;
reuse release-history hooks and retained document observations. A permissive
family/version join would create unsupported links. A separate integration stack
would duplicate provenance and publication validation. Neither is selected.

Deliver three coherent stages, each tested before the next builds on it:

1. Repair source-owned fix links. Keep fixed claims and original product IDs;
   attach copies with explicit reviewed-section provenance rather than rewrite
   publisher identities. Validate matching fixed siblings in Python, browser and
   streaming readers. Preserve same-CVE/source/revision/product ownership and
   non-fixed/planned/negated/mixed-product exclusions.
2. Normalize release and bundle history with actual reported dates and provenance.
   Use official public release documents through existing retained-document paths;
   do not expose private browser captures. Distinguish patch releases, release
   trains, advisory/bundle dates and unavailable dates. Link a fixed release to a
   dated release only by an explicit vendor/product-owned literal identity; no
   range arithmetic, next-version selection or train-date substitution. A release
   without a justified CVE link is context, not a resolved-CVE count.
3. Add a customer summary beside the current switching study. Reuse selected
   CVE/severity/KEV/coverage/model sets rather than calculate another denominator.
   Load release history lazily using publication-bound metadata. Show source links,
   unknowns, advisory-window basis and separate software-release dates. Provide
   JSON/CSV parity and retain compatibility with older publications lacking assets.

## First source-owned repair set

Aruba HPESBNW04669 / CVE-2024-6387 has explicit affected and fixed AOS-CX siblings
but no direct CSAF affected-to-fixed relationship object. Allow only three reviewed
section associations: the exact 10.14 affected ID to 10.14.0007, 10.13 to10.13.1031,
and10.10 to10.10.1131. These are reviewed derivations from the same-CVE/product-owned
source sections, not publisher-ID equivalence or computed version matching.
Leave10.11/10.12 migration, legacy unaffected and foreign products unresolved.
Preserve the original remediation product set and record the exact fixed ID in
scope_binding. A source revision outside the reviewed ownership guard fails closed.

Arista SA0128/CVE-2025-8872 and SA0201/CVE-2026-111943 already have affected EOS
claims and literal fixed lists. Add fixed claims and reviewed affected-to-fixed
links with section boundaries, including EOS versus TerminAttr isolation. SA0075 /
CVE-2022-0778 needs its reviewed older EOS layout. SA0070 and SA0081 exclude EOS;
they must not gain an EOS remediation. Existing SA0100 semantics remain unchanged.
All new fixed lists report availability, not software release dates.

Arista SA0148 explicitly groups linked advisory identities; its summary's initial
publication and the body's member-publication date differ. Preserve both distinct
facts; neither supplies software availability. Existing Cisco ERP-75056 bundle
semantics remain unchanged. No same-day grouping or generated member URLs.

## Release evidence limits discovered in recon

The current Aruba history adapter covers unrelated4100i/10.13; Arista's covers
CloudVision train dates. Neither establishes this switching cohort's patch dates.
Several official6300/6400 PDF links returned404, and the Arista software-download
entry redirects to login. Search snippets are discovery leads, not acquired source
bytes or confirmed release dates. Implement explicit unavailable/unparsed states,
then populate dates only where retrievable primary evidence supports them.

## Contracts and verification

Advisory schema v2 and frozen study definition remain unchanged. Extend typed
scope_binding additively for AOS-CX, with exact fixed product identity and semantic
ownership checks. Regenerate browser contracts from the canonical schemas. Do not
relax old guards or byte/storage/candidate limits. New release reporting gets its
own versioned schema and current-source public projection; no caller-supplied
private notes, captures or review assertions may enter a public report.

Use authored synthetic fixtures in Git. Reuse cached public captures for local
acceptance outside Git, preserving URL, SHA256, real retrieval time and revisions.
Test foreign CVE/product/hash/revision/locator, duplicate/missing fixed siblings,
unknown/planned/negated/lifecycle text, cross-train and cross-product clauses,
ambiguous literal dates, unsupported layouts, stale generations and old assets.
Complete focused tests per task, whole-branch review and final CI. Keep existing
fresh-worker, privacy, native/static and publication acceptance gates mandatory.

## Release/report stage decisions after source reconnaissance

Reuse ReferenceSource and reference_documents for the reviewed public histories;
add purpose=release_history and pure vendor source adapters. This avoids another
collector, DB schema or private-browser publication path. All documents normalize
to software-release-evidence-v1; the legacy posted-only browser history contract
is unchanged. New vendor sources require an exact registered URL and parser.

Working Aruba6300/6400 consolidated10.14 and10.16 HTML tables provide real origin
bytes. Dates are publisher-reported retrospective testimony. One10.14 row asserts
posting; another only says Initial release. The latter retains unknown posting.
The companion supported-products table has SKU-specific minimum versions; retain
literal support context without applying version arithmetic or inferring every
6300M/6410 release is supported. Cisco's reviewed17.12.1 model page labels a release
date, but the collection probe returned403; preserve disabled/unavailable state
until acquired. Arista patch-release dates remain unavailable; explicit fixed
release references can still be shown with unknown dates.

Reference documents preserve their own source capture and parser times. Public
projection uses only registered public release sources, closed normalized fields
and current typed claims. Do not publish private browser captures or private fix
review checks. A new switching-release-history report joins only literal named
fixed releases from validated source-owned remediations. The original expression,
claim IDs, CVE/advisory identity and source remain attached. No earliest/latest
version matching, cross-train migration, train-date substitution or model inference.
Where the same literal release has conflicting dates, show conflicting evidence
rather than choose one. A history entry without justified fix links is context;
absence of links is not zero vulnerabilities resolved.

Bundle history keeps notice initial publication separate from explicit member
publication date and from software availability. New Arista0148 bundle context
must not overwrite existing typed event dates or become an inferred upgrade.
Existing Cisco typed bundles are reused. Software dates never come from capture,
advisory, HTTP Last-Modified or search-index timestamps.

The customer view is an additional Vendor comparison mode using existing study
controls/selection and lazy release-history loading. A customer envelope combines
existing study summary, selected release history and limitations; it does not
create another CVE denominator. JSON/CSV and the native API derive from the same
pure selectors as the static browser. Old publications without release assets
show explicit unavailable history while retaining the existing study summary.
Keep report roots bounded and optional for old generations; avoid duplicating
full claim bodies or rebuilding study facts separately for each customer view.

Explicit CVE-specific fixed-only claims may supply publisher-reported fixed-release
context independently of an affected range. The report must distinguish
vendor-reported fixed CVEs from affected-scope-linked cohort CVEs. Fixed-only
context never authorizes affectedness, model applicability or an upgrade event.
