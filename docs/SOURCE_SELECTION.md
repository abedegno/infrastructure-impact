# Reviewed publisher representation choices

A structured download is not guaranteed to enumerate the same product scope as
its HTML article. The collector normally follows an advertised CSAF link, but a
reviewed plugin can explicitly select another validated representation while
retaining the alternatives and explaining the choice.

The first policy covers Cisco's single-CVE
[regreSSHion campaign advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssh-rce-2024).
On 27 October 2026, the retained HTML normalized **89 affected and 119 explicit
unaffected product-label statements**. Its advertised CSAF normalized **three
SD-WAN affected statements**. Both identify the same advisory and CVE, and their
publisher update metadata identifies the September 2024 revision. These counts
are source-format observations, not unique physical products or comparable
exposure denominators. The HTML and CSAF scopes must not be assumed equivalent.
The difference does not establish intentional withholding.

## Source-led scope

The Cisco parser accepts one canonical URL, exact title, advisory identity,
single-CVE header, final status and dated metadata. It reads the product table
inside `div#vulnerableproducts` and the explicitly listed products inside
`div#productsconfirmednotvulnerable`. It rejects changed columns, unknown affected
categories, missing introductions, conflicting product labels and nested list
conditions. Layout tables surrounding the article and unrelated page lists never
become product rows. Repeated identical unaffected labels are coalesced while
preserving their publisher categories.

Only the current campaign CVE is enrolled; a historical vulnerability mentioned
in a footnote does not become another product claim. The parser does not expand a
publisher statement about unlisted products into blanket unaffectedness.

Affected-product rows do not supply affected version ranges. Fixed-release
entries remain remediation expressions, with bug IDs and source locators.
Estimated month/year entries remain **planned publisher claims even after that
month passes**. The passage of time cannot verify a release. Unknown, unavailable
and no-fix-planned expressions stay separate. Platform, configuration, model and
article-footnote qualifications require source review; no deployment exposure or
automatic version match is inferred.

The two literal ASA/FTD labels in this reviewed table are recognized by the Cisco
family matcher. FMC, SD-WAN and unrelated product labels are not added to the ASA/
FTD family by this change. Component studies expose the current family catalogue
version and scope fingerprint separately from frozen CVE enrollment. Source-led
matching refinements can change the report's evidence cells; they do not rewrite
the candidate list. Support/lifecycle windows remain a comparison blocker.

## Plugin contract

The existing optional `resolve(raw, url, fetch)` hook can still return the legacy
`(url, raw)` tuple. It may instead return:

```python
from infrastructure_impact.plugins import SourceSelection, SourceView, SourceViewIssue

selection = SourceSelection(
    selected=SourceView(
        url=html_url, raw=html_bytes, format=html_record["source_format"],
        assessments=len(html_record["assessments"]),
        adapter_version=html_record["adapter_version"],
    ),
    alternatives=(SourceView(
        url=csaf_url, raw=csaf_bytes, format=csaf_record["source_format"],
        assessments=len(csaf_record["assessments"]),
        adapter_version=csaf_record["adapter_version"],
    ),),
    reason="A short, reviewed explanation of the source choice.",
)
```

These example variable names stand for validated, identity-matching records and
bytes retrieved through the supplied allowlisted `fetch` callback. Plugins remain
trusted installed code, not remote configuration or executable source content.
Parsers themselves do not fetch, write storage or execute page scripts. The
orchestrator checks every selected, alternate and unavailable URL against the
same pure official-source policy used by transport and redirect handling. A
selection stops automatic structured-link following; it does not merge claims
from separate representations or transfer one capture's provenance to another.

If a reviewed primary source remains valid but its alternate cannot be retrieved
or validated, return an empty `alternatives` tuple and an `unavailable` tuple of
`SourceViewIssue(url, error_code)`. The total number of alternatives/issues is
bounded to four. Diagnostic bodies, cookies, headers and arbitrary exception
messages are not part of that contract. The valid primary remains usable, the
alternate failure is visible in collection health, and the main run is partial.
A later successful alternate check clears that URL's health error. A changed or
invalid primary layout fails explicitly and retains the prior valid advisory.

The built-in Cisco policy checks the advertised CSAF identity and CVE scope. Its
choice is based on the reviewed source structure, not an automatic rule that
whichever representation has more rows must be correct.

## Storage and public audit

Migration 009 adds append-only source selections, retained-view edges and bounded
issue metadata. Source bytes still use the existing deduplicated evidence store.
Repeated selection checks do not create new content captures. Source selection
time is an analysis/check timestamp; the public card separately identifies the
capture's first retained time and fingerprint. A source-view switch is recorded
as a source-view change, not newly discovered historical disclosure.

**Collection health** displays the selected and alternate formats, normalized
statement counts, parser fingerprints, retained capture times and SHA-256 values.
It includes alternate failures and the limits of comparison. The same metadata
is under `source_selections` in `/source-audit.json`, using
[`source-selection-v1.json`](../infrastructure_impact/schemas/source-selection-v1.json).

The public projection allowlists those metadata fields and official URLs, and
requires the selected URL/fingerprint to match a published advisory. Raw HTML,
CSAF bodies, extra diagnostics and private extension fields stay outside the
publication. Older read-only vaults have an empty selection audit; no past choice
or retrieval time is invented. Evidence audits verify graph integrity and raw
fingerprints. The source-choice counts are dated parser observations, not an
independent validation of extraction accuracy.

Synthetic tests cover product/CVE boundaries, old estimated dates, duplicate
labels, changed layouts, alternate failures/recovery, exact route policy,
backward-compatible tuple resolution, partial-run accounting and public privacy.
Independent human adjudication of the new product statements remains pending.

Resolution returns the selected bytes and bounded metadata without persisting a choice. Collection writers retain that metadata after validated ingestion. Retained-source triage works through a read-only vault connection and cannot create successful collection checks, selection history or advisory revisions. A missing retained alternate is reported separately from a failed live retrieval.
