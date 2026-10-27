# Component reference studies

The **Component studies** view joins a frozen, outcome-independent component
reference list to retained vendor family statements. It answers “what evidence do
we hold for each of these CVE/family pairs?” It does not estimate which vendor is
more secure, count unknowns as unaffected, or establish concealment.

The first study is `openssh-service-2023-2026`, version `2026-10-26.1`. Its frozen
selection and role review are in
[`openssh-service-2023-2026.json`](../infrastructure_impact/resources/studies/openssh-service-2023-2026.json).
The SHA-256 covers the period, family list, candidate reviews and selection rule;
the loader rejects a changed enrollment with a stale fingerprint.

## Enrollment and limits

[Apstra server release-note references](research/juniper-apstra-openssh-20261027.md)
can supply Juniper vendor evidence without supplying an SRX family assessment.
Similarly, [Cisco UCS release security-fix statements](research/cisco-ucs-openssh-20261027.md)
do not establish ASA/FTD exposure, prior affected builds or a shipped OpenSSH
version. Their fixed release identifiers are firmware versions, not component
inventory.
The study does not add Apstra to its frozen family list or transfer its OpenSSH
version, workaround or planned fix to SRX/Junos.

The complete, single-page official NVD 2.0 OpenSSH CPE query returned 146 records
on 26 October 2026. Forty have registry publication-date claims from 1 January
2023 through 26 October 2026. The response fingerprint and every candidate's
semantic record fingerprint are retained in the definition. All forty have a
positive OpenSSH product mapping; logical CPE expressions are not interpreted as
appliance affectedness.

Twenty-one candidates refer to a server or server-and-client service role. The
other nineteen are excluded explicitly: client, agent or tool roles, or the
co-located memory threat model of CVE-2023-51767. Excluded does **not** mean
unaffected. Role decisions are assistant source reviews, not independent human
adjudications. OpenSSH release notes and the NVD descriptions informed this
review; release notes sometimes omit CVE identifiers and are not the enrollment
catalogue.

CVE-2026-3497 is retained with its **downstream GSSAPI patch only** qualification;
the NVD description explicitly distinguishes that variant from upstream OpenSSH.
CVE-2026-55654 has a GSSAPI variant provenance review requirement. Neither an
upstream version string nor a CPE match proves that an appliance ships the
relevant variant or enables the vulnerable path. All other candidates also
require product-build and configuration review.

This is a **retrospective registry product-mapped reference cohort**, not an
exhaustive upstream vulnerability catalogue or historical preregistration. The
project already held vendor evidence when the selection rule was frozen, but
this study's enrollment was fixed before joining vendor outcomes. The six
selected families are ASA/Secure Firewall, PAN-OS, SRX, Quantum Gateway, FortiOS
and Arista NG Firewall. Other infrastructure families are outside this narrowly
defined service study; no security conclusion follows from their exclusion.

The date window selects CVEs by **NVD publication metadata**, not vendor advisory
publication time. An older vendor advisory may later acquire an assessment for a
newer CVE. Current retained vendor statements are joined regardless of the
advisory's initial date. This does not reconstruct historical affectedness.

## Reference collection and drift

Reference sources have a separate registry and append-only storage table. They
are not vendor plugins, vendor advisories or component inventory documents and do
not increase the infrastructure vendor count. The collector's optional
`reference_sources` configuration selects a reviewed built-in ID and its exact
HTTPS URL. It cannot import arbitrary code or widen network access to the whole
NVD domain. Redirects are still subject to the retrieval allowlist.

The parser requires an NVD 2.0 response with `startIndex=0`, all results present,
no duplicates, and at most 2,000 records. A paginated, unrelated, empty or partial
response is a visible collection error. A future query exceeding that limit
requires an explicitly implemented and tested pagination contract; it cannot
silently shrink the cohort. NVD mappings may themselves be incomplete or wrong.

Refreshes compare candidate identities and semantic hashes of ID, publication
claim, English descriptions, configurations and rejection state. Transport
response hashes still identify exact retained bytes. API generation timestamps,
CVSS and unrelated last-modified metadata are not enrollment drift. Additions,
removals, and changed descriptions/mappings are review-required changes. They
never silently alter the frozen cohort. A latest collection error remains visible
beside the earlier valid capture. A vault with no current capture reports
`not_collected`; the frozen baseline remains explicit.

## Vendor cells and public contract

Family matching reuses the curated family matcher and only current non-draft
normalized records. The report distinguishes:

- No retained family assessment, or a vendor CVE reference without family scope.
- Shared bulletin statements, without converting them to CVE-specific claims.
- Explicit affected, unaffected or partially mitigated publisher statements.
- Fixed-only statements, without inferring prior exposure.
- Mixed affected/unaffected branches or conflicts that require scope review.

These states describe evidence, not deployment exposure. Each cell preserves up
to twelve statement examples with publisher date, source URL and SHA-256, literal
versions, product/platform labels, product context and the source section locator.
Exposure-context presence is reported; prerequisites must be checked in the
original source. Example truncation is explicit. Product-build equivalence and
deployment exposure remain unverified even for explicit publisher statements.

The public projection rebuilds the report after sanitizing vendor records and
allowlists reference metadata. Raw registry descriptions, captured response
bodies, private extensions and collection diagnostics are not copied into the
report. The original private human-review worksheet is neither read nor changed.

`/api/v1/component-studies` serves the generation-bound report from the Python
reader. GitHub Pages serves `/component-studies.json`; the bootstrap carries the
same whole-publication study independently of the selected dashboard CVEs. Both
use [`component-studies-v1.json`](../infrastructure_impact/schemas/component-studies-v1.json).
Rates are `null`, ranking support is `false`, and independent human review remains
pending. Inventory equivalence, coverage and build-variant checks remain blockers.

## Adding another component study

1. Implement a reviewed source parser and register its exact route in
   `references/registry.py`. Keep upstream references separate from vendor claims.
2. Test complete enumeration, duplicate/partial rejection, scope, drift, network
   boundaries and public projection. Retain an official source receipt privately.
3. Freeze an explicit period, family list, all candidate decisions, reasons and
   source fingerprints before joining the new study's vendor outcomes. Document
   retrospective limitations and downstream/client distinctions.
4. Add a versioned definition under `resources/studies/`, calculate its canonical
   cohort digest, and validate the strict report schema. Study loading is generic;
   another vendor family uses the existing normalized advisory/family contracts.
5. Obtain independent source-led human review before removing review blockers or
   developing any defensible rate comparison. Do not repurpose the existing blind
   extraction-review packet as completed study validation.

Synthetic tests exercise unknown cells, exclusions, fixed/shared states, branch
conflicts, privacy projection, source drift and generation binding. They validate
the software contract; they do not substitute for source-led human review.

The report also carries the current family catalogue version and a digest of the selected matching rules. Reviewed literal product-label additions can change evidence cells without changing frozen CVE enrollment. [Source selection](SOURCE_SELECTION.md) explains the reviewed Cisco HTML/CSAF scope difference and the two ASA/FTD label additions. Product lifecycle, support windows and equivalent observation periods remain unaligned.
