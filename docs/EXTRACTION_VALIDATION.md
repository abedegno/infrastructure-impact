# Source-led extraction validation

The initial second-pass review has **22 assertions across eight vendors and thirteen
primary source documents**. It checks affected ranges, unaffected platform
exceptions, fixed-only statements, shared bulletin scope, and a planned fix next
to an unrelated issue's completed fix. It also checks the Fortinet HTML statement
that supplements an empty CSAF export.

This review was performed by an automated assistant in the implementation session.
It is not independent human adjudication, a random sample or an estimate of global
precision. The published `independent_human_review_completed` remains false.
The existing 47-case mapping benchmark and synthetic parser regressions remain
separate checks with their own declared scope.

`resources/extraction-review.json` records each official source URL, exact reviewed
SHA-256, source locator, expected product/CVE status, rationale and any scope,
version, remediation or forbidden-status boundary. Its input contract is
`schemas/extraction-review-v1.json`. Evaluation requires matching current source
bytes or an explicitly reviewed article-section digest, reported separately. Otherwise a source revision becomes `source_revision_unreviewed`, even when the new
parser output would satisfy the old expectation; labels never change themselves.
Missing sources, missing product scope and disagreements are separate outcomes.

```sh
impact validation
impact validation --fail-on-disagreement
impact validation --packet > independent-review-packet.json
```

The failure flag exits nonzero for product-scope loss or disagreement on reviewed
bytes. Missing or changed sources remain explicit, incomplete states, not passing
checks. The command does not contact vendors, expose raw source bytes or modify
assessments. Source retrieval uses the normal collection workflow.

The dashboard has an **Extraction validation** view. Public exports are
`extraction-validation.json` and `review-packet.json`; the Python reader provides
`/api/v1/extraction-validation` and `/api/v1/review-packet`. These reports cover the
whole review sample independently of the selected dashboard cohort. Every report
is tied to the publication that supplied its current source fingerprints.

## Independent adjudication

The blind packet contains source links, reviewed/current hashes, source-section
locators and blank adjudication fields. It withholds parser outputs, expected
statuses and rationale. A reviewer should read each original source and record
product/version/configuration/CVE scope, remediation and date basis before
consulting the extraction report. Missing access must remain a gap; an IPS
protection signature is not evidence that a vendor's own appliance is affected.

Contribute the completed packet and review notes through a reviewed pull request.
Identify the reviewer as human or automated, review date, conflicts of interest,
source fingerprints and all disagreements. Do not submit confidential or entitled
vendor documents. Source originals are not redistributed. Maintainers must resolve
scope disagreements explicitly; agreement with the parser is not a reason to
relabel the source. There is no automatic certification switch or contributor
file that can unlock vendor rankings or verified fix timing.

## Changed bytes and reviewed article sections

Four assertions additionally pin a structural digest of the reviewed static HTML
article. Arista's `item-page` body and Fortinet's title, detail sections and metadata
table have explicit boundaries. Tags, text, attributes, table structure and link
targets remain significant. Only surrounding page content, blank whitespace and
randomized Joomla email-cloak span IDs are excluded. This does not verify rendered
JavaScript, every site layout or general semantic equivalence. Changed boundaries
fail closed. A section match is reported as
`reviewed_scope_match_source_changed`, separately from a raw-byte pass; changed raw
fingerprints stay visible and expected labels are unchanged.

## Private review proposals

Review packets now carry a canonical SHA-256 binding. Save the packet that the
reviewer actually used. Generate and complete a private submission template:

```sh
impact validation --packet > independent-review-packet.json
impact validation --submission-template > private-review.json
impact validation --submission private-review.json --packet-file independent-review-packet.json
```

The template intentionally has blank fields and is invalid until completed.
`schemas/review-submission-v1.json` bounds the submission. The audit accepts a
saved packet without opening the evidence database, checks its binding, source
fingerprints and dates, and reports unresolved items. It writes no assessment,
expected label or eligibility change. Reviewer names, independence statements and
rationale are excluded from audit output. A declared human reviewer is not a
machine-verified independent reviewer. Keep submissions private until a maintainer
has reviewed identity, conflicts, source access and any proposed public text.
