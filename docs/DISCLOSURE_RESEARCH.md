# Disclosure timing research

A component CVE does not prove product exploitability. A firmware date preceding
an advisory does not prove that the firmware was publicly available then, that no
earlier disclosure existed, or that a vendor intended to hide a fix.

## Retained release-note revisions

Configured release documents retain their raw fingerprints and parsed text in the
private vault. Successive observations record added/removed CVE references and
new security language, with before/after evidence IDs and capture times. Reversions
(A → B → A) remain observations; repeating an identical state is idempotent.
Capture times bound what this collector saw, not the publisher's first disclosure.
Only signals tied to configured public release sources cross the publication boundary.

## Availability observations and review

A fix candidate needs product/version/CVE linkage and a separate release-availability
observation. Record the exact source locator and classify the evidence:

- `publisher_date_claim`: a date asserted in a bulletin; insufficient alone.
- `public_release_listing`: a reviewed public listing with release metadata.
- `observed_download`: a reviewed availability observation, with a defensible date.

Example workflow, substituting actual retained IDs and reviewed facts:

```sh
impact research release-observation --evidence-id 101 --vendor arista --product 'Example router' --version 1.1 --released-at 2025-01-01 --kind public_release_listing --locator 'Version 1.1 row in dated release listing'
impact research review-fix 7 --status verified --observation-id 3 --earlier-disclosure-search 'Describe official archive, related advisories and release notes searched, including gaps' --note 'Explain the specific product/version/CVE linkage and date basis'
```

The review gate rejects a bare publisher date, a mismatched product/version/date,
missing search history, and the same source URL or bytes reused as independent
release/link evidence. A human or reviewer must still judge whether distinct
sources are truly independent and whether a listing proves availability on the
claimed date. Verification means the recorded evidence passed review; intent and
absence of all earlier disclosures remain unestablished.

The HPE Cray timing lead remains unresolved. Its date claim has not been promoted
to an independently verified release-availability finding. No confirmed concealment
finding is published.
