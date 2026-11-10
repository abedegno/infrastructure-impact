# Review packet and evidence receipt

This packet belongs to publication `6d1e2458972f428ebe023e5deaa4a993`, generated at
`2026-11-10T02:41:08.074204+00:00`. It contains **16 questions across nine source
documents**. It is the existing published blind switching packet, exported without
expected statuses, parser output or filled adjudications. Independent human review
remains pending. Five or more assertions per vendor does not mean five independent
documents or five reviewed target models.

- [Blind packet](review-packet.json): official URLs, source fingerprints and locators.
- [Blank submission template](review-submission-template.json): existing submission
  contract; intentionally invalid until the reviewer completes required fields.
- [Evidence receipt](evidence.json): verified public input descriptors, current
  counts, year inventory, failure categories and metadata-only validation replay.
- [Yearly coverage CSV](coverage-by-year.csv): observed affected advisories;
  empty expected totals mean unknown, never zero.
- [Customer brief](../2026-11-10-vendor-comparison-brief.md) and
  [source/validation audit](../2026-11-10-switching-evidence-audit.md).

## Review instructions

1. Save an unchanged copy of the packet and template. Read the official source at
   each locator and record the exact response SHA-256. For changing pages, compare
   the fingerprint with the packet; a newer response is not the same evidence.
2. Fill each adjudication independently before reading automated expectations or
   validation results. Record explicit product scope, status, versions,
   configuration qualifiers, remediation and date basis. Use `not_adjudicated`
   when evidence is unavailable; explain what is missing rather than guess.
3. Complete reviewer type, display name, review timestamp and independence
   statement. Keep your completed submission outside the public repository until
   you deliberately choose what to disclose. The template contains no identity.
4. Audit the saved submission against this exact packet using the existing CLI:

   ```sh
   impact validation --submission /path/to/private-review.json \
     --packet-file docs/research/2026-11-10-comparison-evidence/review-packet.json
   ```

The saved-packet audit checks the submission binding without opening a vault. It
does not verify independence, certify semantic correctness, publish reviewer text,
change expected labels or mark human review complete. A mismatched source requires
a new evidence review. See [the review method](../../EXTRACTION_VALIDATION.md).

## Provenance and verification

The bootstrap, publication catalogue, overview and compressed snapshot were cached
once and checked against their declared byte lengths and SHA-256 hashes. The
archive's expanded hash, embedded asset hashes and generation identities were
also checked before using the existing codec to decode records and the study
summary. No new claims were generated. Every affected advisory identity joined to
one retained record; yearly totals reconcile to 170 / 16 / 53. CVSS coverage uses
set unions across facets. The local report was compared with the entire published
switching report after removing only the three new metadata contexts.

The packet's canonical hash uses the existing `packet_sha256` function; it excludes
the digest field and optional publication wrapper, not the questions. The template
binds to that digest. All adjudications remain blank. `evidence.json` is a dated
research receipt, not a new API/schema contract or a full vendor-source archive.
Raw vendor pages and the full public snapshot are not redistributed here.

To repeat the checks, retain the public inputs named in `evidence.json`, verify
their descriptor hashes and generation before decoding them with
`infrastructure_impact.publication_codec.CatalogReader`. Obtain the study's
`affected_advisory_ids` and join by `(vendor, advisory_id)` to `records`, using
`published_at` for the yearly inventory. Re-run
`switching_validation.report(records, switching_reviewed_source_scopes,
source_selections=source_audit["source_selections"])` for the metadata replay.
Current site URLs may advance to a newer publication; do not mix its inputs with
this receipt or silently call them the same observation.
