# Cisco explicit model binding

The switching extractor now accepts literal structural `Series Switches` names
for 9200, 9300, 9300L and 9500 through the existing CSAF graph resolver. Existing
exact chassis names still work. Numeric fragments, family names, unrelated
Firepower products, wireless controller hosts and X/LM variants do not establish
another model. Ambiguous product graphs remain unresolved.

Four public Vulnerable Products sections are accepted by full source SHA-256,
note SHA-256, exact URL, advisory identity, CVE and affected IOS XE ownership:

| Advisory | Models | Qualification retained |
| --- | --- | --- |
| cisco-sa-fast-Zqr6DD5 | 9300, 9300L | vulnerable IOS XE release |
| cisco-sa-ios-xe-cat-verify-D4NEQA6q | 9200 | vulnerable IOS XE release |
| cisco-sa-iosxe-priv-esc-sABD8hcU | 9200, 9300 | affected at publication; vulnerable IOS XE release |
| cisco-sa-iosxe-mpls-dos-Ab4OUL3 | 9300, 9500 | vulnerable IOS XE release; MPLS configured |

The entire accepted note stays in `conditions`. The binding retains its exact
`/document/notes/1/text` locator and source digest. The caller supplies retained
retrieval time through the existing evidence pipeline. A changed source or note
causes local model abstention, preserving the OS claim and its existing status,
version expressions, dates and remediation facts. Notes never bind fixed,
unaffected, conflicting or recommended rows. ROMMON, mixed platform tables and
all other unreviewed note layouts remain unresolved. No fixed software threshold
has been interpreted as a model-specific upgrade.

`adapters.cisco_models.note_bindings(data, url, digest, cve_id, status, family,
product) -> dict` is a pure helper over parsed publisher data. The extractor
computes `digest` from the exact raw bytes; `product` is the literal IOS XE name
owned by the resolved product graph. Result keys are `bindings`, `conditions`
and `diagnostics`, each a fresh list. Positive bindings use the existing
`publisher_explicit` schema. The packaged rule inventory is
`resources/cisco-model-notes.json`; supplementary automated examples are in
`examples/cisco-model-validation.json`. Independent human review is pending.

## Coverage DTO

`application.switching_model_coverage.build_report(evidence, study_selection, *,
publication, generated_at) -> dict` first validates both native envelopes and
requires exact retained evidence identity. It uses the union of actual selected
row claim IDs, inheriting the selected vendor, window, scope and CVE cohort.
Inputs are never mutated. Invalid generation, definition or ownership raises
`ValueError` through native validation or the helper identity check. Full native
selection inputs are required; a summary-only selection is insufficient.

The returned JSON object has these exact fields:

- `schema_version`: integer `1`; `publication`, `generated_at`,
  `definition_sha256`, `observation_end`: retained generation identity.
- `selection`: deep copy of the accepted native selection object.
- `nonadditive`: `true`; `interpretation`: explanatory string.
- `totals`: `{claims, advisories, cves, bound_claims, unresolved_claims}`.
- `models`: definition-order rows for each selected vendor's frozen targets.
  Each row is `{vendor, family, model, counts, by_status, by_source, claim_ids,
  advisory_ids, cve_ids, sources}`.
- `unresolved`: reason-sorted rows `{reason, counts, claim_ids, sources}`.

`counts` always means `{claims, advisories, cves}` with distinct claim IDs,
(vendor, advisory ID) pairs and non-null CVE IDs. `by_status` maps each represented
literal status to `counts`; absent statuses are omitted. `by_source` is a list of
`{source, counts, by_status, claim_ids}` grouped by exact positive model-binding
proof. `sources` contains distinct claim sources and applicable binding sources.
A `source` is the existing four-string `{source_url, source_sha256, retrieved_at,
source_locator}` object. ID lists and sources are sorted deterministically.
Models and source proofs can overlap; their totals must never be summed.
Unresolved reasons include local rule mismatch, malformed or unreviewed notes,
ROMMON qualification, embedded controller host context and family-only 9400/9600
context; otherwise `model_binding_unresolved` applies. These are evidence
coverage categories, not unaffectedness or inventory exposure claims.

## Bounded offline comparison

The cached 188-source public corpus retained on 10 November and refreshed on
13 November 2026 produced 95,707 claims before and after this change. Model-bound
claims increased from 0 to 290 across four advisories and five CVEs. Per-model
counts overlap: 9200 110 claims, 9300 182, 9300L 89, 9500 91. No source extraction
errors or changes to pre-existing status/date/version/remediation/source facts
were observed. 95,417 claims remain unbound. This is a bounded cached corpus,
not a complete live archive, accuracy estimate or independent human review.
Two unrelated source bodies differ from their older retained hashes; the replay
uses their newly captured bytes and hashes without reusing old revision IDs.
No hosted publication or default delivery has been activated by this change.
