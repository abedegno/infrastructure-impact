# Comparison evidence follow-up

The maintainer approved coverage investigation, validation repairs and a customer
brief on 10 November. Routine design questions were previously waived. Reuse the
existing publication, source-selection and review contracts.

## Findings and approach

Publication `6d1e2458972f428ebe023e5deaa4a993` has no demonstrated extraction
disagreements in either validation sample. Its 44/47 mapping benchmark is distinct
from the 16-case switching sample. Three switching cases reference an exact retained
but unselected Cisco CSAF representation. Do not change HTML selection, merge
assessments or label metadata as a passing extraction.

Add optional `source_context` to those missing switching cases, using only validated
public representation metadata anchored to a published selected capture. Its state
is `retained_unselected_representation`; include the reviewed alternate URL/hash
and the selected capture URL/hash. A wrong vendor, URL, revision, unavailable view
or unpublished selected anchor must not qualify. Leave all outcomes, counters and
independent-review flags unchanged. Rebuild context from inputs rather than trust
precomputed annotations. The CLI and public projection use the same report builder.

Alternatives: replacing the selected HTML loses broader scope; normalizing a new
validation-only inventory introduces a larger evidence contract. Neither is needed
to correct this availability description. Frozen cases remain unchanged.

Prepare a dated customer brief, compact generation-bound evidence receipt and blind
review packet. Report observed counts and source errors separately from unknown
historical denominators. Source failures outside this study are not switching gaps.

A fresh bounded request recovered the previously blocked exact Cisco 17.12.1
model page (SHA-256 `2f6c9f50a4dededb423e5ba80a4873e194310499d7911b7b34f22d8aded79ba6`).
Its existing reference adapter supports a synthetic section layout only. Extend
that reference adapter for the actual software metadata tables: exact title/h1,
one software-data-wrapper within support-birth-cert, direct owned Series/Product
Type and Release Date rows. Retain the existing synthetic-layout compatibility.
Reject duplicates, foreign model/type, nested/unowned dates and malformed values.
The literal Release Date is 28-JUL-2023; lifecycle/document dates are separate.
This optional source stays disabled until separately approved hosted activation.

## Constraints

- No changes to selected assessments, frozen expectations, advisory schema v2,
  advisory normalizers, source defaults, schedules, hosted permissions, runtime pins or publication activation.
- Only official public evidence; no private configuration, vault, worker logs or customer data.
- Retained metadata is not extraction validation, model applicability, security quality or customer upgrade workload.
- Independent human review stays pending; unknown coverage and release dates stay unknown.
- Preserve output without context when the optional selection input is absent.

Acceptance: focused negative and delivery tests, existing source-selection regression,
verified public-input hashes/identities and a fresh review. No full-state deployment
is required to prepare this local reporting change and research packet.
