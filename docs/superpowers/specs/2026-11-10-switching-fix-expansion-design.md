# Expand reviewed switching fix attribution

The maintainer approved expansion across retained advisories, starting with Aruba
and Arista. Routine design questions were previously waived. This extends the
approved 9 November remediation/history design, without changing its evidence standard.

## Outcome and approach

Make more existing affected-CVE statements traceable to publisher-reported fixes
and literal release identities. Remediation publications, fixed versions, software
release dates and customer upgrades remain separate quantities. Expected historical
coverage and independent human review remain unknown/pending.

Use a finite, versioned reviewed-binding resource shared by extraction, Python
validation and generated browser contracts. This avoids repeating source tables
in three validators. Existing legacy 04669/SA0075/0128/0201/0100 guards stay intact;
new sources use the shared registry. A general family/train/version join would
lack source ownership; adding more hand-maintained parallel rule tables would
increase drift. The registry is the selected implementation choice.

Only bundled trusted data selects parser behavior. No caller-supplied rules,
dynamic code, generic version arithmetic or model inference. Cache immutable rule
metadata, never validated evidence/proofs. Keep per-invocation matching bounded.

## Reviewed source set

Public captures and machine review findings are cached outside Git under
`/tmp/impact-fix-expansion/`. They are primary-source evidence, not human sign-off.

Aruba: HPESBNW04888 (65 finite associations), HPESBNW05027 (20),
ARUBA-PSA-2022-012 (16 consistent associations only), ARUBA-PSA-2022-004 (15;
an existing counted publication), and HPESBNW05134 (170). Review files
`aruba-recon.json` and `05134-recon.json` enumerate all 286 candidates. Pin exact
URL, raw SHA256, advisory/CVE, common product parent, independently named affected
and fixed products, publisher IDs, literal expressions, status/remediation locators,
original dates and complete remediation-details digest. 05134 uses remediation 1;
its differing leaf product names do not require any alias or family expansion.
These are reviewed section derivations, not publisher-declared CSAF relationships.

Establish available fixes only for enumerated original fixed siblings using the
reviewed literal branch/upgrade and download evidence. Preserve full details,
original product IDs and dates. Existing planned/unavailable/future/truncated
states must not become released fixes. Copy a fixed remediation onto an exact
reviewed affected tuple with existing reviewed_source_sections provenance. Preserve
all unrelated claims. 012's narrative/fixed-ID disagreements and unsupported
combinations remain unlinked. 004's existing directly scoped remediation remains.

Arista: SA0099/CVE-2024-27890 and 27892, SA0103/CVE-2024-6858,
SA0140/CVE-2026-10040. `arista-recon.json` records exact affected/fixed ownership,
source format, tracked CVE set, complete normalized Resolution hash, exact
CVE-specific div marker followed by direct UL, ordered literal LI expressions
and clause hashes. Wrapper changes can be accepted only when reviewed article
identity and owned sections still match. No positional pairing by CVE order.
Keep hotfix, MOS, TerminAttr, planned CVP and platform exclusions separate.
SA0062's component/configuration-dependent fixes are excluded from this contract.
No software date is supplied by these new lists. Preserve publisher typos and
punctuation rather than silently repairing versions. Cached replay found SA0140
has truncated affected-platform text. Its complete fixed-only evidence may be
retained, but the existing truncation guard blocks a copied affected link and
remediation publication; no evidence limit or guard is relaxed for this source.

## Implementation boundaries

Add a small registry/guard module and source-adapter helper beside existing modules.
Use a closed internal JSON schema for the resource. Bindings expose exact affected
and fixed tuple fields, expected remediation/dates and availability evidence.
CSAF entries require raw source pins and explicit parent ownership; Arista entries
require owned-section pins and exact clause/list parsing. Generate browser registry
data from the same validated resource. Add new dependency files to appropriate
normalizer identities and report actual fingerprint changes; do not redesign the
fingerprint scheme or force unrelated source reprocessing.

At validation boundaries, require exactly one fixed sibling, matching vendor,
advisory, CVE, family, revision, publisher, source URL/hash/retrieval time and exact
expected products/locators/expressions. Copied remediation fields must match the
original fixed remediation, with only the existing copied product-ID/list/binding
projection. Source- and clause-inconsistent copies reject in full, compiled,
browser full/stream and native streaming validation. Native/browser accumulators
must retain every registered fixed sibling, with existing byte limits unchanged.

On fix-only source drift, preserve valid existing affected claims, omit new fixes
and report an explicit diagnostic. Never treat metadata alone as a validation pass.

Literal release identity parsing may recognize the exact `AOS-CX ` label prefix
and terminal punctuation on an otherwise supported Arista expression. Stored
claims remain byte-for-byte literal. The release view may recognize the exact
`HPE Networking AOS-CX` leaf label while still requiring the already-resolved
`aruba-aoscx` family; extraction/study family aliases remain unchanged. Misspellings such as 0103's `4.28.11Mand...`
remain unresolved. Parsing an explicitly stated first literal version does not
match installed versions, imply all later releases or establish availability dates.

## Constraints

- Advisory schema v2, public DTOs and frozen study/review definitions stay unchanged.
- No source defaults, schedules, permissions, runtime pins, limits or publication activation changes.
- No original/private operator config, vault/key, worker logs, customer artifacts or firmware access.
- Only official public sources; raw captures stay outside Git and are reused without refetching.
- Preserve affected CVE/product/status/configuration/model evidence; do not infer customer upgrades, security quality, equivalence or concealment.
- Human review stays pending. Missing/conflicting source evidence stays visible as unknown.

## Verification and rollout

Baseline 232 focused tests pass. Use authored synthetic positives and negatives,
then exact cached public-source replay with receipts. Compare affected evidence
before/after, publication-event deduplication, literal fix coverage and unresolved
cases. Do not substitute subset replay totals for the full published collection.
Run Python/browser/native/JSON/CSV parity and appropriate broader CI. Deliver
reviewable commits and a PR with actual replay results. Hosted retained-byte
preview/reparse and activation are separate; prepare concrete requirements rather
than activating a changed normalizer from a development branch.
