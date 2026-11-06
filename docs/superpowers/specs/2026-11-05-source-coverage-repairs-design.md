# Public-source coverage repairs

Status: coverage-first approach selected by the maintainer; written design passed the builder-completeness check and was approved with “Proceed.” The implementation plan uses the maintainer’s existing subagent-driven preference. Release-history work follows this milestone.

## Intent

Improve the evidence used to compare Cisco IOS XE, HPE Aruba Networking AOS-CX and Arista EOS before extending the measurement of security-driven upgrade workload. The question concerns operational burden, applicable exposure and disclosure completeness. Published CVE totals alone do not establish relative security, equivalence, discovery effort or concealment.

The maintainer requested a brainstormed backlog followed by implementation and tests, and selected **coverage fixes first, then release-history work**. This document bounds the first milestone. It extends the existing approved campus/branch study and existing vendor plugins; it does not redesign the comparison method.

## Approaches

1. **Coverage first — selected.** Repair demonstrated discovery/extraction gaps, distinguish notices from failures, and report remaining gaps before adding release-history evidence. This improves the input denominator first; authenticated collection and broader workload conclusions remain constrained by access and missing evidence.
2. **Release history first.** Build release/hotfix inventories immediately. This approaches maintenance burden sooner but leaves the observed vulnerability coverage unequal.
3. **Combined milestone.** Build both together. It permits earlier integration at the cost of a substantially larger implementation, validation and review surface with independent access blockers.

The selected milestone is a project involving discovery, normalization, study extraction and operator diagnostics. Separate implementation tasks must each have tests and a reviewable deliverable. New releases and hosted activation are subsequent decisions, not implied by local acceptance.

## Current evidence and constraints

The v0.9.1 activation succeeded on 5 November, including encrypted recovery readback, Pages, browser/native JSON/CSV parity and public health. It retained 912 advisories, 23 current source failures and 44/47 benchmark passes. The separate earlier staging run had 53 unparsed Arista documents; those observations are not interchangeable or additive.

Relevant code already provides:

- Bounded archive discovery, resumable queue state, retained-source replay, source audit and triage.
- Optional credential-isolated Cisco openVuln transport and persisted quotas; the staged history run reported `auth_not_configured`.
- A structured-only Aruba plugin with no historical directory parser.
- Arista source-specific adapters, a generic current HTML adapter, source-format gates and a reviewed study bridge. The reviewed bridge must also recognize newly supported representations; normalizing an advisory alone does not make it study evidence.
- Positive non-CVE notice handling for selected sources. This is different from an unaffected CVE advisory, which must remain an ordinary parsed advisory.
- Source-bound CVSS extraction for structured representations, official fallback retrieval and explicit unknown/unsupported states.

Research confirmed a public Aruba 2021 directory listing 19 text advisories. `ARUBA-PSA-2021-013` explicitly covers AOS-CX 6300/6400 families and four CVEs; `ARUBA-PSA-2021-019` includes an ArubaOS-CX statement. This proves usable older source material exists, not that every historical advisory or exact target model has been enumerated.

Arista SA-0202 and SA-0203 contain explicit affected, unaffected and triage statements despite current extraction failures. SA-0203 distinguishes underlying IPv4 code from exposure requiring MPTCP. SA-0204 is advance notice, not a present CVE/product assessment. The advertised Arista CSAF subscription returned a client challenge in a direct anonymous probe, so it is not assumed to be a reliable new transport.

## Deliverables and behavior

### 1. Aruba historical listing and text support

Add a reviewed Aruba year-directory parser through the existing `parse_archive` plugin contract. Support the explicitly observed official 2021 directory layout; do not synthesize URLs for unlisted files or assume other years share its semantics. Other years can be added later with evidence and tests.

Follow only positively recognized advisory links in the requested directory on the reviewed official host. Reject cross-host/path/year escapes, ambiguous listing structure and unsafe continuation links. Preserve listing evidence, entry counts, duplicate entries and discovered identities through the existing bounded queue. A terminal listing establishes exhaustion of that listing only. Publisher-wide expected totals stay unknown unless supplied by an authoritative source for that scope.

Add a text advisory adapter to the Aruba plugin while retaining existing JSON behavior. The initial reviewed patterns come from the two known 2021 sources. Support other listed documents only when they positively match those reviewed structural and attribution rules; unfamiliar layouts remain unsupported. Enumerating 19 files is not a commitment to manufacture assessments for all 19.

Extract literal advisory identity, revision, dates, CVE identifiers and explicit product/status/version/configuration statements with deterministic source locators. Handle continued header lines and signed-text framing conservatively. Preserve the original complete bytes, including signature framing. Parsing a PGP-signed message must never be labelled cryptographic signature verification.

Keep per-CVE attribution explicit. A document-wide affected-version block may apply to multiple header CVEs only when the publisher explicitly supplies shared scope. Preserve exact product names and platform lists. A 6300 or 6400 family statement does not automatically establish 6300M or 6410 applicability. Generic “all other products” wording must not create an invented list of unaffected models.

Integrate the text representation with the Aruba research-evidence hook so ordinary normalization, study claims and public projection agree. Preserve fixed-only, planned, unavailable and workaround distinctions. A fixed-version expression is not a date of public release. Do not alter frozen source bindings or study definitions to make the new representation qualify.

Preserve source-bound severity and CVSS when an explicitly identified CVE section supplies the score/version/vector and the existing typed score validation can represent it. Unsupported or ambiguous metric forms remain diagnosed and unknown; do not populate scores by reading back untrusted normalized metrics. Reuse the current official fallback path where applicable, without adding automatic collection or a new credential/source requirement.

Provide a separate opt-in example configuration for the reviewed year listing. Existing source defaults and the installed scheduled collector remain unchanged. Both ordinary archive and switching staging paths must retain the existing page/document limits and resumability.

### 2. Arista current applicability and exclusions

Add a narrowly reviewed adapter for the observed SA-0202/SA-0203 layout and wire it through the existing Arista parser and study-evidence bridge. Preserve source identity, publication/revision chronology, CVEs, literal product/model lists, version expressions, locators and conditions.

The normalizer must distinguish:

- An affected non-EOS product and its explicit affected-version list.
- Explicitly listed EOS platform exclusions.
- Products still under triage.
- An underlying component flaw or future hardening recommendation without demonstrated affectedness for the selected platform.

Nested lists and heading context must not attach one product's versions, platform list or status to another product or CVE. Preserve explicit unaffected EOS statements even when no affected EOS software range exists. Source-wide severity is not evidence of product exposure. Unknown products may remain literal unresolved products; they must not be guessed into EOS.

Keep MPTCP and other source-stated configuration conditions as source context with their correct scope. Do not transform the publisher's “not affected under the stated precondition” assessment into an affected claim. A planned defense-in-depth fix is neither a released fix nor an automatically required upgrade event. Existing version/model matching remains unchanged.

Only positively reviewed source routes/layouts use this adapter. A changed applicability marker, an incomplete exclusion list or an ambiguous scope must remain visible as unsupported rather than broaden into blanket family affectedness/unaffectedness. Update normalizer dependencies/fingerprints and exercise retained-source replay without rewriting historical evidence.

### 3. Advance notices and informational classification

Recognize the observed Arista SA-0204 advance-notice representation using positive publisher markers and source identity. Use existing notice/source-observation contracts; do not create a second advisory store or a new public document schema.

Retain source evidence and distinguish a recognized notice from a malformed advisory. Notices must not create guessed CVEs, exposure, future publication dates used as present disclosure dates, bundles or required upgrade events. Revisions that later contain real CVE/product evidence must be eligible for ordinary advisory processing rather than remain permanently ignored.

A CVE-bearing advisory with explicit unaffected statements is not a non-CVE notice. A source denied by a verification challenge is not a notice. Unknown empty documents still fail visibly.

The current Cisco notice failure is included in the triage inventory. Add a Cisco notice route only if its actual official bytes provide a positively reviewed signature under the existing Cisco informational-notice contract. Otherwise leave it unresolved with its real error; do not guess its classification from its URL.

### 4. Read-only coverage-gap summary

Provide a versioned operator JSON summary assembled from existing source audit, archive/backfill manifests, retained-source triage and current collection-state metadata. Its purpose is to explain missing input, not to create a security score or silently change public comparison eligibility.

Expose it through a read-only CLI operation with explicit staging database/configuration inputs. No network requests, ingestion, queue mutation, writer lock acquisition, credential probing or report publication occur during this operation. An explicit empty configuration remains empty; no fallback to the native research vault or personal source configuration is allowed.

Per vendor/source, distinguish configured-but-unobserved feeds, bounded feed windows, discovered identities, retrieved documents, parsed advisories, recognized notices, pending documents, retrieval/access failures and unsupported extraction. Preserve source/representation attribution, observed window or backfill invocation window, generation/retrieval context where available, and unknown totals/dates/models.

Current latest-source states, historical attempts, parser-replay results and vendor-wide completeness are distinct measures. Do not sum a last-run failure count with all historical unsupported captures. Do not promote `parsed` to `classified` or `human_reviewed`, infer historical availability from retrieval time, or treat multiple representations of one known advisory as multiple disclosures. When an alias/identity cannot be resolved from retained evidence, report the uncertainty.

Keep the existing full public study/scorecard/comparison contracts unchanged in this milestone. The operator report has its own versioned documented shape and tests; expose no raw source payload, private field, secret, customer identifier or key. Its summary must not call every recognized notice a collection failure or claim that the remaining errors prove incomplete vendor disclosure.

### 5. Cisco readiness and operator handoff

Retain the existing openVuln client and its secret isolation, supported endpoint allowlist, quota reservations and resume behavior. Recheck supported endpoint examples, missing/partial credential cases, response redaction, interruption and document-retrieval failure after successful enumeration. Add code only for demonstrated defects or missing bounded operator diagnostics; do not rewrite the working integration.

Provide operator instructions and an opt-in example configuration for a staged authenticated history run. Read credentials only through the existing environment variable names; never ask the maintainer to paste values into chat or include them in evidence/public outputs. Documentation must distinguish API enumeration success from successful retrieval, normalization and platform classification.

A real authenticated run is blocked until authorized credentials are available. Hosted secret wiring, full hosted backfill and source-default changes require a separate concrete proposal and approval. Missing access is a reported deliverable limitation, not a reason to infer Cisco history from a handful of seeds or increase RSS limits and declare completion.

## Verification and evidence

Public tests use project-authored synthetic fixtures only. Actual vendor source captures, operational receipts and staging databases stay outside Git and release assets. Real-source smoke checks use an isolated public-only staging vault with all IMPACT paths explicit; never inspect the native vault, private-review submissions, worksheet or customer data. Retain exact URL/hash/retrieval/revision metadata and make clear whether a run fetched current bytes or replayed earlier captures.

Required test coverage:

- Directory/path/host/year escapes, missing or duplicated entries, changed listing structure, terminal enumeration and interrupted/resumed bounded batches.
- Signed-text framing, continued headers, dates/revisions, multiple CVEs, shared versus section-specific scope, affected/unaffected/fixed-only evidence, mismatched product versions and malformed sections.
- Arista nested applicability lists, target-model exclusions, triage, product-specific versions, MPTCP context, source-wide scores and planned defense-in-depth fixes without inferred affectedness.
- Notice-to-advisory revision transitions, empty/malformed/security-challenge negatives, retained evidence and honest failure/notice accounting in ordinary collection and archive replay.
- Read-only report behavior, source/window identity, unknown totals, alias uncertainty, historical/current separation and no credential/network/private-vault access.
- Cisco missing/partial credentials, redaction, quota/resume and inaccessible documents without real secret values.
- Strict native/public validation, Python/JavaScript study-selection and JSON/CSV parity for newly supported cases; immutable old inputs/publications and no change to existing review status.

Use RED/GREEN regression evidence for repairs, then focused tests per task. Final acceptance includes supported full Python suites, Node checks where the study bridge changes, lint/format, actionlint if workflows change, clean source export and installed-wheel/external-plugin checks. Update CI test paths only as necessary; do not change CI or hosted workflow permissions, schedules or runtime behavior. Run a bounded actual public-source staging acceptance and report recovered, unsupported, blocked and notice counts without claiming complete vendor history.

Independent human review remains pending. The maintainer's existing choice to review personally is preserved; do not nominate or contact a reviewer, label new automated checks as human-reviewed or overwrite frozen review resources.

## Shared constraints

- Primary vendor and official CVE/NVD/KEV sources only; no third-party aggregator as affectedness authority.
- Advisory schema v2, frozen study definitions/source bindings, original review resources, existing identifier semantics and dependency pins remain intact.
- No automatic product/model/version/date matching or inferred software release dates. No equivalence/security ranking, causal Glasswing finding or concealment claim.
- Existing source defaults, hosted schedules, automatic publication behavior, workflow permissions, runtime pin, secrets and recovery/storage settings remain unchanged.
- Preserve at most 20 pages/200 documents per archive invocation; 512,000-byte target parts, 8,000,000-byte maximum parts, 2,000,000-byte index and 20,000,000-byte default monitor budget. Preserve existing compressed/expanded archive and storage limits.
- Do not change package version or publish a release solely to make the design stage appear complete. Propose release metadata/activation after reviewed implementation and exact-head CI.
- No customer names/data, raw vendor captures, credential/token material, local identities or private operational receipts in public source/history/assets.

## Backlog after this milestone

1. Public product/train-scoped release and hotfix inventory, tied to explicit advisory/fixed-release evidence. Keep release events separate from actual maintenance windows and leave account-gated/missing history visible.
2. Official CVE-list reconciliation to identify missed vendor advisory references; deduplicate mirrored content and preserve applicability uncertainty.
3. Dated discovery/disclosure-policy context, including Cisco's July 2026 umbrella-CVE changes and the fact that Arista also describes Glasswing-related testing. These are contextual sources, not proof of causation.
4. Maintainer evidence review and explicit comparison eligibility for vendor/period/model coverage.
5. Evidence-led investigation of fixes without corresponding notices, dependent on actual versioned source/SBOM/firmware evidence. Component version changes alone do not establish exposure, a security fix or concealment; authorized private artifacts remain unavailable for the pilot.

Each item retains its own design and access requirements. The selected order is coverage fixes followed by release-history work; this document does not claim that later items are implemented or authorize hosted changes for them.

## Builder discretion

Choose focused module decomposition, helper names and exact synthetic fixture construction consistent with existing plugin contracts. Reuse existing persistence and read-only manifest/audit operations rather than creating parallel advisory or evidence storage. Choose bounded stage batch sizes within existing caps. Resolve routine implementation details without broadening source routes, matching semantics, public contracts, defaults or operational permissions.

## Primary references

- [Aruba 2021 directory](https://csaf.arubanetworking.hpe.com/2021/), [AOS-CX advisory 2021-013](https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-013.txt), [2021-019](https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-019.txt).
- [Arista SA-0202](https://www.arista.com/en/support/advisories-notices/security-advisory/24853-security-advisory-0202), [SA-0203](https://www.arista.com/en/support/advisories-notices/security-advisory/25023-security-advisory-0203), [SA-0204](https://www.arista.com/en/support/advisories-notices/security-advisory/25024-security-advisory-0204).
- [Cisco authentication](https://developer.cisco.com/docs/psirt/authentication/), [supported all-advisory endpoint](https://developer.cisco.com/docs/psirt/all/), [disclosure-policy changes](https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure).
- [Arista AI-enhanced security statement](https://www.arista.com/assets/data/pdf/glasswing/QA-Project-Mythos-Glasswing.pdf), [official CVE List V5](https://github.com/CVEProject/cvelistV5), [official KEV mirror](https://github.com/cisagov/kev-data).
- [v0.9.1 activation and remaining findings](https://github.com/abedegno/infrastructure-impact/releases/tag/v0.9.1).
