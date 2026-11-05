# Source coverage and vendor comparison backlog — 5 November 2026

Status: the maintainer selected coverage fixes first, then release-history work, and approved the [coverage-repair design](../superpowers/specs/2026-11-05-source-coverage-repairs-design.md). The [implementation plan](../superpowers/plans/2026-11-05-source-coverage-repairs.md) is ready for review. Product code and hosted configuration are unchanged.

## Intended outcome

Answer the customer’s operational question: for comparable switching products and periods, how much security-driven upgrade work is disclosed, what exposure is established, and what disclosure evidence is missing? Do not equate CVE totals with security quality or assume either vendor equivalence or concealment.

## Approaches under consideration

1. **Coverage first (selected):** repair demonstrable parser/discovery gaps, validate a source inventory, then extend release history. Produces trustworthy input sooner; measured upgrade-workload analysis follows.
2. **Release history first:** prioritize actual software releases, bundles and hotfix guidance. Addresses operational burden sooner, but the advisory coverage denominator remains uneven.
3. **Combined milestone:** coverage and release history together. Integrates both immediately, with a much larger implementation/review surface and credential/public-availability blockers.

The selected approach follows the existing approved campus/branch switching design’s priorities. It does not approve a new hosted backfill, credentials, schedule, permission, runtime-pin or publication change.

## P0 — directly evidenced coverage repairs

### COV-01 — Aruba historical directory discovery and signed-text advisory extraction

Evidence: the official 2021 directory lists 19 TXT documents. ARUBA-PSA-2021-013 explicitly covers AOS-CX 6300/6400 families, four CVEs, affected/fixed expressions and configuration details; ARUBA-PSA-2021-019 contains an ArubaOS-CX statement. The existing CSAF-index path did not enumerate these historical representations.

Implementation scope to design: reviewed listing parser and TXT adapter through existing plugin contracts; opt-in local source configuration; existing resumable queue/evidence/revision storage. Follow explicitly published links only. Preserve signed source bytes as source evidence; parsing signed text does not establish cryptographic signature verification. A directory’s discovered count is not a complete vendor-history denominator.

Acceptance: synthetic affected/unaffected/multi-CVE/version/configuration and malformed section tests; parent/path/domain escapes, missing/duplicate entries, interrupted/resumed batches, source-specific totals and year/date tests. Actual public-only staged replay captures original URL, retrieval time, SHA-256, revisions and parser outcomes. Family 6300/6400 never automatically implies exact 6300M/6410 model applicability. No default source or frozen study definition change.

### COV-02 — Arista current platform/applicability layouts

Evidence: SA-0202 and SA-0203 currently fail normalization despite explicit product statements. They distinguish non-EOS affected products, EOS platform exclusions, triage and configuration requirements. SA-0203 distinguishes underlying vulnerable code from exploitation requiring MPTCP.

Implementation scope to design: narrowly reviewed current-layout adapter through existing Arista plugin; source-scoped affected/unaffected/investigating claims and literal product/model/configuration context. Keep source-wide CVSS severity distinct from product applicability. A defense-in-depth recommendation must not silently turn an unaffected platform into affected, or into a proven required upgrade event.

Acceptance: synthetic nested lists/headings, per-CVE scope, explicit model exclusions, triage, missing versions, changed wording and hostile markup tests; no blanket family status from an incomplete list; independent Python/JavaScript/report/export parity. Real official-source replay must preserve original product statements and demonstrate the changed extraction without changing source facts.

### COV-03 — classify advance/informational notices

Evidence: SA-0204 is advance notice of future advisories; the Cisco notice source also needs document-type review. Current unsupported-document counters can conflate such notices with extraction failures.

Implementation scope to design: existing non_cve_notice/retain_unlinked_notice and source-observation paths. Require a reviewed positive notice signature; retain provenance and classify as a notice without inventing CVEs, products, fix dates, bundles or affectedness. Ordinary malformed or unfamiliar advisories must still fail visibly. Revisions that later add CVEs must re-enter normal advisory processing.

Acceptance: notice versus genuine malformed advisory tests, subsequent notice-to-CVE revision, retained-source replay and ordinary scheduled collector source-state tests. Counter changes must be explained, never presented as newly collected security coverage.

### COV-04 — reconciled source-gap inventory

Evidence: the activation has 23 current failures; the earlier dedicated stage had 53 unparsed Arista documents. These are different observations and must not be added or substituted. Discovery, retrieval, parsing, classification, scope qualification and human review are distinct states.

Implementation scope to design: extend/reuse existing archive manifest, triage, source audit and validation reports. Report vendor/source/window, explicit discovered identities, retrieved/parsed/classified/pending/blocked counts, duplicates and unknown totals. Link each gap to source evidence and error category. An exhausted listing does not establish full vendor coverage. Keep public and private evidence boundaries intact.

Acceptance: consistent generation/source/window accounting, duplicate and alias handling, unknown totals, notices, stale captures and parser replay regression tests; immutable old publications and frozen studies unchanged. API/export consistency if any public report contract is extended.

### COV-05 — Cisco integration readiness and historical enumeration

Existing implementation: credential-isolated OAuth client, quota/resume state and paginated API enumeration already exist. The previous staging run reported auth_not_configured. Do not rewrite the working client or assume increasing RSS limits establishes historical completeness.

Immediately testable: exact current endpoint configuration, missing-credential diagnostics, redaction, request quotas, resume and official-representation fallback. Prepare operator documentation for registering/mapping credentials and an explicit bounded local backfill.

External blocker: a real authenticated run requires an authorized Cisco client ID/secret. Never ask for values in chat or put them in source, snapshots or logs. Hosted secret mapping/backfill is a separately reviewed configuration change. Record returned totals and access errors; preserve source gaps even when the API enumerates a document successfully but document retrieval is denied.

## P1 — customer workload and comparison evidence

### CMP-01 — product-scoped release/hotfix inventory

Collect publicly available version histories, release notes, resolved-issue lists and hotfix publications for the selected OS families/platforms/trains. Reuse existing narrow release-history adapters where applicable; the existing Aruba adapter is currently restricted to an unrelated 4100i/10.13 page and must not be treated as coverage of the customer models.

Store explicit release identity/date, relevant products/trains, source provenance and links to advisory/fixed-release evidence. Missing or account-gated material stays visible. A fixed version expression is not an availability date. A release event, a CVE count and an actual customer maintenance window are different measures; bundling requires explicit publisher evidence.

Acceptance: public source-specific release fixtures, date/branch/platform negatives, revisions and bundle deduplication, unknown availability, native/static/JSON/CSV parity. No actual customer workload estimate without deployment/change-window evidence.

### CMP-02 — official CVE reconciliation

Use the official CVE List V5 and vendor CNA containers to identify published CVEs/advisory references absent from our source inventory. NVD can supplement metadata; KEV supplies exploited membership, not a complete CVE census. Deduplicate equivalent representations and never treat mirrored CVE/NVD content as independent corroboration. A component CVE alone cannot establish appliance applicability.

Acceptance: bounded/resumable updates, source/container attribution, duplicates/rejected records, references outside allowlists, affectedness conflicts, missing versions and corrected records. Full-history bulk retrieval remains a separately bounded operation.

### CMP-03 — discovery/disclosure policy context

Preserve dated vendor policy/research statements separately from vulnerability claims. Cisco’s July 2026 umbrella-CVE/disclosure changes are a structural break alongside the April Glasswing launch; Arista also describes Glasswing-related AI discovery. Membership or a before/after increase does not establish causation for individual advisories. No statistical security ranking or inferred number of bugs per umbrella CVE.

Acceptance: policy source/date/provenance, unchanged original publication dates, clear distinction between reported claims and analytical hypotheses. Requires a specific report design before adding UI/schema behavior.

### VAL-01 — independent evidence review and eligibility

Prepare a reviewable sample from corrected sources and report automated source/section matches separately from human judgment. Preserve the maintainer’s existing choice to review personally. Do not mark evidence human-reviewed automatically or replace frozen review resources. Report which vendor/period comparisons remain ineligible because source/model/release evidence is missing.

## P2 — evidence-led investigation of fixes without a matching notice

### RES-01 — versioned component/fix evidence

Where vendor-published source bundles, SBOMs, release notes or authorized artifacts actually exist, compare versions and explicit security-fix references across releases. Backports, disabled features, build options and exact product applicability need separate evidence. Classify evidence as a lead, corroborated fix or unresolved; do not infer concealment or intent from a missing notice.

Blockers: exact authorized artifacts are not yet available for the private pilot; public availability varies by product. No new private evidence collection or redistribution is implied by this backlog.

## Proposed first implementation milestone

Coverage-first scope: COV-01, COV-02, COV-03, the reporting/diagnostic parts of COV-04, and readiness/documentation for COV-05. Retain CMP/VAL/RES items with their dependencies rather than inventing inputs. Separate small reviewed commits, synthetic public tests, actual public-source staged acceptance, whole-branch review and exact-head CI before proposing activation.

## Shared constraints and verification

Follow the approved campus/branch design, existing plugin contracts, advisory schema v2 and source provenance handling. No automatic product/version/date inference; no new runtime dependencies unless justified. Preserve source defaults, frozen research/study definitions, original human-review resources, schedules, workflow permissions, runtime pin, secrets and recovery settings. Preserve 20-page/200-document archive invocation bounds, 8,000,000-byte parts, 2,000,000-byte index, 20,000,000-byte default monitor and existing archive/storage limits.

Before code: review the concrete coverage design and implementation plan under the brainstorming workflow. During implementation: regression-first tests, source-specific changes and focused tests. Final: supported full Python suites, Node/native/static/export checks where affected, lint/format/actionlint where relevant, clean source export and wheel/external-plugin probes, no raw vendor captures or private material committed. Hosted backfill/publication/activation is not implied by a green local run.

## Primary evidence

- https://csaf.arubanetworking.hpe.com/2021/
- https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-013.txt
- https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-019.txt
- https://www.arista.com/en/support/advisories-notices/security-advisory/24853-security-advisory-0202
- https://www.arista.com/en/support/advisories-notices/security-advisory/25023-security-advisory-0203
- https://www.arista.com/en/support/advisories-notices/security-advisory/25024-security-advisory-0204
- https://www.arista.com/assets/data/pdf/glasswing/QA-Project-Mythos-Glasswing.pdf
- https://developer.cisco.com/docs/psirt/authentication/
- https://developer.cisco.com/docs/psirt/all/
- https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure
- https://github.com/CVEProject/cvelistV5
- https://github.com/cisagov/kev-data
- https://github.com/abedegno/infrastructure-impact/releases/tag/v0.9.1
