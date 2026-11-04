# Campus/branch switching descriptive study

Status: descriptive-study approach approved on 4 November 2026; written design proposed for maintainer review. No implementation or hosted configuration change is authorized by this document alone.

## Intent and interpretation

Compare documented vulnerability and remediation-publication patterns across Cisco IOS XE, HPE Aruba Networking AOS-CX and Arista EOS. The maintainer wants an interesting evidence-backed data point between vendors, with an expectation that the observed patterns may show little difference. That expectation is a hypothesis, not an acceptance criterion. Results may show similarities, differences or inadequate evidence.

This is a descriptive public-source study. It produces source-bound counts, scope qualifications and coverage observations, not a vendor security ranking, equivalence test, deployed-estate risk estimate or estimate of actual upgrade work. Higher disclosure can reflect more scrutiny. Missing coverage cannot support a similarity conclusion.

### Approaches considered

- **Descriptive study — selected by the maintainer:** consistent declared scope and periods; CVE, severity, KEV and remediation-publication observations alongside gaps. This fits the intended exploratory use and can proceed without customer inventory.
- **Formal equivalence study — deferred:** predeclare a practically meaningful difference and obtain sufficiently comparable enumeration, exposure and adjudication to test it. The current dataset does not establish those prerequisites.

My implementation proposal is incremental: prove source access/enumeration, add typed score/scope evidence, then assemble the study. This sequencing is a builder call for review, not an additional selection the maintainer has already made.

## Registered scope and dates

Create an independently versioned and fingerprinted `campus-branch-switching` definition. Preserve the existing 24-CVE benchmark, legacy switching plan (NX-OS/AOS-CX/EOS/Juniper), product-cohort resources and original human-review packet.

Declared targets are IOS XE on Catalyst 9200, 9300/9300L, 9400 (C9407R/C9410R), 9500 and 9600 (C9606R); AOS-CX on CX 6300M and CX 6410; and EOS on 7050X3, 720XP and the 750 campus chassis series. Do not expand 750 to 7500 or collapse nearby product identifiers. Resolve series/individual-SKU ambiguity with cited vendor catalogues and preserve the literal target names. Record supported roles, lifecycle dates and release-train associations only where primary documentation establishes them; unknowns stay unknown. Do not declare these unequal model sets equivalent.

Use two explicitly labelled scope levels:

1. **OS-family context:** explicit family applicability statements, including model-unspecified statements and their conditions. Identifiable out-of-target platforms remain traceable and are excluded from the model-qualified subset.
2. **Model-qualified subset:** source statements explicitly naming a declared model/series, its exclusion or another reviewed, unambiguous publisher scope binding. A family name or generic release expression alone cannot establish named-model applicability. Record unresolved model scope separately.

Present these levels separately; OS-wide counts must not be labelled confirmed impacts on the listed models. Preserve per-model/version/configuration branches, product IDs, ancestry and locators. A fixed-only statement does not establish prior affectedness. Contradictions and mixed platform statements retain their own contexts.

The mandatory historical start is 2021-01-01. Earlier official history is desirable additional coverage, not a prerequisite for the initial 2021-onward report. Each publication has an explicit observation end date; 2026 is partial until year end. Calendar-year rows and nonoverlapping date partitions use pre-cutoff `[2021-01-01, 2026-04-07)` and post-cutoff `[2026-04-07, observation_end]`. Date-only publisher dates retain their calendar day; timezone-aware timestamps use UTC; unusable timestamps enter an undated bucket. The cutoff is descriptive; no intervention or causal explanation is asserted.

Match existing chronology semantics: latest retained statements grouped by the advisory's initial publisher date. Label that basis plainly. Later-added CVEs can therefore be associated with an older advisory year; these are not counts of newly disclosed CVEs or historical as-of exposure. Record explicit CVE-statement dates separately when available. A CVE can appear in more than one year's distinct set; annual counts must not be summed as a unique overall total.

Remediation-publication events use the evidenced event's initial publication date; an unbundled event uses its advisory's initial publication date. An update does not create another event without a distinct, explicit publisher event identity. Preserve update and first-observed remediation dates separately; neither proves when a fix first became available.

## Primary sources and retained evidence

### Cisco feasibility and connector

Existing Cisco RSS/CSAF/vendor-CNA and reviewed HTML handling remain useful. Current data already contains limited IOS XE statements; the gap is systematic Catalyst-qualified coverage. Before broad collection, establish a bounded source-led sample spanning a Catalyst-specific advisory, conditional family-wide statement, multi-CVE scheduled bundle and version-leaf CSAF tree. Verify identity, date, scope, fixed-version and alternate-representation fidelity. Existing recorded anonymous CSAF 403s are access observations, not proof that every route remains blocked.

Use the currently documented openVuln v2 all/year/date pagination for candidate enumeration. OS software checking is version-specific (`/OSType/iosxe?version=...`); the old `/iosxe` route is sunset and neither software nor broad product search establishes complete model scope. Review the actual API response before deciding which claims it can substantiate. Metadata and inaccessible advertised CSAF links cannot manufacture product assessments; retrieve and bind official advisory HTML/CNA/CSAF evidence as required.

Authentication uses environment-provided `CISCO_OPENVULN_CLIENT_ID` and `CISCO_OPENVULN_CLIENT_SECRET`; the maintainer provisions approved credentials securely. No Cisco-named Actions secrets were configured during reconnaissance. Missing credentials produce explicit `auth_not_configured`, not zero advisories or completed coverage.

Token acquisition is a separate credential-only session, outside evidence/cache persistence. Tokens remain in memory, refresh within documented lifetime, and never appear in URLs, captures, errors, logs or public data. Bearer headers are allowed only on the reviewed exact API host; broad vendor-domain redirect permission must not forward them. Retain public advisory/API document evidence, never token responses. Use persistent quota accounting across resumed runs, obey Retry-After and bounded backoff, and stop on access/entitlement failures. The reviewed documented caps are 5 requests/second, 30/minute and 5,000/day; implementation verifies current official limits and stays within all three.

### Aruba and Arista history

Reuse existing archive discovery, checkpoints, retry/error classification and plugin normalization. The reviewed 3 November publication exhausted Aruba's known 110-document CSAF queue, with usable dates beginning in February 2022. Investigate official older HPE/Aruba sources to establish 2021 coverage; another pass over that index is not proof of earlier coverage.

Arista traversed 21 pages, discovered 202 documents and retained 52 document errors. Triage these by access/layout/identity/scope before widening parser coverage. Preserve the 37 retained CSAF draft statuses. Reconcile official HTML/CSAF representations through reviewed publisher identity/CVE bindings; retain differing source status and chronology, and never automatically promote a draft. Keep draft, interim, final, withdrawn and unresolved representations distinguishable in counts.

Preserve literal publisher advisory identifiers and explicit sequence numbers where present. Add reviewed canonical identity bindings across representations without rewriting historic core identities or treating adjacent sequence numbers as proof of missing/hidden advisories. Bundles require a retained vendor event identifier/page and explicit membership; same-date publication is insufficient.

Every source body and normalized revision keeps source URL, retrieval time, SHA-256 and revision history. Keep parser reinterpretation distinct from new retrieval. Unknown or excluded scopes remain visible. Use synthetic public fixtures with source-led expected assertions; retain vendor captures within the existing evidence boundary.

### Bounded full backfill

A full backfill is one logical, resumable operation that can span bounded batches and quota windows, not an unlimited single workflow execution. Reuse CLI backfill controls and a dedicated staging vault/configuration; do not seed from or modify a native research vault. Preserve scheduled incremental budgets. Avoid repeatedly resetting exhausted failures.

Freeze an enumeration manifest per source/window with pages/cursors, declared totals when supplied, discovered stable identities, duplicates/withdrawals, retrieval/parse states, errors, missing dates, timestamps and hashes. Known listing exhaustion, successful retrieval and period/OS/model classification are separate facts. Blocked documents with unknown dates or products cannot disappear from the denominator. Report expected totals as unknown where the publisher does not establish them; never equate a drained queue with portfolio completeness.

Preflight archive, database, recovery and publication sizes. Keep existing limits: 512,000-byte target parts, 8,000,000-byte maximum parts, 2,000,000-byte index and 20,000,000-byte default-monitor budget. Do not enlarge hosted storage/delivery limits or enable publication to get a backfill through. Produce a staged run summary even when credentials, routes or layouts prevent completion.

## Scores, platform evidence and compatibility

CSAF/CVE score objects already exist internally; public projection currently clears metrics. Introduce a strict, allowlisted CVSS claim contract and project only its validated fields into the existing advisory-v2 `metrics` array. Record CVE, source/product scope, scorer/provider, CVSS version, base score, vector, source URL/hash/revision and observation time. Preserve missing components explicitly; reject invalid values visibly rather than inventing scores or dropping otherwise valid applicability silently. Never expose arbitrary raw metric objects or private extensions.

Retain all score claims. Prefer applicable vendor-advisory scores; otherwise use an official CVE record, then NVD, with provider identity and explicit CVE-level fallback attribution. Vendor ratings such as SIR remain separate. Do not silently choose the highest conflicting score. Show version-specific severity facets, None/Unknown, and ambiguous or multiple scored contexts separately. A cross-vendor severity table distinguishes vendor-scored from fallback-scored counts; overlapping versions/contexts are not additive distinct-CVE totals.

Existing optional `platforms` remain string arrays and `identifiers` retain their current CPE/purl meanings. Keep source expressions in versions/remediations. Structured platform/model bindings, preconditions, publisher identities/sequences, bundle links and richer date evidence live in a separate versioned public evidence report keyed by advisory/revision/CVE/source-product identity. Preserve source ancestry even when leaf labels are version strings; test duplicate-ID and relationship lineage loss. No automatic model/version matching or deployment inference is introduced.

No new advisory-v2 top-level or assessment properties are required by this proposal. Existing strict readers can accept the already permitted metric-object array; the new metric validator and evidence/report schemas carry their own versions. Older publications without new data remain explicitly unavailable. Publishing scores is an intentional allowlist change, not removal of the existing privacy boundary.

KEV already carries the full catalogue index and joins the entire publication scope. Newly collected CVEs use that join automatically; no selected-24-CVE restriction is introduced. Retain current read-time freshness/unknown semantics and same-generation evaluation/source identity. KEV is exploitation context, not model affectedness.

## Descriptive report and reader

Add a strict `switching-comparison` v1 report for the registered study, plus its public definition/source-evidence links. Per vendor, scope level, calendar year and cutoff partition, expose:

- Distinct advisories and CVEs with explicit affected statements; partially mitigated, shared-bulletin, fixed-only, unaffected, conditional, mixed/conflicting, draft and unresolved claims remain separately inspectable. State buckets may overlap across distinct product/version contexts.
- Explicit vendor remediation-publication events, with evidenced bundle identity/membership and unbundled publications shown separately. Label them publication events, not actual upgrade counts. Only published available vendor-fix statements contribute; planned fixes, workarounds alone and missing remediation evidence remain separate.
- Version/provider-qualified CVSS severity observations, vendor severity and current KEV membership, with missing/ambiguous states and denominators.
- Source/window coverage: known expected/discovered/retrieved/parsed/classified counts, unresolved dates/models, errors and declared enumeration boundaries. Show scope/basis beside every result; zero is distinct from unavailable or unestablished coverage.

Do not add a median fix delay in the initial study. Retain explicit fix-date evidence for a future separately approved timing design. A first-listed version label, shared document date or local observation does not establish first fix availability. Verified fix-delay fields and existing research gates remain suppressed.

Use a new descriptive option within the existing Vendor comparison area, leaving old plans identifiable. Its default population is the complete registered study scope, independent of the ordinary 24-CVE benchmark selector; show which controls apply. Drill-down subsets preserve requested/effective study scope in exports. Display methods, date basis, source gaps and the caveat: **Counts measure disclosure, not vendor security quality; higher disclosure can reflect more scrutiny.** Do not compute a winner, security rank, equivalence verdict or an automatic 'no difference' conclusion.

Publish generation-bound JSON and CSV, a native read-only `/api/v1/switching-comparison` endpoint and matching static selection. JSON provides claim/source traceability; summary CSV rows include study-definition identity, publication, scope level, window, counts, coverage state and score/KEV basis. Document filters, date boundaries, unavailable states and limits in OpenAPI. Native/static selectors, exports and displayed rows must agree. Readers make no upstream requests and never merge evidence generations.

## Validation, completion and authorization

Add at least five source-led boundary cases per vendor: affected, unaffected, fixed-only, platform exclusion and bundled/multi-CVE publication handling. If a vendor has no evidenced bundle concept, test missing bundle identity and a real multi-CVE document; do not invent a bundle to fill the matrix. Register the new set separately, retaining source hashes/locators and expected outcomes. Report per-vendor full-byte matches, scoped assertion matches, failures and denominators; these are sample checks, not global precision. Independent human review remains pending.

Exercise authenticated transport redaction/redirects/quotas/resume; malformed and corrected official source layouts; draft/final identity; CVSS/fallback scope; platform exclusions and preconditions; date/cutoff boundaries and undated claims; bundle deduplication; missing denominators; full-scope KEV and stale data; old publications; hostile text and native/static/export parity. Verify clean source/wheel/external plugin acceptance and supported Python/container CI. Use a staged real-source run summary with per-family/per-year counts, unknowns and source errors before any hosted publication change.

The builder may choose internal table/module decomposition and bounded batch sizes within the registered limits. It may not choose new statistical endpoints, product equivalence, secret provenance, relaxed evidence gates or larger runtime limits silently.

Approval of this written design is followed by an implementation plan for review. That plan must explicitly identify the proposed public-score/report/UI changes and any secret wiring. Existing schedules, automatic publication behavior and hosted workflow permissions stay unchanged until the maintainer approves a concrete change. A CLI-first staged backfill can be implemented without altering them; a hosted full-backfill mode, publication transition or release activation requires separate explicit approval. No customer names/data, secret values, private review submissions or raw operator receipts enter the repository or release assets.

## Primary references checked during reconnaissance

- [Cisco authentication](https://developer.cisco.com/docs/psirt/authentication/), [all-advisory enumeration](https://developer.cisco.com/docs/psirt/obtain-all-advisories/), [current software route](https://developer.cisco.com/docs/psirt/ostypeostype/), [API quotas](https://sec.cloudapps.cisco.com/security/center/resources/openvulnapi).
- [Arista 7050X3](https://www.arista.com/en/products/7050x3-series) and [750 campus series](https://www.arista.com/en/products/750-series): product roles are source descriptors, not an equivalence certification.
- Code/sanitized-publication reconnaissance on 4 November: publication `cc672063ffb04700a40cebc29f84f9e6`, generated 3 November 19:50 UTC; Cisco 34, Aruba 109 and Arista 150 records; extraction validation 13/25 and separate benchmark 44/47. These are dated observations, not completion thresholds.
