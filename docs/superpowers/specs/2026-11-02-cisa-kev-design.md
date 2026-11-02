# CISA KEV enrichment

Status: approved by the maintainer on 2 November 2026. Prepare the implementation plan for review; implementation has not started.

## Intent and scope

Add CISA Known Exploited Vulnerabilities (KEV) context across the project's collected CVEs, with badges, filtering, publisher metadata and reproducible exports. Keep exploitation intelligence separate from vendor/product/build affectedness. KEV membership must never create a vendor assessment, certify shipped components, change frozen studies, establish first exploitation/disclosure or support a vendor security ranking.

The selected approach is a retained reference feed joined by exact CVE ID into each immutable publication. My implementation proposal is to reuse the existing reference-document storage and collection infrastructure rather than introduce a vendor plugin or a new database. The alternative of fetching independently from each browser would not share the publication's retained evidence or support offline/static selection. An independent KEV dashboard would add a separate product surface outside this requested integration.

For transport, my proposed initial source is CISA's own mirror:
`https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json`.
Direct CISA page/feed requests returned 403 during reconnaissance; the official mirror was accessible. CISA describes it as synchronized shortly after the canonical source. Preserve both the actual retrieval URL and canonical catalogue attribution; do not label mirrored bytes as a direct CISA retrieval. No scraping, proxy, challenge bypass, credentials or automatic source switching is required. A future direct-feed/fallback policy is a separately reviewed transport change.

## Collection, normalization and retention

- Register KEV as a separate enrichment-purpose reference source. Keep existing NVD/OpenSSH study inputs separate; adding KEV must not send its payload through the frozen component-study parser or change that study's enrollment/fingerprint.
- Add the reviewed KEV entry to public root and bundled default source configurations together. Preserve the existing native custom `sources.json`; absence from a custom configuration yields explicit unavailable/not-configured context rather than silently enabling a request.
- Use the existing reference revision/evidence and collection-health tables; no SQL migration or runtime dependency is expected. Retain the complete valid source privately, including unchanged-fetch observations and later corrections/reversions. Readers use only sanitized publications and perform no upstream request.
- Bound the feed at 8,000,000 bytes and 20,000 entries. Require a nonempty complete envelope with non-Boolean integer count equal to the entry count, unique canonical CVE IDs, valid release timestamp and required fields/dates. Reject malformed/duplicate-key/non-finite JSON, duplicate CVEs, truncated/oversized content and invalid dates before replacing the normalized last-good catalogue. Keep the failed collection visible.
- Normalize known fields explicitly; retain original bytes for future schema additions. Preserve CISA's literal vendor/project, product, vulnerability name, description, required action, date added, due date, ransomware-use value, notes, CWE list and optional forensic-triage value. Optional missing fields stay null/empty as appropriate; unknown publisher values are not converted into a reassuring Boolean.
- Preserve catalogue version, publisher release time, raw SHA-256, parser version, source/revision identity, latest attempt and successful verified check time. A successful unchanged fetch refreshes check time without manufacturing a content revision. Catalogue release time is not a freshness clock: a successfully checked, unchanged weekend catalogue can still be fresh.

## Common public contract

Add a strict version-1 `kev` enrichment report, separate from advisory and existing research-report schemas. It contains:

- Source identity, catalogue version/release time, declared count, check/attempt metadata and policy limits.
- A complete sorted `listed_cve_ids` membership index from the retained validated catalogue.
- Detailed entries only for the publication's imported/benchmark CVE union, keyed by exact CVE ID. These are CISA statements, never a vendor/product match inferred from names.
- The immutable publication identity/time, and a distinct `evaluated_at` timestamp for freshness calculations in selected views/exports.

The compact full membership index permits an exact lookup for a user-entered CVE outside the local advisory set. Its detailed CISA record may be unpublished; show membership plus the source link without fabricating missing details or an appliance impact. A valid ID absent from a fresh complete index means **not listed in that catalogue**, not nonexistent, unexploited or unaffected.

A design-sizing observation on 2 November used catalogue `2026.10.30`: 1,766 entries; 71 matches in the project's 3,993 imported/benchmark CVE IDs. Full IDs plus matching details occupied about 103 KB. These are sizing observations, not fixed counts, affected-product totals or coverage guarantees. Keep the existing 512,000-byte target, 8,000,000-byte maximum part, 2,000,000-byte index and 20,000,000-byte default-monitor budgets unchanged.

## Freshness, failure and time semantics

Effective membership has three states: `listed`, `not_listed`, `unknown`. The source separately exposes availability/freshness and the last retained catalogue. Latest collection failure, missing successful verification, disabled/unconfigured source, or a verified check older than 36 hours makes current membership unknown. Retained prior entries remain available as clearly historical context, not fresh status. Future verification timestamps beyond five minutes of clock tolerance are unavailable.

Evaluate freshness from the source's verified check time and latest-attempt outcome, not its release date or first observed content hash. Use the same rule in native and browser selection with an explicit injectable evaluation time for parity tests. Default selected views evaluate at read time; exports record that distinct `evaluated_at` while retaining the original publication identity/time. No newer source is fetched to fill an old generation. Date-only `dateAdded` and `dueDate` stay dates; date added is not a first-exploitation/disclosure date.

An older publication without KEV has an unavailable state. A current valid feed with no matching entries is distinct from unavailable data. No failure may become a fresh empty catalogue or negative membership result.

## UI, filters and exports

Use the existing visual style and navigation. Add a CISA KEV-listed badge beside relevant CVE identifiers in Product impact and dossier views, with dated source details and an unavailable/stale indication. Present CISA's due date, action, ransomware and optional triage values as attributed publisher metadata; do not declare an organization's legal deadline, prescribe a device upgrade from KEV alone or interpret `Unknown` ransomware use as `No`.

Add an optional **KEV-listed only** control intersecting the user's requested CVE cohort with fresh KEV membership. Preserve requested scope separately from effective scope. Do not filter by CISA vendor/product strings. Existing product assessments, vendor filters, eligibility gates and frozen studies retain their meanings. A valid fresh catalogue with no listed matches produces an explicit empty selection. If membership cannot be evaluated reliably, reject the KEV-only selection with an explicit `kev_unavailable` response (native/static HTTP 503); preserve the last committed view with a clear error rather than silently emptying or broadening it.

Expose the additive report in state/snapshot and a generation-bound `kev.json`/native read-only report endpoint. Include KEV fields and evaluation/source identity in selected JSON/CSV exports; provide a same-generation KEV JSON download. Keep existing single-dossier JSON as its established evidence contract, with KEV context supplied through the separate enrichment/state export rather than silently altering the dossier schema. Escape publisher text and use existing safe-link rules.

Native selectors, the real static request adapter, browser controls and downloads must agree on valid/repeated/invalid filter handling, arbitrary CVE membership, time evaluation, vendor coexistence, legitimate empty results and unavailable data. Slow older requests cannot replace newer committed evidence. An already-open page re-evaluates KEV age on render/refresh before applying the filter; no timer-driven upstream fetch is introduced.

## Verification and release

Use synthetic fixtures only: schema evolution, invalid/truncated feeds, duplicate IDs/keys, unchanged checks, last-good retention, correction/removal/reversion, old release with a fresh fetch, stale/failed/future checks, literal dates and ransomware/triage values. Exercise actual collection/query/publication boundaries, frozen-study isolation, Python/JS selectors, static interception, empty/custom scopes, hostile text, coherent exports and stale-response guards.

Validate public report schema/fingerprints/source identity and unchanged policy bounds with the standard-library monitor. Unavailable KEV is an honest upstream-data state, not by itself a failed public-site health check. Verify source export, installed wheel/external plugin behavior, distribution resources, full suite and exact supported-Python/container CI; use a real-browser synthetic publication before release and a controlled hosted collection after authorized activation. Retain actual feed health and membership/source counts; do not treat manual publication as scheduled reliability.

Update source/data attribution for CISA's CC0 mirror. Source release, runtime activation and live verification remain deliberate steps after review. Preserve original observation anchors, schedules, recovery controls, private evidence boundaries, existing frozen research resources and the native custom configuration. Terrapin/cohort expansion remains subsequent work; this feature creates no new vendor enrollment or inventory claim.
