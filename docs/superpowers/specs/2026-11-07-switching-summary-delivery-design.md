# Bounded switching-summary delivery repair

The maintainer asked us to continue autonomously without further questions. This is a focused repair of the observed offline publication failure, not hosted activation.

## Intent and evidence

The 174-document retained-evidence replay passed audit, then `write_static_delivery` called `write_part(summary(report))` and exceeded the unchanged 8,000,000-byte part limit. The summary removes inputs but retains potentially large row identifiers, events and provenance. Existing claims are chunked; this summary is not. Do not infer complete archive capacity from that failure.

## Approach

Keep the existing single `switching.summary` part for summaries that fit. For oversized summaries, add a mutually exclusive `switching.summary_fragments` descriptor containing ordered content-addressed parts plus the original UTF-8 JSON byte count and SHA-256. Each part uses the existing publication envelope, with a JSON string fragment as its data. Reassemble the exact original bytes before parsing and validating the unchanged summary contract. Fragment on Unicode boundaries, preserve order and repeated equal fragments, verify each envelope/hash/size and the reconstructed whole hash/size. Browser fetch concurrency stays bounded by the existing six-request pattern. The monitor uses the same reconstruction and existing actual-read budgets. Bound declared and accumulated reconstructed size before joining to the existing 128,000,000-byte expanded archive ceiling; this is a defensive upper bound, not a raised publication limit. Default 20 MB network and 8 MB part budgets remain unchanged.

A larger part limit would weaken a deliberate guard. Dropping identifiers or replacing the summary with counts would alter exported meaning. Structured splitting of every row field would spread a data-model change across reducers and readers. Lossless ordered fragmentation is the smallest transport-only repair and preserves the full semantic report.

## Boundaries

No evidence deletion, changed applicability, source acquisition, recovery access, merge, hosted dispatch, source pin, scheduling or permission change. No dependency or advisory-v2 changes. The static index remains v1 with a backward-compatible optional capability: exactly one legacy summary or fragmented summary. Current readers continue to accept old publications. Python and generated JavaScript schemas change together. Existing full report and CSV semantics remain exact.

## Acceptance

Reproduce the old failure with authored data, including a real >8 MB summary, then test browser and standalone monitor reassembly and report parity. Reject tampering, wrong size/hash, invalid fragment type, mixed generation, reordered/missing fragments and both/neither capabilities. Retain UTF-8 and repeated-fragment cases. Preserve fail-closed publication when another limit is reached. Run affected delivery/monitor/schema/distribution tests and existing Node checks. Repeat the actual retained-evidence laboratory run once after the focused fix passes; retain intermediate diagnostic products outside Git to avoid repeated expensive queries. Report each measured gate honestly; this local 223-record stage is not the complete hosted inventory.

## Confirmed adjacent index boundary

The same retained run has 34,923 claims. Their quoted 64-character IDs alone occupy at least 2,339,841 serialized bytes, exceeding the existing 2,000,000-byte index ceiling before descriptors/cohorts. This is a concrete lower bound, not another guessed failure. Keep small legacy inline `switching.claims` catalogs. For a large catalog, use mutually exclusive `switching.claim_catalog` (ordered ordinary part descriptors), where each part holds an ordered array of the existing `{claim_ids, part}` entries. Reconstruct and validate that catalog lazily for claim drilldown/full hydration, including cross-part duplicate membership and descriptor contracts. Preserve the exact claim order, IDs, hashes and row data. The standalone monitor validates catalog membership/descriptors without downloading all claim bodies, still within its existing actual-read budget. Every new transport capability is validated before choosing the branch. Whole-candidate verification continues checking all manifest assets and regenerated output; no raw evidence is dropped. Tests cover legacy/catalog and legacy/fragment summary combinations, missing/tampered catalog metadata and bounded fetch concurrency. If a catalog itself needs multiple metadata parts, preserve order across them; if another hard limit is reached, fail visibly.
