# Round 6: binary dates and Cisco 17.9.6 control

Research only; independent review pending. The [JSON packet](2026-11-27-round6-dates-control.json) records **zero new admissible model-bound binary release dates**. IOS XE 17.12 on Catalyst 9200/9300 and EOS 4.33 on 720XP/720DP remain unknown. No catalogue, denominator or production resource changed.

Eight fresh official-domain search batches, 32 queries, covered document histories/revisions, What's New, release-information and documentation indices, software-image tables, and image/lifecycle discovery. All returned source content is labelled `tool_excerpt`, with original-document hashes null. The JSON supplies every selected fact's official URL, stable locator, exact quotation, UTC recording time, excerpt SHA-256 and capture path. Search results are incomplete indexed extracts, not complete archives. Per-query empty results are not inferred from mixed search responses.

| Source control | Date found | Date kind and disposition |
| --- | --- | --- |
| C9200 17.12 release-note book and What's New | 2026-08-05 | `document_revision`; rejected as binary release date |
| C9300 17.12 image chapter | 2026-08-05 | `document_revision`; rejected as binary release date |
| C9300 17.12 command reference | 2023-07-28 | `document_revision`; rejected despite coincidence with other-platform evidence |
| Catalyst recommendation revision 24.0 | 2025-11-26 | `document_revision`; recommendation update, not software publication |
| C9300 17.12.7 and C9200 17.12.1 image rows | None | Binary names without release-date assignment |
| Arista product bulletin index | None | 4.33 release references without dates or model binding |
| Arista TOI article | 2024-10-18 | Article publication/update only; revision remains `document_revision` |
| Vendor-hosted certification DTR #4 | 2025-04-10 | `certification_approval`; rejected as software date |
| Existing Arista lifecycle image | 2024-10-10; 2026-10-23 | Train initial date; `document_revision` respectively, neither a model-bound binary release date |

The lifecycle image was **rehashed locally**, not fetched again. Its prior visual transcription, original retrieval time and original-document SHA-256 remain in the JSON. The row names the 4.33.x train; it does not assign a literal binary/date to either study model. RSS announcement dates were not promoted. Previously gated Arista bulletin/detail routes were not retried.

## Outside-cohort Cisco 17.9.6 control

**Result: `not_established`.** Withdrawal, deferral and explicit supersession by 17.9.6a remain unknown; notice date, action date and software release date are separately null. The official [C9300 What's New chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/release_notes/ol-17-9-9300/whats_new_in_cisco_ios_cupertino_179x.html) names a CSCwm57734 fix in 17.9.6a; the [Caveats chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/release_notes/ol-17-9-9300/caveats.html) corroborates the fix. Exact short quotes and locators are `c9300-1796a-fix-fresh` and `c9300-1796a-caveat-fresh` in the JSON.

This control was **already recorded** in [round4 Cisco](2026-11-25-round4-cisco.json), evidence ID `control-1796a-fix`, and [the publisher event sample](2026-11-25-publisher-event-sample.json). Its original source capture and extracted quote both rehash to the prior fingerprints. This pass improves discoverability and fresh indexed corroboration; it adds no publisher-action claim. The fix statement does not explicitly name 17.9.6 as affected or replaced, so neither supersession enum is warranted.

Search receipts `search01`–`search03` retain the attempted `superseded`, `superseded by`, `replaced`, `replaces`, `deferred`, `defer`, `withdrawn` and `no longer` queries. Later-version existence, image omissions, unrelated router/wireless material and command removals cannot prove a switch-software withdrawal.

Cisco's known robots HTTP 403 was respected: **zero origin requests and zero detail opens**. No robots refetch, alternate-host bypass, authentication, mirror, private artifact or customer data was used. Raw tool responses and extracted records stay outside Git in `$RELIABILITY_ROUND6_CACHE/dates-control/`. Eight targeted batches reached repetitive nonqualifying sources; the bounded search stopped with unknowns retained.

JSON SHA-256: `42bc21ad5c0207d0628e50cee9f16f07944d8720681062833fbff77003d31eb6`.
