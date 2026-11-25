# Cisco targeted release-date coverage supplement

Research date: 25 November 2026. **Human review pending.** Research only.

The bounded pass found **eight explicit release dates for other Catalyst platform
scopes, and zero dates directly established for Catalyst 9200/9300**. The sixteen
study-family/version date rows therefore remain unknown. This supplement cannot
supply the target catalogue's yearly denominator or a withdrawal rate.

Cisco's public [ISSU lookup page](https://www.cisco.com/c/dam/en/us/td/docs/Website/enterprise/issu-matrix/pages/cat9k/cat9k-issu-matrix.html)
links a [release lookup workbook](https://www.cisco.com/c/dam/en/us/td/docs/Website/enterprise/issu-matrix/pages/cat9k/ISSU_Release_Lookup.xlsx?v=20260806-2).
Its platform worksheets have explicit Release and Release Date columns.
The retained seven rows below are from worksheet `c9500h`, scoped to Catalyst
9500 High Performance. The workbook contains no C9200/C9300 worksheets. Other
platform worksheets were inspected for context but are not silently collapsed
into a train-wide or study-model release date.

| Version  | Source release date | Exact source locator                                                     |
| -------- | ------------------- | ------------------------------------------------------------------------ |
| 17.12.1  | 2023-07-28          | Workbook `c9500h!A23:B23`                                                |
| 17.12.2  | 2023-11-15          | Workbook `c9500h!A22:B22`                                                |
| 17.12.3  | 2024-03-21          | Workbook `c9500h!A21:B21`                                                |
| 17.12.4  | 2024-07-24          | Workbook `c9500h!A20:B20`                                                |
| 17.12.5  | 2025-03-18          | Workbook `c9500h!A19:B19`                                                |
| 17.12.6  | 2025-09-01          | Workbook `c9500h!A18:B18`                                                |
| 17.12.7a | 2026-03-25          | Workbook `c9500h!A17:B17`                                                |
| 17.12.8  | 2026-08-05          | ISSU HTML inline supplemental release record and Release Date assignment |

For 17.12.8, the public page's inline script supplements the workbook at runtime:
it names that exact release and assigns the explicit release-date field to
5 August 2026 for a specified C9400/C9500/C9600 variant set. This is a static
inspection of the supplied release metadata. It is not inferred from the page's
update timestamp. The JSON preserves the code fragments and narrower scope.
All eight source date values are already ISO calendar-date strings; normalization
is an identity operation, with no Excel serial or timezone conversion.

The [C9200 What's New chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/whats_new_in_cisco_ios_dublin_1712x.html)
and [C9300 What's New chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/whats_new_in_cisco_ios_dublin_1712x.html)
were checked in full origin HTML. They supply release feature headings, including
17.12.7a, but no per-version release dates. Their document-update date was rejected.
Official-domain searches returned product-index dates and router/wireless material
without establishing dates for the study switches. Recommendation dates, advisory
first-fixed labels, document publication dates and HTTP metadata were not used.

The web service could not read `software.cisco.com/robots.txt`; no source HTTP
status was supplied. No authenticated download or openVuln service, hidden API,
firmware binary, private reference or internal workbook link was accessed. This
pass does not establish that no public download metadata exists.

The [JSON delta packet](2026-11-25-round4-coverage-cisco.json) retains source URLs,
cell/code locators, short quotations, retrieval times, distinct original and
excerpt hashes, attempts and unresolved dates. Five new anonymous origin sources
returned substantive HTTP 200 responses: two What's New chapters, the ISSU page,
its linked lookup JavaScript and the linked workbook. Requests were bounded,
throttled and checked against same-day cached Cisco robots rules; no login or
challenge bypass was used. Cisco terms remain an internal-research boundary,
not authorization for redistribution or collector activation.

Full source bytes and excerpts stay outside Git under
`$RELEASE_RELIABILITY_CACHE/cisco`. The original research packet, application code,
notices, withdrawal conclusions and production dataset were not changed.
