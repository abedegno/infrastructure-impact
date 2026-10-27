# Check Point public-index row scope — 27 October 2026

The official [public product-advisory index](https://iapi-services-ucs.checkpoint.com/public/api/support-center-mms/api/securityAdvisories/getAllActive)
can contain several CVE rows with the same SK identifier. The previous adapter
returned one normalized document per row, and routine collection successively
wrote them under that same advisory identity. Only the final row remained in the
latest view. Offline maintenance correctly refused the resulting ambiguous batch,
but routine collection could write those partial interpretations again.

The retained index capture with SHA-256
`1aaa948e8acfed2b0d34fb108fb12f21f6abeddffa5eca186757f15e840a04b7`
contains 157 rows, 76 logical advisory identities and 14 repeated SK groups.
A separate source-row/CVE/locator multiset check accounted for all 931 product
statements after grouping, with no missing or added association. This is an
assistant review of that exact response, not independent human adjudication,
portfolio completeness or a claim that every historical advisory is in the index.

For example, `sk176865` has five explicit CVE entries: CVE-2021-4104,
CVE-2021-44228, CVE-2021-44832, CVE-2021-45046 and CVE-2021-45105. Its combined
interpretation retains 30 row-specific product statements rather than only the
six belonging to the final row. Each statement keeps its own source-row locator
and CVE association; no product is cross-joined onto other rows' CVEs. Numeric take
expressions and unknown-detail markers remain literal; they do not establish
independently verified fix availability.

The adapter groups only an exact repeated SK identity with agreeing article links.
It preserves the original single-row behavior for other records. Duplicate source
row IDs, unreviewed repeated aliases or disagreeing article links fail for review.
For combined records, differing publication or update dates produce a null
advisory date rather than an invented earliest/last disclosure date. Private row
metadata remains attached to the normalized revision and is excluded by the public
projection. Public source hashes and row locators still identify the primary data.
The generated combined title explicitly describes an index grouping rather than
claiming to reproduce an SK article's title.

A common feed-writer guard now rejects repeated vendor/advisory identities before
its first advisory write, protecting other installed plugins from the same loss
pattern. Offline replay of earlier same-byte interpretations appends a
`parser_reinterpretation`; it preserves the SK identity, original capture time,
raw evidence and HTTP observation history. It does not invent a later publisher
CVE disclosure event. Frozen review packets are unchanged and still require the
user's independent review. This correction does not establish comparative vendor
rates or concealment.
