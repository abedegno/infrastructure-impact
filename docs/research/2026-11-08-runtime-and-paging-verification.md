# Retained-data runtime and detail paging

The runtime fixes preserve the comparison's facts while removing repeated scans.
They do not change affectedness, CVE enrollment, source coverage, review status,
publication defaults, or resource limits. This work follows the maintainer's
request to stop compression work and make the retained import usable.

## Same-input query check

The saved public stage contains 223 current advisory identities. A read-only
query before and after the fixes used the same database and evaluation clock.
The private evidence context remained equal, and the complete public query JSON
was byte-identical after canonical serialization:

`73235d962d585d2bcbf66c879db31e7cf57334879371d6f72125540c34e46444`

| Measurement | Before | After |
| --- | ---: | ---: |
| Query wall time | 438.27 s | 88.88 s |
| Query CPU time | 96.20 s | 30.90 s |

Stack samples located repeated CVE-by-assessment scans, repeated preparation of
literal family patterns, and repeated family scans for each frozen-study CVE.
The fixes group statements by CVE once, reuse compiled literal patterns, and
build family groups once per study report. Score diagnostics similarly index
source contexts, CVE scores and attempts instead of scanning them for every row.
The indexes are invocation-local except for the bounded compiled-pattern cache;
no applicability or validation result is cached across queries.

Separate helper checks on the saved records also matched complete baseline JSON:

| Helper | Before wall time | After wall time |
| --- | ---: | ---: |
| Comparison | 12.46 s | 0.25 s |
| Scorecards | 12.45 s | 0.23 s |
| Frozen component studies | 14.99 s | 0.66 s |
| Score diagnostics | 18.13 s | 1.80 s |

These are measurements on this machine, not a service-level guarantee. CPU time
is reported separately because wall time varies with available resources.

## Indexed detail pages

Optional v2 detail indexes are separate from ordinary root ranges and are loaded
only when paging. Metadata identifies item boundaries and diagnostic vendors;
readers fetch the requested children and check their hashes. Independent native
verification checks complete index membership against projected facts. Totals,
ordering, cursor bindings, unknown values and existing vendor filters are
preserved. Older publications retain their existing fallback path.

First, middle and last pages matched the saved native facts for both arrays.
These measurements exercised the browser JavaScript readers in a Node VM,
not a live browser or the complete application startup sequence:

- **35,357 sources:** browser pages took 2.97–5.21 seconds and fetched at most
  664,910 additional bytes.
- **91,441 diagnostics:** browser pages took 6.78–7.51 seconds and fetched at
  most 800,328 additional bytes.

All six JavaScript-reader and six native checks passed. The reader's default transfer
remained 24,655,412 bytes. Previous full-array paging reached the five-minute
deadline. Native claims retain their existing reviewed-link validation path;
custom full-claim queries can still be expensive and are not certified by these
page-only measurements.

## Writer and verification scope

The writer profile also found duplicate root hashing and allocation of hash
objects for unindexed values. The correction creates hashes only for indexed
ranges, shares the root digest with its root range, and calculates the legacy
ASCII hash only for the snapshot. ASCII byte accounting and limits remain in
force for every root. A scaling regression dropped 204 empty hash allocations
for 200 unindexed values to a constant number; 153 root/range/archive/reader
regressions passed.

Integrated targeted checks passed 163 Python tests, browser/UI/codec suites and
independent code reviews. The frozen code commit is `2395163`; its six GitHub
checks passed. The installed wheel matched all 264 required source package files
and passed a fresh synthetic worker, audit, native parity and both HTTP monitors.
Its SHA-256 is:

`79f87466d4a3144dd034c2c4a60bf33c9608bea689bb7b290a4e07678789dc8c`

The retained-target replay at `2395163` still failed at the unchanged
2,400-second worker deadline. Its producer query took 50.66 seconds, projection
294.13 seconds and writing 584.16 seconds; independent native query and projection
took 97.68 and 318.58 seconds. All 174 retained documents were normalized with
their original capture dates, existing rows preserved, zero HTTP attempts and an
unchanged source database. Complete parity and monitor acceptance were not
returned, so this candidate is not accepted.

Sampling the saved publication isolated a further validation hot path: the
generic envelope union tried the string-table branch against arrays of detail
index objects, triggering quadratic uniqueness comparisons despite the wrong
document kind. Exact dispatch now selects the existing schema branch by its
literal kind and validates the complete envelope against that branch. Required
headers, closed fields, payload checks, references and existing limits remain
in force. Native and browser regression tests check both dispatch and malformed
envelope rejection; 195 targeted Python tests and the browser suites passed.

Verification against the saved publication passed in 596.74 seconds (238.91 CPU
seconds), including complete root and detail-index membership checks. The six
JavaScript-reader page checks also passed with the exact-kind validator: source pages took
1.72–2.86 seconds and diagnostic pages 3.77–4.08 seconds, with the same byte bounds.
Profiling outputs remain private diagnostic artifacts, separate from acceptance.

## Accepted local retained replay

The fresh replay using frozen code `ca27f6c` and the following installed wheel
completed successfully on 8 November 2026:

`e74e6df134809a33fc5b9dc9697cd2e0caeb56a87c6bc254a6144501aff8c919`

The worker took approximately 1,453 seconds, within the unchanged 2,400-second
limit. Audit, capacity, independent native parity, default HTTP monitor and
archive HTTP monitor all passed. All 174 retained documents were normalized;
existing rows, original capture dates and the source database were preserved.
HTTP attempts and newly claimed retrieval observations were zero.

| Publication measurement | Bytes |
| --- | ---: |
| Complete physical site | 464,855,421 |
| Expanded snapshot archive | 39,411,181 |
| Compressed snapshot archive | 5,037,754 |
| Default HTTP monitor transfer | 28,392,214 |

The accepted local generation is `bc5e22934d8b432b9e90b6b96fcacd3f`; its manifest
SHA-256 is `86db851af528e11cbd75a3d065318d737da4fe800a595fc112741c06b5eec51b`.
The [machine-readable proof](2026-11-08-retained-import-acceptance.json) records
the input, software and receipt identities and the explicit acceptance flags.
Earlier failed replay receipts remain preserved.

The pinned repair batch contains the following vendor publications by year:

| Year | Cisco | Aruba |
| --- | ---: | ---: |
| 2021 | 52 | 1 |
| 2022 | 24 | 0 |
| 2023 | 20 | 0 |
| 2024 | 26 | 0 |
| 2025 | 33 | 0 |
| 2026 | 18 | 0 |
| Total | 173 | 1 |

These are repair-batch document counts within a local 223-identity sample.
They do not measure comparable vendor affectedness or complete historical
coverage. No source acquisition or hosted activation occurred, and live source
reachability was not tested by this offline replay. The complete hosted union,
independent human evidence review and expensive custom browser query limits
remain separate from this local acceptance.
