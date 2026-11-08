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

First, middle and last pages matched the saved native facts for both arrays:

- **35,357 sources:** browser pages took 2.97–5.21 seconds and fetched at most
  664,910 additional bytes.
- **91,441 diagnostics:** browser pages took 6.78–7.51 seconds and fetched at
  most 800,328 additional bytes.

All six browser and six native checks passed. The browser's default transfer
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

Profiling outputs are private diagnostic artifacts, not accepted publications.
Verification against the saved publication is being measured before another
retained-target replay. No source acquisition or hosted activation is implied
by these measurements; the complete hosted union and independent human evidence
review remain separate from this local sample.
