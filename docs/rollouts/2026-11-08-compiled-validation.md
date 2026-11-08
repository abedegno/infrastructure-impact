# Approved compiled validation rollout — 8 November 2026

The maintainer explicitly approved adding `jsonschema-rs==0.60.3` and implementing
the reviewed [proposal](../research/proposals/2026-11-08-compiled-validation.md).
The native dependency is now pinned in the manifest, `uv.lock` and the hashed
runtime requirements. Existing dependency versions remain unchanged.

The implementation keeps strict JSON/type checks, the original format callbacks,
Python regex behavior, installed-schema registration and denied/offline schema
retrieval. Native rejection goes through the original Python validator for
compatibility and error behavior. Semantic/provenance checks still run, and
only compiled schemas are cached. The study schema and public outputs do not
change.

## Preflight

- The new test failed against the missing helper before the implementation.
- All 193 targeted contract, mutation, scaling and runtime tests passed.
- Independent implementation review found no critical or important findings.
- A wheel built and passed the isolated offline distribution probe.
- The installed v2 worker, native/static checks, standalone monitors and
  missing-monitor rejection passed outside the checkout using synthetic inputs.
- Ruff, formatting, whitespace and public-source export checks passed. The
  export verified 650 files, synthetic fixtures and private-artifact exclusions.

The complete application suite and Python/platform CI are separate release gates.
PR #44 remains draft until complete hosted certification succeeds. Component
benchmarks in the proposal are not a full-hosted runtime claim.

## Recorded accepted baseline

The public accepted pointer was read at immutable publication-state commit
`6caac484839968a047668080a126062a63528545`:

- Database: 713,977,856 bytes.
- Accepted source/runtime pin: `d473d60ec46783750fcaa1795035603ca43a9100`.
- Accepted checkpoint time: `2026-11-08T18:10:54.453212+00:00`.
- Accepted-manifest SHA-256:
  `74ac7a8e4ab354b345a25a926b98cdf6af786533ec1ca42c20ddc3fdfc192f4e`.
- Public generation: `ff61832828904b6b9614c796d95146ae`.
- Public-index SHA-256:
  `cd765d3bff972cf3d109b28b5d0aabe00fc0b18ddf9979e31de8fa471f92a537`.

The manual certification workflow still checks out the accepted branch. Record
its resolved checkout commit and compare it with this identity; a moving branch
name alone is not a pinned-input measurement. Any concurrent routine collection
must be distinguished from experimental certification.

The retry will reuse encrypted captures from run `42510212446` on the GitHub
runner, authenticate them and rehash each target. No actual vault, encryption key
or ciphertext is downloaded to the operator's machine. No schedule, workflow
permission, live source activation or public promotion is changed by this rollout.
Final hosted results must be inspected before treating the candidate as accepted.

## Resumed full hosted attempt

[Run 42521786472](https://github.com/abedegno/infrastructure-impact/actions/runs/42521786472)
used source `a77baf0d06591e5e8b51ae120b4d9a5c4d7cea74`. The checkout log confirmed
accepted checkpoint `6caac484839968a047668080a126062a63528545`, identical to the
recorded baseline. The full local suite had passed 3,811 tests and 12 subtests;
Python 3.11/3.13 and container CI passed, as did the installed offline v2 probe.

The hosted candidate still failed: the worker finished normally after 2,204.69
seconds, and its closed phase diagnostics identified `stream_deadline` during
native query comparison. The audit passed; all 174 targets were imported with
zero HTTP attempts and received bytes. Capacity acceptance and standalone
monitor gates were not reached. This is not a successful certification.

| Completed phase | Seconds |
| --- | ---: |
| First projection | 231.18 |
| Writing | 444.45 |
| Independent projection | 232.24 |
| Native root verification | 576.55 |
| Query comparison (failed with inner deadline) | 454.67 |

The earlier same-checkpoint attempt took about 380/644/384/667 seconds in the
first four phases. These component improvements do not establish complete
pipeline acceptance, and runner variation remains possible.

## Decoded-claim follow-up

The query reader still used the Python `evolve().validate()` gate for every
decoded claim. The follow-up routes that exact installed claim-schema fragment
through the already approved compiled engine. It retains fresh strict JSON
checking, the original validator on rejection, all existing format/pattern and
offline-reference rules, and every identity/provenance/linkage check afterward.
Only the compiled claim schema is cached; no claim's validation result is cached.

The new fast-path regression failed against the missing helper before the fix.
The 142 targeted compiled-validation and reader tests passed, and the freshly
installed v2 worker and standalone/missing-monitor probe passed. Independent
review found no critical or important findings. Full-suite/platform checks and
another complete same-checkpoint certification remain required.

## Claim-path certification result

[Run 42526370751](https://github.com/abedegno/infrastructure-impact/actions/runs/42526370751)
used source `6b7086df2c5a168d7cf1b3f590f2a8a8fdbfb294`. Before dispatch, accepted
checkpoint `6caac484839968a047668080a126062a63528545` was confirmed unchanged.
All 3,818 local tests and 12 subtests passed; Python 3.11/3.13 and container CI
passed, as did the refreshed installed v2 worker/monitor probe.

**The performance/parity blocker is resolved for this run; complete certification
still failed.** The worker returned normally in 1,353.67 seconds (22.56 minutes).
Native root verification and native/static query comparison both passed. The
audit passed and all 174 targets were imported with zero HTTP attempts/received
bytes. The later capacity gate rejected the candidate with `candidate_capacity`;
`capacity_passed` and `candidate_validated` were false.

The native query comparison completed in 280.98 seconds; it had previously
failed with an inner stream deadline. Root verification completed in 321.00
seconds, and the first/independent projections completed in 153.09/162.15 seconds.
Whole-run timing differences also reflect runner variation; do not attribute
all of this reduction to one code change. Peak resident memory reached
6,134,284,288 bytes, so memory remains a separate architectural concern.

The rejection occurred after native parity. Inspection of the worker's capacity
classification identifies the standalone monitor's download/part-size gates.
The retained summary does not identify the particular request or exact monitor
assertion; do not claim a precise overflowing file from this result alone.
A local saved-public-sample replay passed the default monitor after reading
28,392,401 bytes against its 32,000,000-byte v2 transfer limit, showing limited
headroom but not reproducing the complete hosted failure.

PR #44 remains draft. Do not raise limits, weaken monitor checks, activate the
source pin or promote this rejected candidate. The next investigation must
identify the exact monitor budget/request and reduce the default payload or
reorganize validation while retaining complete-data checks. No further
unchanged full certification is justified merely to repeat the known rejection.

## Monitor capacity diagnostics

The next attempt retains a closed `monitor_capacity` event immediately before
an existing download-budget assertion. It distinguishes default versus archive
mode, cumulative transfer versus individual-part overflow, static resource
category, observed bytes and the unchanged limit. No document paths, URLs,
exception text or evidence contents enter this metadata. The worker and hosted
sanitizer preserve at most two such events. All existing acceptance checks and
budgets remain in force; these events do not establish candidate acceptance.

Actual per-file and aggregate overflow tests verify rejection and the emitted
metadata; hostile-input tests verify sanitization. The 173 focused tests, built
wheel/offline distribution checks, isolated installed v2 worker/monitor probe,
Ruff and source export passed. Independent review found no important issues.
The complete suite also passed: 3,819 tests and 12 subtests in 363.92 seconds.

## Reject monitor capacity before native parity

After physical inspection, the worker now runs both existing standalone monitor
modes before the independent native comparison, for v1 and v2. Both gates and
preservation checks remain mandatory before acceptance. A rejected monitor leaves
native parity unattempted, rather than spending its CPU budget on a candidate
already known to fail capacity. This changes verification order only, with no
budget, schema, publication, schedule, permission or activation change.

Four orchestration cases verify failure skips parity and successful candidates
still pass all gates. They failed against the former order before the change.
All 145 focused tests passed; the complete suite passed 3,821 tests and 12
subtests in 332.44 seconds. Independent review confirmed failed receipts allow
unattempted gate values and still fail closed. Run 42530463587 was dispatched
before this reorder and continues to use source `5b9de3fe88dc2b212286becf257aad3ff160fab8`.

## Exact capacity result and bounded table transport

[Diagnostic run 42530463587](https://github.com/abedegno/infrastructure-impact/actions/runs/42530463587)
used `5b9de3fe88dc2b212286becf257aad3ff160fab8`. Its worker completed in
1,327.00 seconds. Audit and native parity passed, but the **default monitor's
aggregate transfer limit** rejected a v2 part at 32,000,001 bytes against a
32,000,000-byte limit. This was not an individual-file rejection. All 174 targets
were imported from cached captures with zero HTTP attempts and received bytes.
The accepted branch remained `6caac484839968a047668080a126062a63528545`; the live
public index fingerprint still matched the recorded baseline.

The [bounded table transport design](../superpowers/specs/2026-11-08-table-transport-design.md)
adds optional deterministic gzip table sidecars while retaining raw assets and
self-contained archive scope. Monitor and browser verify both representations'
lengths and hashes, bound decoded output, and keep the existing table, envelope,
generation, token, routing and range checks. Transfer limits and decoded/cache
limits remain independent. No scheduling, permissions, accepted state or live
source activation changes are included.

A read-only overlay of the frozen 223-advisory public sample passed the actual
standalone default monitor with **13,865,516 bytes**, compared with **28,392,401
bytes** using raw tables. It made 109 HTTP requests / 108 asset-body reads in
both cases; this is a transfer reduction, not a request-count reduction. Its 39
sidecars transferred 4,239,922 bytes. This is a public-sample result, not complete
hosted certification, and it does not reduce decoded table memory.

Core tests cover strict descriptors/maps, deterministic production, unchanged
logical roots/archive scope, corrupted/truncated/trailing gzip and bounded
expansion. Monitor tests additionally prove rejection at exactly 32,000,001 bytes
while reading gzip, with the bounded sentinel read and no raw fallback. Browser
tests cover both hashes/lengths, oversized input/output, legacy compatibility,
cache accounting, cancellation, stalled readers/decoders and deadlines.
Task and fresh integration reviews found no important or critical issues.

The combined suite passed **3,879 tests and 12 subtests in 479.65 seconds**.
All nine JavaScript suites, source export, Ruff/format, Prettier, built-wheel
/offline distribution and isolated installed v2 worker/monitor probes passed.
The next cached full hosted certification remains the acceptance gate; these
local results do not authorize source activation or accepted-state promotion.

## Combined decoded-table bound and runtime portability

Final review identified that compressed transfer must not become an unbounded
aggregate decoded-table allocation. Nonempty transport maps now require the sum
of every strings/shapes descriptor occurrence to fit the existing 128,000,000-byte
selection ceiling, before any table fetch. Unmapped entries and repeated paths
count too. Empty/absent maps retain legacy behavior. This bounds serialized table
input, not exact process RSS. Boundary, combined-kind, partial-map and repeated
entry cases failed before the fix and pass afterward.

Linux CI 42534002069 also exposed a test portability issue: native gzip decoding
correctly rejected concatenated overflow with `TypeError`, while the test expected
only a library size/gzip error. The assertion now accepts that native rejection
and explicitly verifies no raw fallback or invalid cache entry. Content/length
checks are unchanged. Superseded hosted run 42534044246 was cancelled before
spending more parity CPU; the reusable capture cache remains run 42530463587.
The scoped fix re-review marked the aggregate issue addressed with no new
important findings. The 49 focused tests and fresh installed v2 probes passed.
The final guarded suite passed **3,889 tests and 12 subtests in 684.77 seconds**.
Ruff/format, Prettier, scoped re-review, fresh offline distribution and installed
v2 worker/standalone monitor checks passed. The read-only public-sample replay
still checked 13,865,516 transferred bytes. Complete hosted certification and
platform CI on this final revision remain required.
