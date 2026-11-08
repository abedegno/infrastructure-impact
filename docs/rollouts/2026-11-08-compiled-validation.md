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
