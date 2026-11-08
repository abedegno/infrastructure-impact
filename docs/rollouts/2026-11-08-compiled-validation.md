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
