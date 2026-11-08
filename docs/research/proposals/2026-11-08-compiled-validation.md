# Proposal: compiled switching schema validation

**Approved by the maintainer on 8 November 2026.** The reviewed patch is now
implemented on PR #44, with dependency lockfiles updated. This document retains
the approved design and isolated benchmark; full application and hosted
verification are separate release gates.

## Approved change

The application pins **`jsonschema-rs==0.60.3`** and implements the fast
shape-validation path in the [historical approved patch](2026-11-08-compiled-validation.patch).
That patch is already applied; it is not an additional installation step. The
project retains its Python validator. `uv.lock` and `requirements.lock` include
the native package's distribution hashes.
The downloaded experimental wheel was approximately 5.3 MiB and declares MIT
licensing. Its documented API supports Draft 2020-12, custom format/keyword
checks and offline references:
[official package documentation](https://pypi.org/project/jsonschema-rs/0.60.3/).

## Evidence

The same sanitized public projection was reused and SHA-256 checked. The
365,068,886-byte evidence root has logical SHA-256
`d1913e0606706bb174d63d88b1633f6246e24855a5a3bf25402dc9f422989a16`.
The complete evidence **schema check**, including original custom format and
Python regex behavior, took **44.32 CPU seconds** with the existing validator
and **3.79 CPU seconds** with the proposed compiled backend (about 11.7 times
faster for that operation). This is not an application-wide or hosted speedup.
The original strict JSON/type checks and semantic validation were outside this
benchmark and remain required.

The isolated proposal passed 54 tests, including comparisons across all six
study schemas and mutated inputs, Unicode control-whitespace behavior, nested
format rejection with the original exception type, and refusal to retrieve an
unregistered schema from a local file. Independent review requested deeper
acceptance-parity tests: the final 54 also cover nested required/extra fields,
duplicates, numeric boundaries, conditional branches and same-object mutations.
This closes the identified test gap before implementation approval. One initial test fixture incorrectly
used a full comparison input as sharded metadata; it was corrected against the
existing metadata contract before the successful run.

## Boundaries preserved

- Run the existing strict Python JSON/type/nonfinite-number guard first.
- Compile the existing installed schemas and preserve the exact custom format
  callbacks. Override pattern checks with Python `re` to retain Unicode and
  control-whitespace semantics.
- Register installed schema URNs explicitly, deny other retrieval during registry
  construction, and set the native validator to offline mode.
- Keep the existing Python validator for rejected native shapes, preserving
  rejection exceptions and compatibility. Fresh semantic/provenance checks,
  identity fingerprints, native/static parity and capacity checks still run.
- Cache compiled schemas, never a prior input's validation result.

A native engine is a new runtime dependency. Lockfile hashes, wheel availability
for supported Python/platform targets, full tests and independent review must be
completed after approval. The corpus comparisons are meaningful evidence but
are not a proof of equivalence over every possible JSON instance.

## Release gate

Run the complete application suite, installed-package checks and platform CI,
then certify the complete hosted inventory using retained captures
and a recorded accepted checkpoint identity. Keep PR #44 draft until that
certification passes. No scheduling, hosted permission, source activation or
publication change is included in this approval request.
