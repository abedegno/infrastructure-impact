# Bounded range hashing — 8 November 2026

The full hosted retry remains rejected by its 2,400-second worker budget.
This change targets measured hashing overhead without removing validation or
claiming that the complete pipeline is fixed.

## Cause and change

Writer and verifier updated SHA-256 for tiny JSON fragments and repeated that
work for every active enclosing range. The reader regression reproduced 60,032
real `hash.update` calls for approximately 230 KB of data. The writer reproduced
40,019 calls on a similar input.

Both now collect at most 64 KiB of canonical bytes and flush before changing
range membership, at the buffer boundary, and before final digest comparison.
The writer has a separately bounded ASCII buffer for its legacy snapshot hash.
Large fragments are hashed directly without a buffer copy. Byte limits still
run before emission. The reader uses absolute start offsets and a stack of
minimum enclosing end offsets to enforce every ancestor's declared size.

The existing native/static checks, physical hash binding, range membership,
number/Unicode behavior, declared lengths, EOF and capacity gates remain.
No validated-input result is cached or reused across invocations.

## Fixed-input measurements

[Machine-readable measurements](2026-11-08-range-hashing-measurements.json)
record the public projection/checkpoint/catalog identities. Before and after
used fresh processes and the same frozen public data, with only the relevant
method replaced by its prior implementation for the baseline.

| Operation on the 365,068,886-byte evidence root | Before CPU seconds | After CPU seconds |
| --- | ---: | ---: |
| Reader verification | 62.98 | 55.93 |
| Writer root generation | 50.49 | 47.14 |

The reader consumed the identical logical byte count and SHA-256. The writer
produced the same 368 physical files with identical content/inventory hashes.
These modest component improvements do not establish a hosted acceptance result
or an application-wide speedup.

## Verification and next gate

The update-count regressions failed before implementation. Focused publication,
codec, reader and Unicode tests passed (192 tests at that checkpoint); the final
eight hashing-specific tests passed, including corrupted child digests/lengths,
token boundaries, a large-literal buffer guard and parent overflow before
emission. Independent static review found no critical or important findings.
Ruff, formatting and whitespace checks passed. The complete application suite
passed **3,757 tests and 12 subtests in 432.73 seconds**. The application has no
compiled-validator dependency; its separate proposal tests ran only in an
isolated process. Hosted certification remains unproven and PR checks are a
separate gate.

The next larger opportunity is schema-validation CPU cost. A separately tested
[compiled-validator proposal](proposals/2026-11-08-compiled-validation.md) is
pending maintainer approval because it adds a native dependency. It is not
installed in the application environment and no application validation backend
was changed. PR #44 stays draft until complete hosted certification passes.
