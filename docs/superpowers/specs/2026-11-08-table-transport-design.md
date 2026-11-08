# Bounded compressed table transport

The maintainer asked to reduce the rejected candidate's payload while preserving
limits and validation, and opted out of further routine design questions.
Hosted run 42530463587 confirmed default transfer overflow at 32,000,001 bytes
(limit 32,000,000), reading a v2 part after successful audit/native parity.
All 174 imports used cached bytes with zero HTTP requests. A saved public sample
uses 18,770,398 bytes for global tables; deterministic gzip reduces that to
4,239,922 bytes. Its monitor makes only 9,273 duplicate bytes of requests.

## Approaches and decision

Extra caching cannot remove this volume. Lazy table lookup would require changing
whole-page/table validation. Choose optional gzip table sidecars: retain every
existing validation and raw asset while reducing transferred bytes. This is the
implementer's choice under the autonomous instruction, not a separately approved
hosted activation. No schedules, permissions, pins or accepted generations change.

## Contract

`publication-v2.json` gains optional `table_transports`: a map from an existing
strings/shapes part path to a compressed descriptor `{path,sha256,bytes}`. Gzip
paths are `data/v2/<compressed-sha256>.json.gz`; descriptors are closed, positive
safe integer size <= 8,000,000 and content addressed. Keys must be existing table
parts, never roots/tokens/other assets. Distinct compressed paths are required.
Only emit a sidecar if smaller than its original. gzip uses filename="", mtime=0.
The original descriptor, bytes, canonical identities, tables and raw files remain.
Catalog without the optional map remains fully supported. Snapshot archives keep
raw, self-contained assets and their existing scope.

Export stdlib codec helpers `validate_table_transports(catalog)` and
`decode_table_transport(raw, compressed, decoded)`. The former returns the
validated optional map; the latter checks encoded length/hash, bounded gzip
expansion (decoded.bytes + one overflow sentinel), exact decoded length/hash.
Malformed/truncated gzip and overflow fail closed. Both descriptors remain bounded
by 8 MB. A nonempty validated transport map also caps the combined advertised raw
strings and shapes table bytes at the existing 128,000,000-byte selected limit,
before any table fetch or parse. Count every descriptor occurrence, including
unmapped raw parts and repeated paths. Empty/absent maps retain legacy behavior.
This is an advertised-byte bound, not an exact RSS ceiling for retained tables
and their indexes. Physical inspection verifies every declared compressed part
against its original and rejects unbound gzip assets.

The standalone monitor uses declared transport when fetching tables, binds both
descriptors to manifest hashes, counts compressed bytes against unchanged network
limits, decodes within the original size bound, and retains existing envelope,
generation, strict JSON, whole-table, token, routing, count and range checks.
The browser similarly checks both descriptors/hashes and bounds, retaining current
request concurrency, cancellation/deadlines, cache bytes, logical/stream limits.
If DecompressionStream is unavailable it uses the existing raw asset. Declared
transport failures do not trigger an integrity-bypassing fallback.

## Verification

Test legacy catalogs, deterministic compression and unchanged logical hashes,
invalid mapping/path/hash/size, corrupted/truncated gzip, decompression overflow,
manifest binding, reduced actual transfer, browser fallback/cancellation and full
existing reader/monitor contracts. Then run the full suite, installed wheel,
JavaScript suites, independent review and a cached nonpublishing hosted attempt.
A complete hosted pass is still required; no source activation is implied.
