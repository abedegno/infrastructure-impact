# Precomputed analysis: disabled public-data prototype

The final paired Node test supports continuing with precomputed common selections.
Cold Cisco 2025 loading fell from 70.50 to 9.27 seconds,
and the same-selection repeat fell from 10.71
to 0.27 seconds. JSON and both CSV exports
matched. This is a disabled local prototype, not a deployed performance guarantee.

## Source and measurement method

The pinned public generation is `e05fc9e8e5ce404190173f4c3c037498`, generated
`2026-11-26T08:22:06.194317+00:00`. Existing retained public projection parts were verified
against their descriptor lengths and SHA-256 values. No new vendor collection or
private evidence was used. Baseline web assets were pinned to main `26ccaef`;
final reader code was `4ff6327`. The full record/evidence writer gate and native
verification ran on the unchanged wire format; final reader assets were refreshed.

Two fresh Node `v22.23.1` processes on `darwin` ran sequentially with
no competing heavy local test or publication jobs. Both received the same accepted
contexts: Cisco/2025, its exact repeat, Aruba/all, Arista/all, All/all. Only the
first Cisco call is cold for the existing full-source reader; later distinct
precomputed views must load and validate their own payloads. Both readers retain
only the cache policy they implement. JSON/CSV fingerprint work was outside timed
loading. Repeat CSV hashes were reused only after identical JSON bytes established
identical input to the unchanged deterministic exporters.

This is one local pair, not a browser or WAN test. The older approximately
49-second historical baseline is not the denominator: the fresh control in this
run was 70.50 seconds. Absolute timings vary. Aggregate CPU includes
worker threads and can exceed wall time. The receipt records the exact catalog,
loaded asset and context fingerprints.

| Measurement                                     | Existing full source |   Precomputed |
| ----------------------------------------------- | -------------------: | ------------: |
| Cold Cisco 2025, seconds                        |                70.50 |          9.27 |
| Same-selection repeat, seconds                  |               10.708 |         0.270 |
| Cold aggregate CPU, seconds                     |                70.23 |          9.80 |
| Cold response bytes                             |           35,301,697 |    11,422,166 |
| Cold requests                                   |                  192 |            26 |
| Cold peak RSS, bytes                            |        1,514,487,808 | 1,129,234,432 |
| Whole-process peak RSS including exports, bytes |        2,675,703,808 | 2,733,113,344 |

| Follow-up distinct selection | Existing, seconds | Precomputed, seconds |
| ---------------------------- | ----------------: | -------------------: |
| aruba-all                    |             2.105 |                0.342 |
| arista-all                   |             1.876 |                0.145 |
| all-all                      |            14.945 |               10.843 |

Across the four unique selections, reader traffic was 35,301,697
versus 26,328,077 bytes. Eligible reads loaded the manifest sidecar
and independent gzip parts without global string/shape tables. Each physical
part remains bounded by 8 MB, decoded slices by 4 MB and the whole selected report
by 128 MB. The raw cache remains 16 MB; only one prepared view is retained.

## Correctness and publication proof

All four unique selected JSON downloads and both CSVs matched the normal browser
selector exactly; the repeat JSON matched too. Four native reads reproduced their
original native JSON byte for byte without loading global dictionaries. Browser
normalization changes only outer facts-map insertion order to the established
browser download order; native and inner fact ordering stay intact.

The fresh public writer passed its record/evidence authority gate in
403.46 seconds.
Independent native projection verification passed in
482.08 seconds. All
1,593 legacy root descriptors stayed unchanged. Final reader
validation and the asset manifest were replayed after the review fixes.

The current generated preview contains 12,620 files totaling
913,449,110 bytes, leaving 86,550,890 bytes under
the unchanged 1,000,000,000-byte site guard. Its current archive has
236 unique referenced paths totaling
132,491,725 bytes **within**, not in
addition to, that site total; 233 members are
shared with ordinary publication assets. No historical-generation directories
were copied. Aggregate hosted and retained-history capacity remains unverified
because accepted-artifact extra files were not inventoried. The four explicit
pilot views do not certify the default eight-view set.

## Limits and next gate

Cold-load peak RSS improved in this pair, but whole-process peak RSS including
exports was slightly higher. The earlier feasibility pair also increased that
whole-process peak by more. Treat memory as unresolved rather than claiming an
overall reduction; retained graphs, exported strings and GC affect the result.
Use a real browser and an explicit hosted view profile before activation.

Old publications, unsupported filters and explicit CVE subsets retain the compiled
selector. An advertised eligible view with corrupt data fails closed. Independent
native regeneration remains the source-authority gate; a self-consistent hash is
insufficient. No budgets, dependencies, advisory schema, source membership,
scientific counts, upgrade walks, schedules, permissions or secrets changed.

The [operator guide](../ANALYSIS_PRECOMPUTED.md) documents the disabled Python
writer flag and verification. The [reproducible harness](../../checks/benchmark_analysis_delivery.cjs)
takes web assets, a verified v2 directory, variant, a new receipt path, contexts,
and an optional local fallback directory for the clearly nonactivatable candidate.
The complete preview needs no fallback directory. It refuses writes into input
trees and checks catalog identity before measuring.

The [public study contexts](2026-11-26-precomputed-analysis-contexts.json) are
the exact 65,895-byte benchmark input. Verify their SHA-256 against the receipt
before replaying the pair. Keep the Cisco warm entry in its original position
immediately after the first Cisco request.

```sh
CONTEXTS=docs/research/2026-11-26-precomputed-analysis-contexts.json
shasum -a 256 "$CONTEXTS"
# Expected: 9e1e5eb5b4e0b18b6164dfa51da3fb2a2cc49d9ee386aa2b6414ea1bcb40286f
node checks/benchmark_analysis_delivery.cjs "$WEB_DIR" "$V2_DIR" "$VARIANT" "$RECEIPT" "$CONTEXTS"
```

The [receipt](2026-11-26-precomputed-analysis-preview.json) retains exact outputs
and measurements. Independent human evidence review remains pending. The existing
caveat remains: counts describe disclosure and collection, not vendor quality;
missing reliability denominators remain unknown.
