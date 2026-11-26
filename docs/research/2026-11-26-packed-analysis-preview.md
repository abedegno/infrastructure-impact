# Packed analysis preview: correctness passed, activation not recommended

The lossless packed representation is correct, but this measurement does not
justify hosted activation. Cold loading remained about 49 seconds, reader traffic
rose about 76%, warm selections were slower, and whole-process peak memory rose.
Cold load peak memory fell about 10%. Keep the existing delivery path active.

## Pinned source and method

The public generation is `e05fc9e8e5ce404190173f4c3c037498`, generated
`2026-11-26T08:22:06.194317+00:00`. Its native compact analysis SHA-256 is
`da2bb0a09a58d1852b6b823a0a9f1a2188bd73a8ce5cffbb7f57d731d1b27ca1`. All cached source parts were checked against
publication descriptor lengths and SHA-256 values. The artifact ZIP download
failed; the preview instead used authenticated public Pages projection roots.
No private database, vault or new vendor collection was used.

The baseline assets were checked byte for byte against `26ccaef`; the packed
implementation was `facc846`. Each reader ran in its own fresh Node process,
sequentially, against cached local public parts. No native writer or heavy tests
ran during these measurements. Both processes used Node `v22.23.1` on
`darwin`, the same selection contexts, and the same JSON/CSV serializers.
The first call selected Cisco, OS-family scope, 2025; subsequent calls selected
Aruba, Arista and All, OS-family scope, all years.

This is one paired local measurement, not a browser, WAN or isolated CPU profile.
Export hashing was outside the timed selection phases; whole-process peak RSS
includes those exports. Small timing differences do not establish an improvement.

| Measurement                                     | Existing full root |   Packed root |
| ----------------------------------------------- | -----------------: | ------------: |
| Logical analysis bytes                          |        126,637,532 |    47,156,423 |
| Cold Cisco 2025 load, seconds                   |              48.65 |          48.5 |
| Reader response bytes                           |         35,301,697 |    62,031,773 |
| Reader requests                                 |                192 |           256 |
| Cold load peak RSS, bytes                       |      1,645,903,872 | 1,481,932,800 |
| Whole process peak RSS including exports, bytes |      2,353,577,984 | 2,463,940,608 |

| Warm selection | Existing, seconds | Packed, seconds |
| -------------- | ----------------: | --------------: |
| aruba-all      |              2.18 |            2.36 |
| arista-all     |              2.02 |            2.18 |
| all-all        |             14.11 |           15.20 |

Logical bytes describe decoded JSON. They do not describe the v2 transport,
which already factors strings and object layouts. The packed root adds another
encoding layer and still reconstructs and validates the full source. The smaller
logical value therefore did not yield a useful loading improvement.

## Correctness and complete preview

- Native packing and unpacking reproduced the complete source JSON byte for
  byte, preserving order and numeric spellings. Counts: 36,592 claims, 35,439
  members and 106,671 requirements. No years, trains or claims were removed.
- All four browser selections produced identical selected JSON, analysis CSV
  and upgrade CSV fingerprints across the two delivery paths. The JSON receipt
  below retains all twelve comparisons.
- A fresh complete native writer passed its public record/evidence authority
  gate in 256.43 seconds. Independent native projection verification passed in
  251.41 seconds. All 1,593 legacy root descriptors stayed identical.
- After refreshing the reviewed browser assets, all asset-manifest fingerprints
  matched. The preview contains 12,817 files totaling
  971,178,899 bytes. Headroom is
  28,821,101 bytes under the unchanged 1,000,000,000-byte
  site guard. Retaining both roots increases site storage.
- Source identity, limits, lexical validation, independent cancellation and retry
  regressions passed scoped review after one consolidated fix round. No hosted
  activation, permissions, schedule, secrets or collection settings changed.

## Reproduction and next work

The [measurement harness](../../checks/benchmark_analysis_delivery.cjs) takes a
web asset directory, a verified public v2 directory, a label, a new receipt path,
and a JSON map of accepted study contexts. Run each variant in a fresh process
with the same source generation and contexts. Its output is metadata and export
fingerprints. It refuses to overwrite a file or write into an input directory.

```sh
TZ=UTC node checks/benchmark_analysis_delivery.cjs WEB PUBLICATION LABEL NEW_RECEIPT CONTEXTS
```

The next loading experiment should avoid reconstructing the complete source for
common selections: publish independently verified precomputed selected reports,
retaining the full analysis for custom selections. Measure that separately before
activation. Do not relax validation or expand budgets to make this preview look
better.

The [receipt](2026-11-26-packed-analysis-preview.json) contains exact sizes,
phase timings and export hashes. The separate
[vendor evidence-request packet](2026-11-26-vendor-evidence-request.md) remains
ready for review; no vendors have been contacted. Reliability denominators remain
unknown where coverage is incomplete. Counts describe disclosure and collection,
not vendor security quality. Independent human evidence review remains pending.
