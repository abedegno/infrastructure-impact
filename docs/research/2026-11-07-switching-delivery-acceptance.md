# Switching delivery repair — retained-evidence validation, 7 November 2026

This records a local laboratory run, not a hosted apply. The input is the pinned 223-identity public research stage, not the complete hosted inventory. No new vendor HTTP observations, original input writes, recovery promotion or publication were authorized.

## Why this change was needed

The earlier 174-document replay passed audit but failed when one switching summary exceeded the existing 8,000,000-byte part limit. Its 34,923 claim IDs also require at least 2,339,841 inline bytes, above the existing 2,000,000-byte index limit. Those are transport scaling failures, not evidence of vendor exposure or a measured complete archive-capacity failure.

The repair preserves small legacy formats. Large summaries use ordered, content-addressed string fragments bound to the original UTF-8 JSON byte count and hash. Large claim catalogs use bounded metadata parts; browser drilldown and full hydration resolve them lazily. The browser and standalone monitor validate both capabilities. No evidence, scope qualifier or identifier is removed. All existing part, index, default-monitor and expanded-archive limits remain in force.

## Software verification

403 affected Python tests (34 new), seven Node checks, Ruff/format/Prettier and a current wheel's byte identity, privacy inventory and isolated stdlib monitor smoke passed. An independent review found one malformed-Unicode byte-count issue; its correction passed 130 focused tests and a clean scoped review. These checks are separate from real-data acceptance.

## Real retained-evidence replay

**Outcome: failed / capacity_failed.** Database audit passed; candidate validation and capacity did not. Accepted staged-database and public-directory paths are null. The private diagnostic bundle exists, but is not an accepted publication.

| Measurement | Observed bytes | Existing bound |
| --- | ---: | ---: |
| Static index | 141,878 | 2,000,000 |
| Snapshot JSON | 129,569,637 | 128,000,000 |
| Snapshot gzip | 8,172,245 | 8,000,000 |
| Switching evidence JSON | 382,384,131 | 128,000,000 per artifact |
| Switching comparison JSON | 404,834,885 | 128,000,000 per artifact |
| Total generated public files | 1,589,739,285 | GitHub Pages published site: 1 GB |

The last bound is [GitHub's published-site limit](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits), rather than a new local monitor rule. The candidate's generic artifact-size inspection rejected the bundle; multiple artifacts exceed their bounds. Generation `c7e7d9f225204b3ebcf685388549078a`, manifest SHA-256 `3bd794b5109a590c77cf66a776e272bdee8e61e72239e570a32d1df4677361ef`.

The summary is 21,973,936 bytes in 43 fragments, and the external catalog uses 13 metadata parts for 91,393 distinct study claims. Those counts include the entire 223-identity local input, not just the 174 target documents. All individual static parts fit the unchanged part ceiling. The summary alone also exceeds the default monitor's 20,000,000-byte actual-read budget; a passing default-monitor result must not be inferred from a successful split build.

A separate diagnostic using the **generated browser assets** reconstructed that summary exactly equal to the snapshot summary. The generated delivery asset is byte-identical to reviewed commit `4670282`. This proves the repaired transport on the real output; it does not clear the rejected candidate or replace native/static CSV, default-monitor or archive-monitor acceptance. Those later candidate checks remain gated and unperformed.

All 174 targets replayed from 32,176,699 retained bytes, with zero vendor HTTP attempts, received bytes or new HTTP observations. Original input SHA-256 remained `a400c2268285ec69122ddcbf34494af321cd6135df68b0f5cb24a423a6cf3dca`; existing evidence/history, unrelated rows and all 174 capture dates were preserved. Revisions changed 223 to 397, exact-target cache rows 242 to 416, and one operation-owned pipeline row was added and marked error after rejection. Original evidence/observation counts stayed unchanged.

Measured worker phases were query 157.368924 s, query 221.380387 s, projection 656.498266 s and writing 278.610810 s. No timeout expansion or repeated replay was used.

A read-only diagnostic ruled out a simple bundle-join duplication bug: grouping all claim fields except bundle and claim ID still produced 91,393 distinct groups. No claims were collapsed. Snapshot records contribute 98,650,994 bytes and the comparison summary 21,973,935 bytes. These results call for a bounded representation/export design, not a limit increase or deletion of distinct statements.

The replay substitutes only the acquisition boundary with pinned retained bytes. Actual preview binding, isolated staging, audit, publication, candidate inspection, monitors and native/public parity code run normally. A browser-only review correction finished before publication asset writing; Python publisher, schemas and normalizers were unchanged during the run. The output manifest and regenerated bundle must bind the final browser bytes.

## Remaining limits

This run cannot establish the complete hosted union's capacity, full historical vendor coverage, model applicability or comparative security quality. Source errors and pending human review remain visible. Counts describe retained disclosure evidence; higher counts can reflect more scrutiny or more complete collection. Neither vendor concealment nor equivalence follows from this work. Hosted inventory validation, release/pin activation and publication remain separate operational steps.

## Additional guard after this replay

A subsequent focused change enforces a conservative 1,000,000,000-byte aggregate
Pages site bound in candidate inspection. Exactly 1 GB and one byte over were
tested using eight sparse assets, all individually below 128 MB: the boundary
passed and the overflow failed with retained measurements. All 45 candidate tests
passed and the change received a clean independent review. A read-only probe of
the existing diagnostic bundle rejected it immediately as `public site size`,
retaining the same expanded/compressed/public sizes. This was not another stage
run and does not clear any acceptance gate.
