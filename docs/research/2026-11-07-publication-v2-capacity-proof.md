# Publication v2 capacity proof — 7 November 2026

This is an offline representation experiment, **not a working publication or accepted import**. It reused the failed local 223-identity diagnostic bundle; no source collection, database replay, recovery access or hosted change occurred.

The unchanged v1 format produced a 1.59 GB site, a 129.57 MB snapshot and oversized research JSON assets. The first all-facts v2 experiment preserved every value but failed the 8 MB compressed and 20 MB default-read limits. Its 13,828,808-byte gzip result remains a failed result.

The bounded variant preserves exactly the current mandatory snapshot's logical scope. The current publisher already stores full research inputs separately: it removes `switching_evidence` from the snapshot and uses the comparison summary. The variant retains every original snapshot field, including the complete summary/provenance. All additional research roots remain mandatory publication assets. No primary fact, claim, version expression, product ID, source locator or capture time was removed.

| Prototype measurement | Bytes | Existing limit |
| --- | ---: | ---: |
| Self-contained snapshot archive, expanded | 39,038,432 | 128,000,000 |
| Deterministic snapshot gzip | 5,079,707 | 8,000,000 |
| Complete proposed default read set | 19,162,427 | 20,000,000 |
| Complete prototype site | 265,582,883 | 1,000,000,000 |
| Largest data part | 512,113 | 8,000,000 |
| Publication index | 64,848 | 2,000,000 |

The archive alone restored the **exact original 129,569,637-byte snapshot**, SHA-256 `b206a4b3ec8ed6a9ad63ddc4d23fea5aad878a047f721f5eea30f061893c56d0`, without external fact references. All 251 logical JSON roots, 223 records and 91,393 distinct claims passed ordered round-trip checks; the 88,382,197-byte CSV remained identical. After verifying all claim ranges were contiguous, normalized routes recovered every original ID, start, end and decoded size while reducing routing bytes from 2,906,624 to 1,561,177.

Literal and object-key tables cannot reference other encoded objects. Bounded prefix pages preserve original ordering and distinguish absent fields from null. A 17.62 MB record still requires streaming across pages. A full logical legacy view must not be expanded into memory before checking its selected-materialization bound.

The prototype includes old browser assets and is deliberately non-deployable. Production numeric grammar, schemas, readers, bounded caches, streaming selectors and adversarial checks still need implementation. The default-read figure includes existing non-switching dependencies, but is a read-plan measurement, **not a successful monitor run**. Its headroom is 837,573 bytes; production assets and grammar changes must be remeasured. Native/Python/JavaScript parity, real monitors and a fresh completed candidate are still required.

The local input is not the complete hosted inventory. This experiment establishes neither hosted-union capacity nor source-history completeness, model applicability, vendor security quality or concealment. Independent human evidence review remains pending. GitHub's [published-site limit is 1 GB](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits); no hosting limit or permission was changed.
