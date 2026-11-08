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

## Retained implementation checks

The measurements above describe the historical prototype. Following the
maintainer's course correction, further table-layout work was deferred. The local
v2 default-download safety ceiling is now 32 MB; v1 remains at 20 MB. These are
operational targets, separate from Pages' site-size limit. See the
[implementation decisions](2026-11-07-publication-v2-decisions.md).

The latest generated diagnostic tree measures **437,319,773 bytes**, with a
39,411,194-byte expanded archive and a 5,037,170-byte gzip. Its generation is
`dd37f363728b4faeaeb46373436c203e`. These are physical measurements of an
**unaccepted** candidate, not successful end-to-end validation or hosted capacity.

Three separate replay outcomes remain preserved outside Git:

- The initial implementation replay reached the 2,400-second worker timeout.
- The next replay reached complete native-root and impact-CSV comparison, then
  failed when intermediate reducer projections hit the 128 MB response limit.
  A separate 512 MB logical working-data allowance corrected that conflation;
  individual values and responses remain limited to 128 MB.
- The corrected-backend replay also timed out at 2,400 seconds. Its producer
  query/projection/write phases took 131.72/281.04/685.59 seconds; the independent
  native query/projection took 352.97/880.13 seconds. Root/query/monitor acceptance
  did not finish. Its receipt reports `worker_failed`, with acceptance flags
  unset. No result is promoted to a successful import.

All 174 retained targets were normalized in the disposable stages. The source
database was unchanged, existing rows/history and all 174 original capture dates
were preserved, and no HTTP attempts or new retrieval observations were made.
The local sample contains 223 identities; it is not the hosted union.

Separately, the default browser view transferred 24,642,098 bytes, and the Python
default monitor completed at 28,367,753 bytes against a preserved diagnostic
generation. The corrected default browser selection's complete JSON and
4,942-byte CSV matched the Python reference. The browser-only correction was
tested against those same retained facts; it is not included in the frozen
backend replay above. Large custom selections and source/diagnostic paging still
have measured five-minute deadline failures. Full browser acceptance remains
incomplete; the interactive timeout was not increased.

The final source commit's six GitHub checks passed. The final wheel independently
matched all 264 required package files and passed isolated installed-worker audit,
native parity and both monitors on synthetic evidence. Those checks establish
software/distribution correctness for their tested scope, not retained-scale
runtime acceptance. No merge, release, source-pin change or hosted activation
was performed.
