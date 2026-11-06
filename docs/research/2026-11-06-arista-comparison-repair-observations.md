# Arista attribution and comparison repair observations — 2026-11-06

These unreleased repairs correct two source-attribution defects and reduce
repeated work in the existing switching comparison. They do not establish a
vendor-wide disclosure denominator, installed exposure or patch burden. The
[original public research follow-up](https://github.com/abedegno/infrastructure-impact/pull/29)
remains unmerged. Independent human impact review remains pending.

## Retained-source replay

Three original public captures were replayed offline into a separate copy of the
public backfill. No network collection was involved. Original capture hashes,
the source research stage and read-only input hashes were preserved. Replay
processing timestamps do not establish historical availability. Raw captures,
scripts and receipts remain outside Git; the replay reconciliation report ID is
`2bed5c3f56faae3d3b0eabf47b94f3a7f543edd83930045cb64b790f7fb5926b`.

| Reviewed source | Corrected result |
| --- | --- |
| [SA-0099 HTML](https://www.arista.com/en/support/advisories-notices/security-advisory/19862-security-advisory-0099) | CVE-2024-27890 has six literal EOS expressions; CVE-2024-27892 has eight. Article-local CVE markers bind the groups separately. |
| [SA-0103 HTML](https://www.arista.com/en/support/advisories-notices/security-advisory/19917-security-advisory-0103) | CVE-2024-6858 has four literal EOS expressions. Both reviewed entry URLs selected the same retained HTML evidence. |
| [SA-0103 advertised CSAF](https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_103.json) | The retained CVE-2023-5501 scope disagrees. It remains literal alternate evidence, with an `unsupported_or_invalid_document` issue and partial primary selection. No CVE alias or remediation transfer is made. |

The parser requires the exact reviewed identities and local structure; unrelated
navigation, description and footer CVEs cannot supply tracking scope. Missing,
foreign, repeated or cross-heading group markers fail visibly. Platform and
configuration qualifications remain source context, without inferred hardware
applicability or fixes. The [representation guide](../SOURCE_SELECTION.md)
describes selection and collection-health behavior.

Older contradictory CSAF revisions remain retained under their original
identity. Direct normalization/replay of that exact route is rejected, and its
research hook emits no claims even from an older normalized revision. This is
not a purge of catalogue history. The reviewed bridge additions change shared
`adapters/switching.py`, so every built-in normalizer fingerprint changes under
the existing shared-source fingerprint policy. That churn is not hidden or
restricted artificially to Arista.

## Validation and bounded performance evidence

The Python implementation removes repeated shape walks, repeated source-row
construction and an extra complete copy. Each public selection still performs
fresh complete input shape and semantic validation. Within that same call,
canonical JSON bytes prove the actual returned inputs are unchanged, and all
remaining generated output fields receive schema checks. There is no identity
trust or global validation-success cache. Caller, sibling and publication objects
remain isolated, including when the caller supplied one shared publication
dictionary. Public signatures, schemas and the frozen study are unchanged.

Deterministic authored tests cover work counts, invalid nested values, mutation
after prior success and input/output isolation. A bounded reference differential
matched complete JSON values and CSV outputs for 18 views on each of authored
and corrected retained samples: 36 equal JSON/CSV pairs. Actual optimized outputs
also received full stock shape and fresh public semantic validation; accepted
and rejected outcomes agreed with the pre-change validator on the valid control
and 13 malformed or tampered controls. The subsequent publication-alias repair
passed its focused regression checks and scoped rereview.

A diagnostic cProfile sample containing 400 claims and 400 score rows measured
selection at 3.681 seconds before and 1.573 seconds with the guarded selection.
Profiling overhead applies; the latter included cold validator initialization.
These bounded observations do not predict full-corpus wall time or peak memory.
Canonical byte buffers and the output copy still consume memory. Operational
profiles and differential receipts remain outside Git.

## Complete-corpus acceptance and remaining limits

Complete-corpus export acceptance passed for 225 latest normalized identities,
91,396 research claims and 91,444 score-availability rows in this isolated public
stage. The matrix contains one all-vendor JSON/CSV pair for each of nine windows
(`all`, `pre`, `post` and 2021–2026) at both OS-family and model-qualified scopes:
18 pairs, with 54 vendor summary rows. JSON exports
use the existing `representation: "summary"` schema, backed by the hashed
`full-report.json` containing complete retained inputs. They are summary exports,
not standalone full reports for reselection.

The complete corrected report built in 125.364 seconds and passed fresh full
validation in 101.083 seconds. A serial validated checkpoint and the first
OS-family/all pair preceded three read-only operator workers with exclusive
assignments and a 1,200-second bound per attempt. Verified accepted pairs were
resumed in two-view batches to finish the remaining 17 views. Each attempt
checked the checkpoint and performed fresh full input/output validation; no API,
validation cache or product limit changed. Worker recorded-phase totals were
2,331.300, 2,455.210 and 2,042.094 seconds. These exclude inactive gaps and
interrupted unfinished phases; they are not wall times or a serial/parallel
performance factor.

The final merger accepted all 18 pairs after full shape/semantic validation,
summary-schema checks, CSV regeneration and export hash checks. Production code,
database and configuration hashes remained unchanged. Deterministic OS-family/all
and model-qualified/post repeats passed. KEV was available under the existing
policy. The outside-Git receipt SHA-256 is
`a67491f532fe0dff82a2915e3e2ab17fd7cfe704bf297d8b4b5528d9a33f9f3e`;
the full-report SHA-256 is
`8a6e52a94c7257793f2a56bed46585f888843c0f480519a3cf8acf400515cb14`.
The unchanged frozen-definition SHA-256 is
`5224471b014fccc278f985d08328926bac29ebc6bfb96d25f98972f91be6fd33`.
See the [operator acceptance procedure](../switching-comparison.md#corrected-source-comparison-acceptance).

The controller's full platform checks on final production code `6b43e54` passed:
Python 3.13 had 2,577 tests and 12 subtests pass in 154.94 seconds; the clean
Python 3.11 export had 2,576 tests and 12 subtests pass in 177.76 seconds, with
one existing Git-only skip. Both exact CI Ruff commands passed across 239 files,
including both new regression suites. The five Node checks and Prettier passed.
Clean-export privacy and authored-fixture checks passed; both frozen dependency
exports were byte-identical. The wheel contained the new Arista modules and
license files, and the offline installed wheel/plugin/resource probe passed.
These are automated controller-owned checks. The final code audit approved the
implementation with no findings; independent human impact review remains pending.

All three vendors have zero supported model-qualified CVEs in the all-window
selection of this bounded stage. That means no qualifying model observations,
not zero vulnerabilities or unaffected platforms. Coverage remains `partial`,
with `expected_advisories: null`. OS-family totals describe unequal bounded input
sets; they do not supply a fair vendor comparison. The customer's platform
comparison remains open pending model and coverage evidence.

Comparison windows use the vendor's initial publication day for latest retained
claims. This differs from the registry-publication discovery window and from a
CVE identifier's year. Restoring the CVE-2024 Arista records does not itself
establish a change after the 2026-04-07 cutoff or a Glasswing effect. The 2026
calendar window remains partial.

Unknown model applicability, unresolved product aliases, source-access and
historical-coverage gaps remain visible. A source or bounded traversal ending
does not establish complete vendor history. Named-model zero means no qualifying
observation, not no exposure. The 2026 window is partial; disclosure counts and
publisher remediation events are not actual upgrade counts. These results do
not establish equivalence, security ranking, concealment, silent fixes or a
Glasswing causal conclusion. No release, implementation merge or hosted
activation is claimed.
