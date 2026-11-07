# Targeted refresh/current evidence acceptance — 6 November 2026

Status: implementation acceptance and all seven task reviews complete; whole-branch findings resolved and scoped re-review clean on 7 November 2026.
Independent human source/extraction review remains incomplete. No release,
runtime activation, hosted preview/apply or dispatch is included.

## Authorized public input and source result

The sole input was the earlier explicitly public-only Arista preview checkpoint:
6,586,368 bytes, zero-byte WAL, SHA-256
`609109890fc7e962eaf67a45644be92b61847eec45d4de622bd00cf764058e62`.
It was copied into separate disposable public-only stages; the input was unchanged.
No native/private/customer vault, recovery material or operator source config was
used. Raw captures, complete row ledgers, databases and operational receipts stay
outside Git and public output.

The input already held the corrected HTML primaries and selected-source facts.
New code therefore partitioned it **before apply** into 11 current, one excluded
retained, and 12 total latest identities. Apply kept those counts. This acceptance
does not credit apply for an exclusion already established by new policy over
preexisting evidence.

The exact three-URL profile made real public HTTP requests to both registered
HTML primaries and the reviewed CSAF alternate; all returned 200. Exact URLs,
new primary hashes, capture/normalization times and the unchanged CSAF hash are
recorded in the [rollout proposal](../rollouts/2026-11-06-arista-targeted-refresh-proposal.md#current-implementation-acceptance--6-november-2026).
The core result was `completed`, two imports and the expected alternate scope
conflict. SA-0099 contains CVE-2024-27890/27892 with six/eight literal expressions;
SA-0103 HTML contains CVE-2024-6858 with four. The exact old CSAF identity remains
CVE-2023-5501, excluded from current records and labelled in retained exports.

All 17 original evidence rows and 13 original revision rows retained their full
row hashes, including original observation/normalization times. Two new HTML
captures and two new normalization revisions were appended (19/15 total).
The unchanged CSAF preserved its original 13:12:43 capture time while recording a
separate 23:15:25 HTTP-200 recheck. Repeating identical captured bytes with the
same installed code completed with zero imports/two unchanged and no revision
append. A separate retained-source replay used the earlier 18:55 HTML captures,
performed no HTTP, preserved capture times, completed, and also repeated without
revision append. Replay is reinterpretation, never fresh retrieval.

Native/static current-evidence and retained API responses agree for default,
explicit JSON/CSV and both relevant CVE filters. Current assessment JSON and CSV
exclude the exact old CSAF identity; labelled retained exports preserve it.
The complete public snapshot retains its labelled wrapper for audit. The tiny
public stage lacks the production default benchmark CVEs: its default-cohort
health check correctly fails `Empty public dataset`; this is not a hosted
publication-health claim. Synthetic publications with an explicit present cohort
exercise the actual checker over localhost HTTP, including successful accepted
generations and incomplete candidates.

## Verification ledger

Execution uses Python 3.13.14, clean Python 3.11.15, Node 22.23.1 and pinned
uv 0.11.21. Full command/result and artifact manifests are retained in the local
acceptance packet, including every complete old row, preview/apply/repeat
receipts, source observation status/time, exact capture hashes and wheel/source
file hashes. No real captures are committed as synthetic fixtures.

- Monitor RED: removing the required disposition asset, report union/generation,
  retained target/membership and capability checks exposed missing gates. Later
  RED proved a declared missing index could silently fall back; corrected code
  rejects it. A genuine legacy fixture now removes the index manifest entry.
  Full-snapshot RED also caught overlap and retained privacy gaps. The standalone
  schema validator now enforces exactly one typed `oneOf` branch, including
  rejection of overlapping alternatives and boolean-as-integer values.
- Initial Task7 monitor suites: 158 passed. Checks use actual HTTP, fingerprinted assets,
  schema and identity validation; no application/jsonschema imports in `-S`
  standalone execution. The previously accepted generation stays byte-identical
  after a rejected candidate; the checker itself has no rollback action.
- Full Python 3.13 suite: 2,901 passed, 12 subtests passed (254 seconds), followed
  by preliminary matrix and final frozen functional verification below.
- Installed wheel plus separate external vendor: passed, including the optional
  absent current-policy hook, count union, schemas, scripts, static capability,
  OpenAPI and native GET/HEAD/405 behavior.

Initial Task7 functional inputs have canonical manifest SHA-256
`4d3ba0886b11851b26be7283a169e6b5ed1fa5fe7da78fd2d6fa0a62ca0f8aef`
(416 package/check/test/workflow/build-input files), on parent
`e5614e0ce3b953ff3791a81e175c6cc6c608f7ec`. All exact CI Ruff check/format command
sets, seven standalone Node suites, locked Prettier3.9.10, both pinned-uv frozen
relative-output dependency exports and generated browser-contract byte parity
passed. The clean public source/privacy export contains 564 allowlisted files.
A clean Gitless Python3.11 environment explicitly passed all 37 portable protocol
cases (two optional Git-package cases deselected in that focused check).

The installed wheel is 620,125 bytes/247 entries, SHA-256
`7145a35b5cb0deabe94c1b6fee4b4bdeecd3a78d5669218eebc464fd4d52662e`,
including LICENSE, NOTICE and THIRD_PARTY plus all new resources. Docker build,
plugin execution and Compose config validation passed from a clean allowlisted
context. All 249 container/package inputs are identical to the final functional
source. Image identity:
`sha256:60643acf1b1a427d9fd33c8ffe071a0cdced24a3a81adbe23f2c55dc2f4e2340`,
user10001:10001. No service or deployment was started.

Actual comparison against base `a9014f0` covers59 existing resource/schema files:
57 are byte-identical; OpenAPI and static-index have their intended extensions.
All frozen study/review definitions, advisory-v2 and default-source resources
remain equal. All nine builtin normalizer fingerprints changed because the
shared plugin contract is a declared dependency; this is not zero-churn or a
claim that nine parsers changed. Arista is now `85c124006aa0bde2` (base
`f0c275e7d65c6fc4`); its separate policy fingerprint is
`0eeb34d6e10995f4125b5811dbc3888af632055d83d153c7823c550f43515b55`.

| Representative local publication asset | Bytes |
| --- | ---: |
| Full snapshot / compressed snapshot | 8,533,398 / 808,885 |
| Current assessment CSV | 4,038,453 |
| Static index / decision report | 335,303 / 2,460 |
| Largest data part | 2,992,096 |

These measurements fit the unchanged delivery limits and describe this small
public-only stage, not production capacity.

Initial Task7 frozen full matrix: Python3.13 **2,905 passed, 12 subtests passed**
(259.90 seconds); clean Gitless Python3.11 **2,902 passed, 3 skipped, 12 subtests
passed** (246.94 seconds). Skips are the original Git-only checked-in source
parity test and the two optional original-package compatibility tests; all 37
mandatory portable protocol cases pass, and both optional package cases run in
the Git-backed3.13 suite. These receipts precede the scoped publication-clock
review correction below; they are retained as earlier verification evidence.

## Publication-clock review correction

Fresh task review found that payload and envelope publication clocks were each
internally consistent but lacked a link: a fresh bootstrap/report payload could
coexist with a stale index and stale part envelopes. The checker now compares the
bootstrap payload publication identity and `generated_at` directly with the index
immediately after reading it. Report payloads continue to bind to bootstrap;
part envelopes bind to index. This concerns publication time only; retained
capture/retrieval and publisher dates remain independent. Genuine no-index
compatibility is unchanged.

A real localhost HTTP regression rewrites every content-addressed part envelope
and its descriptor/hash to the stale index time while preserving fresh,
consistent bootstrap/report payloads. It first failed because the old checker
accepted the mixed clocks; the corrected checker rejects it immediately. All
four monitor suites now pass **159 tests**, including standalone no-site-packages
and exactly-one typed-schema cases. Exact CI Ruff/Node/Prettier commands, generated
contracts and both frozen dependency exports pass again.

The corrected 416-file functional inventory has canonical SHA-256
`c74c1e528dba2a72d07b16947b32e6c45ccc6a1f9b7b66cc02d0527ce134c677`,
on parent `4a048036a6d22b767160c81061ef27c7433f3be5`. This inventory is distinct
from the full 564-file allowlisted source export, which also includes documentation.
Only the checker and regression test changed functionally. All 249 wheel/container
build inputs match the previously verified artifacts, so their successful probes
and image are reused. The exact core/profile/policy/normalizer code is unchanged;
original live/replay source acceptance above remains earlier evidence, and no
new retrieval or apply is claimed. A clean public-source/privacy export passed
again. Final corrected-code matrix: **Python 3.13: 2,906 passed, 12 subtests
passed** (295.47 seconds); **clean Gitless Python 3.11: 2,903 passed, 3 skipped,
12 subtests passed** (284.91 seconds). The three skips remain exactly the original
Git-only source parity case and the two optional original-package cases. All
mandatory portable cases pass, and the Git-backed 3.13 suite executes both
optional original-package cases. This is the Task7 corrected functional verification;
the final whole-branch fix verification below supersedes it.

## Limits and rollout decisions

Synthetic integration and local public-source acceptance establish bounded
behavior, preservation and packaging, not full vendor coverage, fair comparative
rates, independent human review, publisher disclosure/fix timing or hosted cleanup.
The default monitor keeps its 20 MB budget and only hydrates normal current cohort
records; it verifies the global count union and every excluded fragment rather
than downloading the entire current catalogue. Part/index/report/request limits,
frozen study/review inputs, advisory v2, default sources, schedules, permissions,
recovery backends/keys, capacity, dependencies, version and runtime pin remain
unchanged. The declared old-helper protocol bridge preserves ordinary operation
at the existing pin and does not make semantic downgrade safe after activation.

The controller retains the approved historical plan and owns fresh task review,
whole-branch review, any completion ticks and the separately authorized push/PR.
Source merge/release, runtime activation, hosted preview and one fingerprint-bound
application remain separate decisions. No local fingerprint authorizes hosted
apply, and no read-only health check performs automatic Pages rollback.


## Final whole-branch verification — 7 November 2026

Whole-branch review found three issues: current filtering removed safe historical
CVSS, native readers accepted missing or mixed decision metadata, and monitor
version checks accepted booleans rejected by the browser. Commit `043d32c`
fixes all three. A single scoped re-review confirmed each addressed with no new
breakage. Historical score enrichment remains source-bound and separate from
current severity; invalid native candidates return 503 without replacing the
accepted cache or changing the publication pointer. Root report versions and
published counts are independently type-checked.

Final functional manifest: **416 files**, SHA-256
`2c9e537e6431fba6fbdd8cca4a74f9f2875f5505b215be6ab3a34debcd82ec8f`.
Python 3.13: **2,966 passed, 12 subtests passed** (397.54 seconds).
Clean Gitless Python 3.11: **2,963 passed, 3 expected Git-dependent skips,
12 subtests passed** (373.68 seconds). Exact CI lint/format, seven Node suites,
locked Prettier, frozen exports, generated-contract parity, clean source/privacy
export and installed-wheel/external-plugin checks pass.

The rebuilt wheel is 621,111 bytes/247 entries, SHA-256
`6caffa225e48a5e434d180a82e42ba57347c331562d2f88a5dd4d65ef0ad8e69`.
Final clean-source Docker image:
`sha256:c7176da80048f552b6199c3363e750c9d276c59c34d5a992e9cfc3b969de0668`.
Build, image inspection and Compose validation pass. A local Docker client
stalled before process start; direct start of its already-created test container
executed the final image's plugin command successfully (all nine plugins,
exit zero). The original retry client encountered an auto-removal race. Only
task-owned clients/containers were cleaned; no service reset or deployment occurred.

Both public stages were rebuilt from fresh copies without HTTP, apply or replay.
All old row hashes and source timestamps remain unchanged. Both retain historical
CVSS 3.1=6.5 on revision10, remain 11 current/1 excluded/12 total, and pass all
12 native/static comparisons plus full/gzip archive checks. Their default-cohort
health still fails `Empty public dataset`. The original 6 November source capture
and retrieval times above remain the acquisition evidence; these 7 November
builds do not claim fresh retrieval or production coverage.
