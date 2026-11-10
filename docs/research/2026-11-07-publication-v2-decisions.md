# Publication v2 implementation decisions

These decisions were made while the maintainer requested autonomous continuation.
They apply to the opt-in local format. They authorize no merge, hosted activation,
source acquisition, credential use, scheduling or permission change. The
[design](../superpowers/specs/2026-11-07-publication-v2-design.md) and
[plan](../superpowers/plans/2026-11-07-publication-v2.md) describe the interfaces and
acceptance gates. Test and replay acceptance must be reported separately.

| Decision, in execution order | Reason | Cost if wrong |
| --- | --- | --- |
| Proceed with the written v2 design without another approval question; retain v1 defaults. | The maintainer explicitly requested autonomous work, and measured v1 output exceeded fixed limits. | Rework of the opt-in format; no hosted side effect. |
| Reuse ordinary v1 bootstrap, cohort, change and current-evidence parts under an explicitly v2 index. | Preserve existing non-study views and avoid rewriting stable delivery paths. | Additional physical site bytes, originally estimated at 100–200 MB; the complete site must still pass the unchanged 1 GB gate. |
| Run the Python and browser owners in parallel after committing the shared wire contract. | Their file ownership is separate and the producer contract is fixed first. | Cross-owner checks must wait for a coordinated code freeze to avoid testing mismatched assets. |
| Inject an ordinary-cohort reader into the standalone browser codec through `createStaticDelivery`. | The facade owns ordinary index descriptors; the catalog-only codec cannot discover that authority. | Standalone cohort callers must supply the capability. Its absence rejects before I/O; it cannot trigger a whole-root fallback. |
| Omit redundant per-claim range catalog entries and use normalized claim routes. | The duplicate metadata would add about 18 MB to default reads. Routes already carry identities, boundaries and logical lengths. | Membership and node boundaries need explicit validation. Content-addressed pages, root hashes, complete semantic validation and native full-root parity remain mandatory. |
| Defer cross-owner/package execution to one combined integration after both owners stop editing. | Packaging mutable browser bytes would produce misleading receipts and repeated builds. | Installed-layout defects may be found later; acceptance remains blocked until the combined checks execute successfully. |
| Use a conservative intermediate budget for ordinary browser cohort parts. | Charge shared envelopes and rows before decoding and retaining them. | A final deduplicated selection below 128 MB can still reject. The failure stays visible; complete logical roots remain available through streaming export. |
| Correct the final retained-page identity regression locally instead of pausing for another approval. | The maintainer requested autonomous continuation, and a known availability defect cannot be treated as acceptance. Keep the correction restricted to identity projection and its regressions. | One additional bounded corrective iteration; no merge, deployment or wider feature scope. |

Native reducer construction also reserves intermediate containers before growth; its allowance can reject below final JSON-only capacity. Exact final response sizing is checked separately, and retained-scale fit still requires the acceptance gate.

After the maintainer's course correction, the opt-in v2 default-download ceiling
is 32 MB rather than 20 MB. The retained generation already fits the 1 GB Pages
site limit (437,319,066 bytes); its measured browser default download is
24,642,098 bytes. The 20 MB ceiling was our operational target, not a GitHub
requirement. Further table-layout/compression work is deferred in favor of import
correctness and useful comparison data. V1 retains its 20 MB ceiling. Archive,
part, index, materialization and complete-site limits remain unchanged.

Reducer working data has a separate 512 MB logical-byte ceiling. Retained-scale queries
exceeded 128 MB of intermediate projections while producing a small summary;
using the response ceiling for both rejected a valid query. Individual values
and returned responses retain the 128 MB limit. Working-data charges still
precede allocation, and smaller caller-supplied working limits are enforced.

The browser's default selection hydrates the existing published comparison
instead of recalculating all 91,393 claims. Its complete selected JSON and
4,942-byte CSV matched the Python reader on the retained diagnostic generation.
The KEV evaluation clock is still refreshed; custom selections retain the claim
reducer. Retained-scale detail paging and custom selections can exceed the
five-minute deadline and remain performance limitations. The timeout was not
raised, and these failures are not reported as browser acceptance.

The first retained replay timed out after 2,400 seconds and is not accepted.
The runtime correction reuses the producer's database query for cohort reporting
and composes validation of unchanged evidence, while retaining a fresh independent
native query and full-root parity checks. A new replay must pass independently;
the old failed result is preserved.

No decision permits dropping facts, declaring missing coverage complete, ranking
vendor security by disclosure counts, or alleging concealed fixes.

## Optional published-row Source membership

New v2 publications can include the generic logical root
`switching-row-sources.json`, validated by `switching-row-sources-v1.json`.
It binds the three canonical `os_family` / `all` vendor rows to their original
snapshot ordinals and row hashes, their sorted unique claim/event membership
SHA-256, and increasing ordinals into the existing global Sources array. Source
identity retains all four fields and the native canonical order; no Source array,
catalog field or envelope kind is added. The root is excluded from the ordinary
snapshot, runtime bootstrap and snapshot archive.

Fresh publication validation derives membership from complete evidence through
the existing nested Source collector. Independent native certification derives
it again, retains complete root/detail/evidence and custom model-query checks,
and compares each vendor's complete summary JSON and CSV to native rows and
Sources. The extra vendor expectations reuse the already validated OS-family
summary; they do not repeat the full comparison proof or its source guards.

The Python and browser readers use the index for canonical options selecting a
registered vendor (or null/default vendor), omitted/exact `os_family` scope,
omitted/exact `all` window and omitted/null CVE selection. They hydrate the seven
row detail fields at the original snapshot ordinal, refresh KEV evaluation, and
rebuild the actual v1 summary selection metadata. Source detail chunks intersecting
the selected ordinal set load once, and only selected Sources are materialized.
Claims and the full reducer remain necessary for other requests, including empty
CVE lists. Existing Python validation and the browser's ignored-key behavior stay
unchanged; explicit null scope/window use their established language paths.

An absent optional root preserves the old artifact path. If Source detail indexes
are absent, present row metadata and selected membership are authenticated before
using the complete reducer. A present corrupt root, row binding, ordinal list or
consumed Source chunk rejects; corruption never becomes missing provenance.
The producer omits this optimization only when its measured compact UTF-8 logical
document exceeds 8,000,000 bytes. Structural or provenance errors always reject.
Readers enforce that cap before materialization, and caller limits can only lower
it. Existing response, working, cache, page and deadline limits remain in force.
Old catalog readers can ignore this generic root; old native verifiers that require
the former exact root set need the corresponding verifier update.
