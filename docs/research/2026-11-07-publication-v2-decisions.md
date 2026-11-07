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

The first retained replay timed out after 2,400 seconds and is not accepted.
The runtime correction reuses the producer's database query for cohort reporting
and composes validation of unchanged evidence, while retaining a fresh independent
native query and full-root parity checks. A new replay must pass independently;
the old failed result is preserved.

No decision permits dropping facts, declaring missing coverage complete, ranking
vendor security by disclosure counts, or alleging concealed fixes.
