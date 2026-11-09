# Native-query certification scaling

The customer comparison implementation is reviewed and CI-green at `5396b9c`, but full runner-state certification 42695025972 timed out in `publication.native_queries`. The sanitized receipt proves zero HTTP attempts/received bytes, all 174 imports reused retained bytes, and completed publication inspection/native-root binding. This follow-up fixes the measured verification bottleneck before the authorized merge/activation.

## Binding constraints

- Preserve independent native/public query inputs, all current comparison/source/identity/JSON/CSV/default/archive checks and every existing memory/byte/time limit. No timeout increase, smaller cohort, sampled parity or trusted boolean bypass.
- Public entry points keep fresh validation and output isolation. Internal composition may reuse an invocation-local validated capability or owned reducer state only when mutation/forgery rejection is demonstrably preserved.
- No original operator configuration, private vault/key or private worker logs. Only the sanitized certification result and designated accepted public publication may be used locally; all original state remains runner-only. No new source acquisition.
- No scheduler/permissions/recovery-format changes. Browser/customer API/data semantics stay unchanged; existing PR and exact-SHA certification gates remain.

## Tasks

1. Diagnose: inspect the actual two-scope native-query path, profile bounded synthetic/public inputs, identify repeated validation/canonicalization/materialization, and write the smallest safe design with tests and predicted savings. Read-only product tree.
2. Implement the diagnosed optimization with meaningful equivalence, mutation/forgery, construction/budget and native/public JSON/CSV parity regressions. Avoid repeated full-source operations without dropping proof obligations. Focused checks, package/privacy checks and one fresh code review.
3. Run required CI on the corrected commit and exactly one full-state certification. Then complete the existing authorized merge, bounded cached reparse, collection/publication and live verification. A failed gate requires diagnosis, not blind retries.

## Evidence

Sanitized result: `/tmp/impact-cert-result-42695025972/result.json`. Query ~95s; projection ~291s; writing ~452s; inspection ~20s; independent query ~98s/projection ~294s; native root binding ~595s; native-query phase then hit the overall 2400s worker timeout. Peak resident ~6.1GB. Acquisition is not the cause.

`publication_v2.native_parity()` verifies two scope summaries via reader.switching_selections and eager switching_comparison._select_summaries. The latter validates the complete comparison, serializes its inputs, fingerprints the whole report before/after each selection, deep-copies inputs and then drops them from summaries. Measure rather than assume which work dominates; root and publication phases remain required.
