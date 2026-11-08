# Native query certification investigation — 8 November 2026

## Observed failure

[Hosted run 42503815667](https://github.com/abedegno/infrastructure-impact/actions/runs/42503815667)
restored the full accepted database, imported all 174 targets (32,176,699 bytes)
and passed its import audit. Candidate validation failed in
`publication.native_queries`. The worker returned normally after 2,368 seconds,
before its 2,400-second limit; peak resident memory was 5,868,761,088 bytes.
The old diagnostics did not retain the exception category, so the exact hosted
failure remains unproven. Accepted recovery, source pin and public data stayed
unchanged, as recorded in the [rollout](../rollouts/2026-11-08-candidate-certification.md).

## Local reproduction and measured cost

The existing saved public-only 223-identity v2 publication was reused; no actual
hosted database, key or encrypted checkpoint was downloaded. With unchanged
code and original reader limits, requesting both switching scopes failed with
`ValueError: stream deadline` after 300.51 wall seconds / 80.11 CPU seconds.
Local wall time reflects competing system work and is not a hosted runtime
prediction. This demonstrates the same possible failure mode, not the original
hosted exception.

A profile of the first 1,000 claims found substantial repeated character scanning
inside `literal()`: 69.96 cumulative profiled seconds. Those calls occur during
JSON validation, literal-table validation and decoding. The profile itself adds
overhead and is not a production latency measurement.

A five-repeat microbenchmark scanning 5,427,200 advisory-text characters per run
measured minimum process CPU time of 0.128923 seconds for the Python loop versus
0.015595 seconds for the C regex prototype (about 8.3 times faster for that
operation). These numbers must not be presented as an application-wide speedup.

## Minimal changes

- Scan surrogate code points with a compiled C regex rather than a Python
  character generator. Keep the same rejection range, original string object,
  no encoded copy and all byte/depth/deadline limits.
- Emit a closed failure code on failed phases: deadline, byte budget, query
  mismatch, schema, memory, recursion or unclassified. Never format arbitrary
  exception details. The bounded diagnostic parser only forwards allowed codes
  on failed events; raw tracebacks and evidence remain private.

Tests cover scalar boundaries, long strings containing each surrogate boundary,
real decoder deadline propagation, unknown exception formatting and forged
failure-code rejection. Independent static review found no critical or important
issues. Exact final verification and representative results are recorded below
when observed; neither a microbenchmark nor a sampled replay certifies the hosted
candidate.

## Representative result after the patch

Both switching scopes completed with the original reader byte/depth/deadline
limits: **248.78 wall seconds / 142.72 CPU seconds**, 77,165,465 physical bytes
read, peak resident memory 678,019,072 bytes. The original run failed at 300.51
seconds after reading only 47,839,276 bytes. The before run did less work because
it terminated early; comparing their CPU time or memory as a percentage speedup
would be misleading. System contention also changed between runs. The relevant
result is completion of both queries within the unchanged deadline.

The first implementation of failure-code tests failed seven cases because the
code was missing, then passed after the implementation. The original full
public-sample query reproduced its deadline failure before the codec change and
completed afterward. The small Unicode fixtures retain boundary rejection and
exact decoded values. No functional validation check was removed.

Ruff, formatting and whitespace checks passed. Public source export checked 644
files, verified synthetic fixtures and passed private-artifact exclusions. The
full suite and the complete hosted candidate remain separate gates.

## Preflight verification

The complete synthetic suite passed **3,749 tests and 12 subtests in 641.06
seconds**. The v2 JavaScript shared codec, query, boundary and cancellation suite
passed. Ruff, formatting and whitespace checks passed. The focused independent
review reported no critical or important findings. These are preflight results;
hosted validation remains unproven until a complete successful run.

The hosted retry should use the encrypted captures retained by run
`42503815667` via `previous_capture_run_id`. Reused bytes must still be rehashed
against each pinned target and normalized by current code; capture time must
not be rewritten as a fresh HTTP check. No live runtime source pin, collection
schedule, workflow permission or public promotion is changed by this patch.

## Full hosted retry: still rejected

[Run 42510212446](https://github.com/abedegno/infrastructure-impact/actions/runs/42510212446)
used source `9794ea510786baf4e46295b55e10b079579b8988` and authenticated the previous
capture checkpoint. It imported all 174 targets with **zero HTTP attempts and
zero received bytes**, replaying 32,176,699 input bytes. This verifies runner-side
capture reuse; no actual capture archive or key was downloaded locally.

The candidate did **not** pass. The worker hit its unchanged 2,400-second timeout
at 2,400.32 seconds. Its last started phase was `publication.native_queries`.
Because the process was terminated before returning its result, the parent
receipt reports audit/capacity/candidate checks as unknown, not passed.

| Completed phase | Wall seconds |
| --- | ---: |
| First query | 98.25 |
| First projection | 379.54 |
| Writing | 644.46 |
| Inspection | 19.36 |
| Independent query | 98.66 |
| Independent projection | 384.30 |
| Native root verification | 666.95 |

These completed phases alone took approximately 2,291.5 seconds; query comparison
and standalone monitors cannot be assumed to fit the remaining budget. Peak
resident memory reached 5,764,694,016 bytes. Phase CPU closely tracked wall time.
This runner was slower on several unchanged phases than the earlier runner, so
cross-run wall times do not isolate the codec change's overall effect.

The public-sample improvement remains demonstrated, but it does **not** resolve
the full hosted pipeline's runtime. The new run's proven failure is the outer
worker timeout; it does not establish the earlier run's hidden exception.
The closed codes will be useful for caught phase errors, while timeout
classification comes from the supervising parent.

PR #44 must remain unmerged pending the wider runtime work. Do not activate its
source, raise limits, weaken validation or repeat an unchanged certification.
The next engineering target is the measured repeated query/projection work and
complete-root traversal, with representative CPU/memory measurements and all
existing semantic, type, provenance and native/static checks preserved. A shared
immutable projection or shared-fact representation needs a concrete design and
mutation tests before replacing independent recomputation.
