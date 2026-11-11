# Bounded client cancellation lifecycle

Live generation1c4f6af0a2954e8c90f3cdac7553a8ba passes health/archive/default browser exports/Aruba selection, but selecting CVE-2026-10040 fails after the existing300000ms client stream deadline. The ordinary OS-family view remains functional. No unsupported fix may be inferred to mask this failure.

publication-v2.js operation.run races every token read against the same unresolved interrupted promise. Completed races leave subscriptions retained on that shared promise until operation close/abort; token counts are millions. First reproduce the resource growth with public streamTokens and an instrumented Promise in an isolated JS VM, then replace the shared unresolved-race mechanism with a bounded registry of only currently in-flight waiters. Every settled read removes its cancellation registration on both success and failure. Abort rejects/clears active waiters, close clears its timer and external-signal listener, and already-aborted signals remain safe. No global retention. No new public test-only API.

Preserve run results/rejections, existing cancellation/deadline errors and300000ms ceiling, byte/depth/working/request limits, source/token/claim validation, observer semantics and all output identities. No schema/DTO/data normalization, workflows, scheduling, permissions, upload roots or backend code changes. No private configs/vault/keys/job logs or customer data. Do not profile heap object values; diagnostic metadata only from an owned headless QA browser.

Prove an O(in-flight), not O(total completed reads), cancellation-registration bound with a resource regression. Retain cancelled/pending/failed reads, nested aliases, external already-aborted and deadline behavior. Run existing JS/publication/selection tests and a fresh browser check against unchanged actual public data through a transparent local test proxy if needed; any local asset override is test-only and must not be represented as a published artifact/manifest acceptance. Full live QA follows ordinary source-pin rollout.

Backend source, schemas, resources and dependencies remain byte-identical to fully certified892f45a. Reuse that backend acceptance plus new full CI/client tests rather than rerunning a38-minute unchanged backend workload; activate through the existing collector with reparse_limit0 only after review/tests. Publication still applies its unchanged audit and public-health gates.


## Measured second bottleneck: schema branch probes

The bounded-waiter fix is independently necessary but did not alone resolve the actual-data deadline. The page-reparse hypothesis was disproven: an existing one-page parsed memo already handles32claims with1–2page parses. Do not change page decoding/caching on that hypothesis.

Two30-second actual-data CPU windows identified switching-contracts.js as77–79% of non-idle sampled time, especially frame-start line33 (failure/Error construction), with heap110–151MB. The validator's private matches() probes schema alternatives by calling check() and catching failures. Creating full Error stacks for expected branch nonmatches is avoidable.

Use a private shared mismatch sentinel only inside speculative matches() checks. Add an internal failure-handler parameter/default to check() and propagate it through its recursive ref/allOf/conditional/property/item checks. The public validation path retains the existing real Error factory and messages; matches() retains its existing boolean/catch semantics. Run exactly the same logical tests, alternatives/order and validation constraints. Do not cache validation results, skip branches or relax any schema/format/identity/byte/deadline rules. No sentinel may escape public validation. Generated bundle/schema/definition contents stay byte-identical; modify only runtime validator code outside the generated region.

Prove valid anyOf/oneOf probes stop constructing Error objects with an isolated error-constructor counter, not a timing-only assertion. Compare valid/invalid decisions and public Error type/messages across nested refs, alternatives, conditionals, negation, numbers/bigints, arrays/objects and formats. Real-data browser selection under the unchanged300s ceiling is the acceptance criterion; metadata-only CPU profiling is diagnostic evidence, not acceptance.
