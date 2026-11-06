# Arista attribution and expanded-comparison repairs

This is a correction of the existing primary-source attribution and validated
comparison design, authorized by the user's request to proceed with the two
reproduced Arista defects and comparison performance. It adds no product scope,
matching semantics, public schema or hosted activation. The earlier approved
[source-coverage design](2026-11-05-source-coverage-repairs-design.md) remains
binding. The operational evidence is recorded in public research PR #29.

## Correctness requirements

SA-0099's own header tracks CVE-2024-27890 and CVE-2024-27892. Its local EOS
version-group markers bind six literal expressions to 27890 and eight to 27892.
The corrected parser must use article-local tracking and grouping evidence,
preserve separate locators and qualifications, reject unbound/foreign scopes,
and remain independent of paragraph order. It must not infer hardware exposure,
versions, dates, fixes or CVE identity from page navigation or descriptions.
Prefer a narrowly reviewed exact-route adapter to broadening generic HTML rules.
Existing reviewed and generic single/grouped advisory behavior stays covered.

SA-0103's exact HTML article tracks CVE-2024-6858 with four literal ranges; its
advertised CSAF currently describes CVE-2023-5501. Preserve independently validated
HTML and represent the alternate disagreement through existing SourceSelection
contracts. Guard both exact entry URLs so direct CSAF collection/replay cannot
restore contradictory primary scope. Keep source URLs, hashes and publisher IDs
literal; use explicit reviewed representation pairing, never a CVE alias, guessed
URL, statement-count preference or borrowed remediation. Fail closed if the
reviewed article/identity/layout changes. Other advisory routes retain their policy.

## Performance requirements

The isolated public backfill has 91,993 latest normalized assessments and yields
91,393 research claims. Input construction measured about 16 seconds; a complete
comparison/export attempt exceeded ten minutes without an accepted output.
Profile extraction, score attachment, projection, strict shape/semantic validation
and reduction separately before changing code. Correct only demonstrated costs.

Preserve all existing JSON shape, source, generation, identity, uniqueness,
chronology, applicability, score and derived-count checks. Preserve fresh-call
rejection after input mutation and isolation between input and selected outputs.
Do not skip validation, narrow away inconvenient evidence, change scopes/statuses,
raise limits or introduce unsafe success caches. Keep existing public function
signatures and report schemas; prefer local algorithm/index improvements over new
prepared-report APIs or cross-call mutable caches. Any necessary departure must be
raised with concrete evidence before implementation.

Compare optimized behavior with stock validators/reference reducers on bounded
synthetic inputs, including invalid/mutated data. Prove scaling with operation
counts or deterministic work bounds rather than machine-specific timing tests.
Real public-data timings and resource observations belong outside Git.

## Acceptance and boundaries

Retain raw primary captures outside Git, use authored synthetic fixtures in tests,
and keep independent human impact review pending. Replay the exact three retained
Arista representations offline and verify CVE-to-version membership and source
selection. Rerun strict JSON/CSV switching outputs against the complete local
backfilled corpus, with the frozen study unchanged, for calendar years and the
existing pre/post split at both OS-family and model-qualified scopes. Known unknown
coverage/model states must remain visible; missing data never becomes zero exposure.
Use one all-vendor selection per scope/window rather than redundant per-vendor
validation runs. Record phase timings and any failure instead of a passing claim.

No native/customer vault, private worksheet, recovery material or credentials may
be read. No hosted source, schedule, permission, budget, runtime pin, release,
replay or deployment change is authorized by this repair. Ship reviewable commits
and a PR; do not merge the implementation or activate it without later approval.
