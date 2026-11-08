# Architecture remediation — 8 November 2026

This change set addresses the startup, acquisition/retry and diagnostic defects identified in the [architecture review](2026-11-08-architecture-review.md). It does not establish complete hosted certification or resolve the larger evidence-representation design.

## Changes retained

- The app reads small benchmark metadata before requesting selected state. `/api/v1/bootstrap` has native/static GET/HEAD behavior and an OpenAPI description. Unspecified-CVE API defaults are unchanged.
- Exact imports prefer hash-verified baseline captures, then a durable private SQLite capture cache, then HTTP. They retain original capture timestamps, create no fictitious retrieval observations, and run the current normalizer. Failed candidate validation cannot erase the separate local cache.
- Optional hosted acquisition checkpoints are encrypted, authenticated and restored before emitting `acquisition_ready`. They use a sibling acquisitions tree, independently of accepted recovery state. The manual workflow option defaults false. A rejected candidate can retain its authenticated acquisition checkpoint without authorizing public publication.
- Staging transfers ownership of its checked checkpoint rather than making a second full database copy on the same filesystem; cross-filesystem transfer retains the standard copy fallback.
- Worker diagnostics retain only bounded, closed phase metadata and explicit termination classifications. Optional CPU and process-lifetime peak RSS measurements survive failure; raw logs and source content are not forwarded. Native parity and authenticated root/range/EOF checks remain intact.
- Quality CI retains its required job contexts, runs Python tests on both supported versions, runs shared frontend/package work on one leg, and avoids duplicate feature-push/PR executions. Superseded quality runs can be cancelled.

No live source pin, collection schedule, hosted permission or public deployment was changed during implementation.

## Measured evidence

The [measurement record](2026-11-08-remediation-measurements.json) separates datasets and measurement scopes:

- Actual headless Chrome with a disposable profile rendered the matrix against the saved public 223-advisory v2 sample. The final condition-based check confirmed 24 selected CVEs, no complete-snapshot request and no runtime exceptions. An earlier virtual-time screenshot harness could capture the loading state prematurely; its elapsed time is not a page-load SLO. This is local saved-data verification, not a live Pages or complete hosted-union test.
- The actual application-script/static-facade check selected 24 benchmark CVEs and fetched 3,318,209 bytes of data in 28 requests, without requesting the complete snapshot root. JavaScript/CSS asset loading is outside that counter. The old whole-cohort startup path rejected the same saved dataset at its 128 MB materialization bound.
- Synthetic restart tests reject a candidate and then replay retained captures with zero HTTP attempts/received bytes, unchanged timestamps and unchanged accepted database. Separate synthetic Fernet tests cover encrypted checkpoint/readback and retry; these do not use the actual hosted vault or key.
- Removing the redundant outer root digest reduced CPU by about 3.46% in one isolated root-verification measurement. This is a minor cleanup and does not identify the hosted failure's cause.
- Ordinary gzip compressed the public records component from 98.65 MB to 3.96 MB and diagnostics from 82.82 MB to 0.71 MB. Only three components were measured; this is not a complete alternative publication format, a browser-memory result or a fair whole-format size comparison.

## Decisions and costs

Acquisition state uses a sibling tree because nesting it inside accepted state breaks the existing strict encrypted-state validator. Both trees must be retained and independently validated; forgetting acquisition retention loses retry efficiency while leaving accepted state protected.

The attempted cloning refactor was reverted. Preserving the original strict JSON rejection behavior made the corrected experiment consume more CPU and memory on the bounded record-heavy test frame. The original cloning behavior and its overhead remain. Five regression cases now protect rejection of invalid discarded wrapper metadata. No cloning improvement is claimed.

## Remaining work

The precise later hosted worker failure remains unproven until the instrumented code runs against the complete hosted baseline. The previous 223-identity acceptance and these local checks cannot substitute for that run. Activation and execution of the prepared read-only certification workflow remain separately reviewable; accepted recovery and public pointers must remain unchanged during certification.

Evidence/source-context duplication, overlapping logical roots and repeated full-state audits remain architectural costs. Normalize shared facts and compare simpler sharding only with representative semantic, memory and runtime measurements. The code retains independent checks rather than trading correctness for a passing timeout.

Hard runner termination before an encrypted acquisition checkpoint can still lose in-flight acquisition. Local caches have no automatic eviction policy. Independent human extraction review, historical coverage completeness and the interpretation of vendor disclosure counts remain separate research limitations.

## Verification

The complete local suite passed **3,711 tests and 12 subtests in 398.98 seconds**, with application credentials and configuration overrides removed and synthetic loopback monitors enabled. All eight JavaScript suites, the explicit CI Ruff/format scope, Prettier and workflow actionlint checks passed.

The wheel built and its offline isolated installed-package probe passed, including external plugins, resources, API views and real candidate monitors. That probe initially failed because its authored fetch stub bypassed transport evidence/budget side effects; it now substitutes HTTP responses at the opener boundary and asserts the actual acquisition counters. Production provenance requirements were retained.

The public-source export checked 641 files, synthetic fixture integrity and private-artifact exclusions. Actual hosted evidence/key access, certification and activation were not performed. The [inactive certification template](../../deploy/github-candidate-certification.yaml) is the next reviewable measurement step.
