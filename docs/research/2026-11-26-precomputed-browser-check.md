# Precomputed delivery: real-browser activation check

Keep the prototype disabled. A real browser reproduced the loading gain and exact
exports, but the cold Cisco view blocked the main thread for 9.3 seconds. Large
export verification also consumed substantial JavaScript heap. Passing the Node
benchmark is insufficient to approve hosted activation.

## Method and results

The implementation was `4bf46ef`, with the same pinned public generation
`e05fc9e8e5ce404190173f4c3c037498` and its refreshed, independently verified local
preview. All three implementation CI jobs passed: Python 3.11, Python 3.13 and
container ([run](https://github.com/abedegno/infrastructure-impact/actions/runs/45889396974)).
No credentials, private evidence, vendor downloads or hosted configuration changes
were used.

The real engine was Chromium 150 / Electron 43.8.10 on macOS, in Orca's embedded
browser. The page reported visible and focused, at 1150 × 874 CSS pixels. The
application's customer-comparison page was served over anonymous loopback HTTP.
After the Cisco/2025 study selection completed, the actual Load and Refresh
buttons initiated the two application measurements. The other three cases used
the production reader in the same page with the checked-in
[accepted contexts](2026-11-26-precomputed-analysis-contexts.json). Those three
cases measure reader completion, rather than their complete application UI.
The earlier study-selection wait is outside these optional-analysis timings.

| Case                                 | Reader completion | Application completion | Response body bytes |
| ------------------------------------ | ----------------: | ---------------------: | ------------------: |
| Cisco/2025 cold optional analysis    |            9.55 s |                10.00 s |          11,422,166 |
| Same Cisco selection, warm refresh   |            0.28 s |                 0.98 s |                   0 |
| Aruba/all, subsequent distinct view  |            0.38 s |           Not measured |             312,551 |
| Arista/all, subsequent distinct view |            0.15 s |           Not measured |             156,689 |
| All/all, subsequent distinct view    |           11.24 s |           Not measured |          14,436,671 |

The [receipt](2026-11-26-precomputed-browser-check.json) records exact values and
response counts; the table rounds wall time. These are single local runs, without
a fresh-process browser control or a WAN comparison. They do not establish a
speedup factor between browser implementations. No CPU-heavy publication job
ran alongside these primary measurements.

All four unique JSON outputs and both CSVs per view matched the earlier pinned
oracle: **12 matching SHA-256 fingerprints**. Exports were serialized and hashed
separately from loading, using the production lossless JSON and CSV serializers.
This tests their exact bytes, not the browser download manager.

## Responsiveness and memory

A `PerformanceObserver` recorded browser long tasks. The actual cold Cisco action
contained a 9,307 ms task; its warm refresh contained a 955 ms task. The cold
application rendered and mounted the analysis successfully, but its main thread
was unavailable for most of the load. The screenshot was inspected: controls and
caveats were legible, with no horizontal overflow at the tested desktop width.
No error or unhandled rejection was captured during the instrumented runs.

JavaScript heap was sampled every 25 ms around the Cisco actions. The cold run's
observed high was 807,495,621 bytes; this is **not a true peak**, because callbacks
cannot sample a blocked main thread. The separately executed Cisco export-hashing
workload reported 2,014,406,921 bytes after its last export. Hashing buffers and
uncollected temporary objects contribute to that figure. It is not process RSS,
retained heap after forced collection, a mobile test or a low-memory guarantee.

A later diagnostic yielded to the event loop before export work, corroborating a
10.35-second task for the All/all read. A native capacity job overlapped that
later diagnostic, so its timings are not an additional controlled benchmark.
The primary other-view export run did not yield between read completion and
serialization; its long tasks can span both and must not be attributed entirely
to the reader.

To repeat the check, serve a fresh verified preview locally, open
`#customer-comparison`, select Cisco and 2025, and wait for the study selection.
Before clicking Load, observe `longtask` entries with `PerformanceObserver`,
sample `performance.memory.usedJSHeapSize` at 25 ms, and record the interval from
the click until `analysisLoading` is false after rendering. The application
variables and function names here describe the pinned implementation, not a
stable external API. Record render/mount duration, resource timing and visibility
separately. Repeat Refresh, then use the pinned contexts through the same
production reader. Hash `InfrastructureJSON.stringifyBounded(report, null, '',
128000000)`, `InfrastructureSwitchingAnalysis.csv(report)` and its
`{upgradesOnly: true}` variant outside the timed interval. Compare the hashes with
the checked-in receipts. Sampling and observer overhead are part of this check.

## Proposed hosted selections and capacity

Use the eight explicit **All/Cisco/Aruba/Arista × full study/2025** selections as
the next candidate profile. The year is pinned for this generation; a later
observation cutoff needs its own profile check. Other years, model-qualified
scope and explicit CVE subsets retain the existing compiled path.

The default eight views generated from the pinned public analysis source in
151.50 seconds. Their standalone manifest and unique chunk files occupy
52,270,221 bytes. Adding their previously absent files while retaining the entire
verified four-view preview gives 939,425,307 bytes, leaving 60,574,693 bytes below
the unchanged 1,000,000,000-byte guard.

This is an additive part inventory, **not complete publication certification**.
The normal v2 logical-root/table encoding and the full authority/verification gate
have not been rerun for eight views; hosted retained-history files also remain
uninventoried. The existing four-view preview and its manifest were not modified
by this capacity run. No new hosted profile or activation switch was installed.

The next implementation should move expensive decode/validation work off the
main thread and reduce returned-object/export allocations, then repeat the same
browser export and responsiveness checks. Complete the eight-view publication
and hosted-history capacity gates after that. Deploy only after those checks and
separate hosted approval.

Counts continue to describe disclosure and collection, not vendor quality.
Missing reliability denominators remain unknown. Independent human evidence
review remains pending.

The subsequent [worker/eight-view verification](2026-11-26-analysis-worker-verification.md)
addresses the blocking task and completes the pinned capacity/inventory gates.
This earlier report remains the in-page baseline; its measurements are unchanged.
