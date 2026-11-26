# Responsive analysis worker: browser and eight-view verification

The worker removes the multi-second main-thread freeze while preserving every
checked JSON and CSV byte. It does **not** make every cold load faster. Keep
hosted activation separately gated; the public writer remains disabled by default.

## Browser result and tradeoff

The production revision was `52ce5d0`. One visible Chromium 150 / Electron 43.8.10
browser on macOS used the complete, verified eight-view publication for generation
`e05fc9e8e5ce404190173f4c3c037498`, generated `2026-11-26T08:22:06.194317+00:00`.
The browser viewport was 1150 × 874 CSS pixels.
The source-authority/native verification jobs had finished before the final
measurements; no full local regression job ran beside them.

The actual Cisco/2025 Load and Refresh buttons produced:

| Measurement                            | Preceding in-page implementation | Worker implementation |
| -------------------------------------- | -------------------------------: | --------------------: |
| Cold reader completion                 |                           9.55 s |               14.25 s |
| Cold application completion            |                          10.00 s |               14.50 s |
| Cold largest captured main-thread task |                         9,307 ms |                365 ms |
| Warm reader completion                 |                           0.28 s |                0.35 s |
| Warm application completion            |                           0.98 s |                0.59 s |
| Warm largest captured main-thread task |                           955 ms |                387 ms |

These are successive local observations, not a matched fresh-process throughput
benchmark or a WAN guarantee. Cold wall time regressed in this run. Worker startup,
transfer, validation and delivery are included. The purpose of the change is to
keep the interface responsive during CPU work. The cold timer observed
563 samples, with a maximum gap of 450 ms.
Structured-clone delivery and DOM work still produce visible sub-second tasks.
The upstream study-selection wait is outside these optional-analysis timings.

The other three pinned contexts used the same production reader, rather than
reselecting their complete application UI. Export serialization was separated
from their timed reads by an event-loop yield:

| Subsequent distinct view | Reader completion | Largest captured main-thread task | Response body bytes |
| ------------------------ | ----------------: | --------------------------------: | ------------------: |
| aruba-all                |            0.35 s |                              0 ms |             312,551 |
| arista-all               |            0.15 s |                              0 ms |             156,689 |
| all-all                  |           10.64 s |                            335 ms |          14,436,671 |

A zero task value means no entry over the observer threshold was captured, not
zero CPU work. Browser response timing can include cached bodies; the receipt
also records transfer sizes. The early four-view diagnostic is not the headline
measurement.

## Exact downloads and ownership

All **12 fingerprints** matched the preceding pinned oracle: four unique JSONs
and both CSVs per view. The Cisco checks clicked the actual three export buttons.
Main-thread JSON and CSV serializers were replaced by throwing traps after the
load/refresh checks; **zero** calls occurred. The UI supplied worker-produced
encoded bytes to Blob creation. Blob bytes were hashed before the download
manager, whose disk-saving click was suppressed during the check.

The other views called `switchingAnalysisExport` for each format. Their returned
mutable DTOs were modified and discarded before export; the source-owned exports
still matched. This complements the real-worker tests for independent clones,
shared cancellation, limits, definition checks, view eviction, faults and retry.
The largest observed main-to-worker physical transfer was
1,543,398 bytes, below the existing 8 MB cap.

The first Cisco JSON download took 17.15 s
including hashing and worker re-preparation after its configured 60-second idle
expiry. Do not present that number as a warm encoding measurement. Subsequent
CSV export/hash checks took 5.83 and
5.73 s. No configured corruption or
worker fault falls back silently. Missing Worker retains the documented existing
synchronous route.

## Memory observations

The observed main-thread heap during cold loading reached
257,094,545 bytes; the preceding implementation observed
807,495,621. These scopes are not equivalent: worker
heap is excluded from the new main-thread value. Moving allocation across threads
is not proof of a reduction in total browser memory. Heap sampling also cannot
certify a true peak during blocked tasks, and Blob hashing adds buffers.

A separate 250 ms OS sampler observed all matching Orca renderer processes,
including workers and other Orca surfaces. Across 696
samples its aggregate RSS high was
1,825,308,672 bytes. This excludes main/GPU
processes, is not an isolated-page benchmark, and has no comparable preceding RSS
series. It does not certify a low-memory device. Caller-owned full DTOs, downloads
and DOM still consume memory; the worker retains at most one prepared view and
releases it after 60 seconds idle. CSV row expansion is now lazy, but the bounded
final export still needs storage.

The screenshot was inspected: the existing controls, caveats and table remained
legible, without horizontal overflow at the measured desktop width. No error or
unhandled rejection was captured during the instrumented runs.

## Complete native and hosting inventory gates

One fresh eight-view publication used the explicit
**All/Cisco/Aruba/Arista × all-years/2025** choices from the cached public
projection. The source-authority writer passed in
364.74 s; independently
regenerating the native roots and all eight selections passed in
376.68 s. All
1,593 legacy root descriptors stayed unchanged. Final reader assets
were refreshed after the review fixes; their manifest and four byte-exact native
reads passed without loading global dictionaries. No new vendor collection or
private evidence was used.

The full site contains 12,679 regular files totaling
940,257,941 bytes, with 59,742,059 bytes below the unchanged
1,000,000,000-byte guard. Its current archive references
236 unique paths totaling
132,491,725 bytes **within**, not in addition
to, that site total; 233 members share ordinary assets.

The accepted public GitHub Pages artifact `15099144817` was downloaded
once and authenticated against its GitHub SHA-256 digest. Its producer was main
`26ccaef`, run `45781834286`, for the same
pinned generation. Inventorying its tar stream found 12,555
regular files totaling 886,999,090 bytes, and no historical-generation
directories. Its path inventory exactly matches its publication manifest. No
private recovery artifacts were downloaded.

Conservatively retaining every old public-artifact path while overlaying the new
site would total 941,172,126 bytes. The
9 old-only paths contribute
914,185 bytes. This closes the formerly unknown current
accepted-artifact inventory. It does not predict future corpus growth; each new
generation must pass its own guard. Private backup retention is outside this
public-hosting inventory and was not inspected.

## Repeating and activating

The [machine receipt](2026-11-26-analysis-worker-verification.json) records exact
values, all output hashes, worker traffic, native proof, archive inventory and the
raw-receipt fingerprints. The [accepted contexts](2026-11-26-precomputed-analysis-contexts.json)
remain the input oracle. Serve a freshly verified preview, select Cisco/2025,
and wait for the study selection. Observe long tasks and a 25 ms heartbeat around
the actual Load/Refresh buttons; track rendering and worker transfers separately.
For export checks hash `await reader.switchingAnalysisExport(study, format)` bytes
with Web Crypto, or tap the actual UI Blob before its download-manager handoff.
Do not serialize another copy on the main thread as part of a loading benchmark.
The operator guide describes the native writer and independent option verification.

No hosted switch, helper promotion, schedule, permissions, secrets, budget,
advisory schema, scientific count or source membership changed. PR90 remains
unmerged. Merge of the disabled implementation follows the user-approved plan;
hosted activation requires a separate concrete proposal and approval. Further
responsiveness work can target remaining clone/DOM costs. Low-memory and other
browser testing remain useful before a wider rollout.

Counts describe disclosure and collection, not vendor quality. Missing reliability
denominators remain unknown. Independent human evidence review remains pending.
