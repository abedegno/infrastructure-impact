# Upgrade-analysis loading performance

The baseline used public publication `141c2f9dc8f04c12a795ac819e7b4c8e`.
The compiled analysis root declares 126,633,200 logical bytes and spans 124
token pages. The decoder also opens 67 shared table parts. A local filesystem
fetch shim measured 35,299,406 transport bytes over 192 requests for the
shared tables and root, including metadata.

| Baseline phase | Local measurement |
| --- | ---: |
| Shared table loading | 1.43 s |
| Compiled root materialization | 41.13 s |
| One full compiled validation | 19.05 s |
| Release evidence join and HTML rendering | 67–123 ms |

The v2 path originally performed full validation when it loaded the compiled
root and again on each selection. It now prepares an in-place frozen, validated
selector once per reader. Each invocation checks the study identity and exact
effective cohort. The ordinary one-shot selector still validates the compiled
input on every call. A repeat selection recomputes its outputs and returns
independently mutable objects.

The decoder charges structural ASCII by character length, shares each quoted
logical string with its canonical observer, and counts the actual incremental
hash input bytes. ASCII exports still fingerprint the logical Unicode form.
The source-group filter indexes selected CVEs by vendor and advisory tuple,
and the inference-group filter indexes the selected requirement group IDs.
Both filters retain their source-array order.

Local timings include decoding, parsing, and validation CPU work. Fetch
latency and the browser UI affect deployed click timings.

## Matched before/after verification

A sequential local pair used the exact public generation, Node with explicit UTC,
the same privileges and warm filesystem inputs; other heavy local tests were
paused. Timed phases exclude export hashing and construction of the already
accepted study. This is one local pair, not a browser latency guarantee.

| Phase | Before | After |
| --- | ---: | ---: |
| Materialization | 34.65 s | 26.53 s |
| Initial full validation / preparation | 20.20 s | 20.40 s |
| First selection (previously includes duplicate validation) | 38.58 s | 15.77 s |
| Cold timed-phase total including tables/open | 94.48 s | 63.60 s |
| Repeat Cisco/2025 selection | 33.46 s | 12.76 s |
| Whole benchmark peak resident bytes | 1,900,527,616 | 2,087,190,528 |

Cold timed work fell about 33%; repeat selection about 62%. Both complete selected
export hashes matched, including the second selection. Both runs produced 3,240
rows, 120 distinct upgrade annotations and 3 source matches, with 192 reads and
35,299,406 transport bytes. No evidence or traffic was dropped to obtain the gain.

Memory did not improve: the optimized process recorded a higher transient peak
(about10% in this pair). End-of-phase heap snapshots are not retained-heap
measurements after forced garbage collection. Deep preparation adds traversal and
a temporary object set; this pair does not isolate that allocation's contribution.
No additional root-sized hash buffer was introduced. Browser memory is unmeasured.

Cold analysis still processes 126.63 MB of logical source data against the unchanged
128 MB selected-reader ceiling. A compact/lazy display path remains future work;
these CPU optimizations do not solve payload growth or mobile-memory suitability.
An earlier optimized attempt blocked in the macOS sandbox timezone service with
zero CPU activity and was excluded. The reported pair uses explicit UTC for both.
