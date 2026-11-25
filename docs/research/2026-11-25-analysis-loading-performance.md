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
