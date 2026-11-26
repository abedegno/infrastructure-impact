# Upgrade-analysis loading performance

The approved task speeds the existing result without changing counts, selections,
provenance, exports or validation meaning. The exact public generation measured
126,633,200 logical bytes, 124 token pages and 67 shared table parts. Local baseline
materialization took 41.13 seconds; full validation 19.05 seconds and ran twice.
Reliability joining/rendering took 67–123 ms. These are local diagnostic timings,
not a browser service-level promise. Large root size remains a limitation.

Use bounded decoder allocation reductions, an immutable validated-selector
capability, and exact membership indexes. Reuse the incremental SHA and strict
parser. Do not add a second root-sized native hash buffer or a new summary schema.
A compact/lazy result root could reduce traffic further, but is a larger API/data
model change; timeout increases would leave the measured work unchanged.

Decoder emit sites are private ASCII structural literals; charge literal lengths
without encoding punctuation repeatedly. Compute canonical string cost once and
reuse logical quoted text for the canonical observer. Return actual encoded byte
length from incremental SHA update and use that instead of encoding each observer
chunk again. Retain logical/ASCII canonical fingerprints, all byte/depth/deadline
limits, exact numeric parsing, page verification and cancellation cleanup.

A new prepared selector validates the compiled input once and freezes its entire
owned graph. It exposes a closure which rechecks generation and effective study
selection on every call, and returns independently mutable selected results as
before. The ordinary public selector still fully validates arbitrary input; no
public boolean bypass. Static v2 privately caches the prepared selector, resets
failed preparations and preserves unavailable legacy behavior. Source-group and
inference-group filters use exact tuple/set membership while preserving ordering.

No publication schema, budget, schedule, permission, source activation or secret
changes. Tests prove mutation isolation, repeated-selection identity, unchanged
exports and codec integrity/cancellation. Controlled before/after benchmarks use
cached public data outside Git, one heavy process at a time. The standing autonomous
execution preference applies; no further design approval loop.
