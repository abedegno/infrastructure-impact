# Switching evidence readiness repairs

The maintainer authorized the repair order in the 9 November investigation and
previously opted out of routine design/plan approval questions. This document
records implementation choices, not authorization for hosted activation.

## Outcome and architecture

Make the live comparison's evidence limits inspectable and correct a demonstrated
Aruba fix-availability extraction gap. Reuse the existing Python reducers, retained
source fingerprints, plugin hooks, browser views and v1/v2 publication paths.
Do not rewrite transport or add a second evidence pipeline.

The legacy dependency readiness report remains intact. New study validation and
metric-specific diagnostics supplement it. Exact-byte matches, structural matches,
missing/unreviewed sources and disagreements remain distinct; no accuracy or human
review claims. Reports and blind packets bind to the same publication.

Study validation uses the existing switching definition, current partition and
vault-computed section digests. Alternate representations absent from those inputs
remain missing, not silently treated as a pass. Public projection must sanitize and
recompute from current records rather than trust caller-supplied results.

Patch counts keep existing evidence requirements. Add descriptive diagnostics for
missing grouping/attribution instead of allowing a null bundle to prove unbundled
release cadence. Correct Aruba availability only with narrowly supported source
structure and fixed product ownership; negated, planned, mixed-product and lifecycle
text must not authorize a fix for a different product. Separate fixed-release
statements may be displayed as such; they must not become affected range/model links.

## Approaches

Extending the existing diagnostics and typed adapters is selected because the
underlying collection/publication architecture is already functional. Relaxing
all fix guards would manufacture product/range links; rewriting the readiness
framework would delay the customer answer without improving evidence.

## Boundaries

No hosted sources, schedules, permissions, runtime pin, publication, secrets,
customer data, original vault or private artifacts. No frozen cohort definition,
version matching, security ranking, causal AI claim, silent-fix intent inference or
new capacity allowance. Missing historical totals and exact model scope remain
unknown. Synthetic fixtures only in Git; public-source observations stay outside it.

## Delivery

1. Study validation/packet publication, API and browser access with current-source
   fingerprints and old-generation compatibility.
2. Correct source-owned fix availability and show metric-specific caveats/readiness
   without converting unlinked fixes or unknown bundles into workload facts.
3. Bounded public-source triage of existing Aruba historical and Arista error lists,
   with a concrete retained-source repair/import worklist and no hosted apply.

## Source-led scope clarification during implementation

SA-0201 exposed a core generic Arista parser boundary defect: an unrecognized
CloudVision Portal heading allowed its version list to enter the prior TerminAttr
assessment. Correct that source boundary in the existing core parser and cover
both normalized and typed outputs. Do not compensate solely in the study bridge
while leaving known incorrect product/version ownership in the main record.
