# Lossless packed analysis preview

## Intent

Make the large Cisco analysis cheaper to load without changing any scientific
selection, inference, upgrade walk, cohort, source attribution or export. The
vendor split leaves Cisco at 122.8 MB versus 126.6 MB for the full report. Repeated
claim/member/requirement objects are the next target. The user has authorized
implementation without further design-question loops; hosted activation remains
a separate approval.

## Chosen approach

Add one opt-in `switching-analysis-packed.json` root containing the complete
analysis. Store the three repeated tables (claims, requirement members and
requirement rows) as layout IDs and pooled value IDs. Pool values are compact JSON
literal strings: this preserves number types/spelling and nested object key order
for native roundtrips. Preserve every row, key, optional field and ordering. A
small `skeleton_json` string preserves the remaining source exactly, with null
placeholders at the three fixed table paths. This is lossless encoding, not
removing years/trains or changing eligibility.

Envelope fields: schema_version=1, representation='packed-analysis', publication,
generated_at, definition_sha256, observation_end, source_content_sha256,
source_logical_bytes, skeleton_json, layouts, values_json, tables, counts and
content_sha256. tables has exactly claims/members/requirements; object table rows
carry key-value pool ID, layout ID and ordered field-value pool IDs; requirement
array rows carry layout ID and ordered field-value IDs. IDs are finite safe
nonnegative integers. Layouts/pool are unique and fully referenced. Fingerprint
uses the existing canonical fingerprint convention, excluding content_sha256.

The decoder checks closed shape, integrity, identity, fixed placeholder paths,
row counts, layouts/IDs, duplicate keys and bounded expansion before allocating
row objects. Preserve native/JS requested-byte ceilings as well as declared source
size; cap cardinalities by existing compiled-schema limits. Reject malformed JSON,
nonfinite/unsafe IDs, accessors, expansion bombs and mixed cutoffs. Then run the
existing complete compiled-analysis schema and semantic validator, including the
original source fingerprint. Native inspection returns independently owned data;
browser pooled objects may share only when frozen before use and cannot escape
into mutable selected results.

`analysis_packed_delivery=False` is a strict opt-in keyword at the existing public
v1/v2 publication APIs. True requires v2 and complete analysis; combining it with
the old vendor-preview flag is rejected. Default false preserves all current
roots. Encode packed output after legacy root/route atoms so existing dictionary
IDs and parts can remain stable. The fresh record/evidence writer authority gate
stays in place, and independent verification regenerates the exact packed root
from fresh native facts. Legacy roots remain for old readers.

The browser chooses the packed root when advertised, for All vendors and concrete
vendors. Missing packed root keeps current paths; malformed advertised data fails
closed. Share prepared work through the existing independently owned flight cache,
with cancellation, per-reader/per-call limits, deadline, retry and last-waiter
cleanup intact. Cheap source-size metadata must not reintroduce first-caller
ownership in lower range caches. Return exactly the existing selected JSON and
both CSV exports.

Alternatives: pruning by year/train changes carry state and export semantics;
more vendor splitting does not reduce Cisco; a lazy proxy/source-schema redesign
is substantially larger. Choose lossless table factoring first and measure it.
If eager reconstruction still dominates, document the result rather than claiming
unmeasured improvement or raising budgets.

## Remove avoidable generation work

Prune vendor ownership before deep-copying the old preview, preserving complete
referenced groups/history and independent returned data. Public packing/vendor
APIs validate source input; private writer-only derivation may reuse its preceding
authoritative source validation. Independent native readback still validates and
regenerates. Never remove a public trust boundary or add a caller bypass flag.

## Evidence and limits

Test literal small encodings, exact source roundtrip, all existing rich selection
cases, both CSV exports, tampering with recomputed hashes, aliases, bounds and
lifecycle behavior. Benchmark the accepted current public generation in sequential
fresh processes using matched options: source logical bytes, physical reads,
loading/preparation/selection time and peak RSS; correctness hashes are mandatory.
Build a new native-validated publication preview from retained public inputs if
possible, with archives explicitly accounted for. A derivative capacity estimate
is not a fresh-publication certificate; state any unavailable gate precisely.

No dependencies, advisory schema changes, capacity increases, schedules,
permissions, secrets, new source collection, customer data or hosted activation.
Prepare a separate vendor evidence-request packet; do not contact vendors.
