# Precomputed selected analysis preview

## Intent and decision

The user approved a disabled local prototype for common vendor/year views, exact
JSON and CSV parity, custom-selection fallback and measurement before activation.
The standing opt-out of design/permission loops applies. Use existing Python and
JavaScript, no dependencies or hosted changes. PR #90 remains unmerged.

Logical packing was rejected: 48.65s versus 48.50s cold, with higher traffic. Move
selection work to publication. An exact Cisco 2025 selected DTO is 94,924,707 raw
bytes and 11,377,570 gzip bytes; Aruba/all is 3,571,916 raw and Arista/all 2,028,217.
All/all is 119,678,881 raw. Small ordinary JSON parts alone are insufficient.

## Delivery

Add `analysis_precomputed_delivery=False` to the two public bundle writers, plus
`analysis_precomputed_options=None` for an explicit bounded set of ordinary
vendor/window/scope selections. Reject options without the flag, v1, missing full
analysis and combination with vendor-preview delivery. Defaults remain unchanged.
Default options are All and each vendor, os_family, all and previous calendar year
if in the study bounds; explicit pilot options may use a smaller set. Explicit
CVE subsets remain a compiled-source fallback, including an empty subset.

Manifest name: `switching-analysis-selected.json`, version 1 and representation
`analysis-selected-delivery`. It binds publication, generated time, shipped study
hash, observation bound, complete source fingerprint and a closed list of views.
Each view binds its requested options, full accepted selection, decoded compact
JSON byte length/SHA-256 and ordered gzip slice descriptors. Divide one exact
native selected DTO's compact UTF-8 bytes into 4,000,000-byte slices; each physical
content-addressed gzip file has its own wire SHA and <=8 MB wire size and its
slice's decoded byte length/SHA. Verify exact slice sizes/count/sums and the whole
stream, even across Unicode/token boundaries. No raw giant DTO assets in the site.
The aggregate decoded value remains <=128 MB; no reader/site budgets increase.

Publish a normal v2 logical root for the small manifest, preserving ordinary-root
semantics and compatibility. Also save the identical logical manifest bytes as
`data/v2/<logical SHA>.json`. Its descriptor is derived from that root's verified
metadata, so the browser can load it without global string/shape tables. This
adds no catalog schema fields. Append manifest encoding after legacy routes and
preserve legacy dictionary partitions/descriptors. Native independent verification
regenerates every selected view and gzip descriptor from native source facts,
checks raw sidecars too, and rejects missing, extra or changed membership. A
self-consistent caller hash is not source authority.

## Selection and validation

Eligible advertised views load without any full-root/dictionary reads. Missing
manifest, unsupported selection or unavailable gzip support retains the existing
compiled selector. Malformed advertised eligible data fails closed. Bind accepted
study identity, observation end, definition, complete selection and child-report
identity/selection, compact memberships/references/fingerprints and row evidence.
Reuse check-only selected-upgrade validation without materializing expanded CSV
rows and without redundant schema walks. Public old validation APIs remain intact.

Native decoded report preserves its original native JSON ordering. Browser
preparation reproduces the existing browser facts-map insertion order (member
source/severity refs followed by requirement proof/train refs), preserving each
fact's inner order. Test literal JSON download string equality, not only object
equality. Preserve exact integers, legitimate float values and both existing CSVs.
No scientific selections, versions, provenance, models or upgrade walks change.

Keep one immutable prepared selected DTO at most, using the existing 16 MB raw
LRU and request pool; do not retain a map of 95 MB graphs per view. Returned
reports are independently mutable. Shared flights own their transport independent
of each waiter; both cancellation orders, last-waiter cleanup, retry, deadlines,
reader and per-call byte limits hold cold and warm. Check native decoded bytes
before fetch/allocation and actual requested JSON cost before handoff. Strict
UTF-8/JSON parsing and every compressed/decoded length/hash remain mandatory.

## Gates

First build four real candidate views from retained public analysis (Cisco/2025,
Aruba/all, Arista/all, All/all), clearly nonactivatable until the fresh writer gate.
Measure production reader cold/warm time, wire reads, RSS, source versus selected
work and exact selected JSON plus both CSVs. Stop rollout on a non-improvement;
do not weaken validation or raise caps. Only after a useful measured gain build a
fresh native-verified publication preview, accounting for current archive members
and clearly labeling any unknown hosted historical-file inventory. Full default
view coverage/capacity is not certified by the four-view pilot.

No customer data, private vault, new vendor collection, secrets, schedules,
workflow permissions, dependencies, hosted activation or automatic PR #90 merge.
