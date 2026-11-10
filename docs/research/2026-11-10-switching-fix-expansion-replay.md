# Bounded switching fix-attribution replay — 10 November 2026

This local candidate expands a finite reviewed set of publisher-reported fix
associations. Independent human evidence review remains pending. No collector,
normalizer activation or hosted publication was changed. These replay counts do
not describe the full retained or published collection, historical completeness,
customer exposure, upgrade work or vendor security quality.

## Source receipts and pins

The replay reuses nine official public captures already acquired on 10 November;
it performs no network acquisition. Every raw SHA-256 is checked before parsing.
Aruba receipts are `aruba/<advisory>.receipt.json`; Arista receipts are the `.json`
file beside each hashed `.capture`. Those files, reconnaissance and all raw bytes
stay outside Git under `/tmp/impact-fix-expansion/`. The older public inventory
was a discovery aid only; the URLs, actual hashes and capture times below bind
this replay. Document dates and file modification times are not retrieval times.

| Advisory | Exact primary URL | Raw SHA-256 | Retrieved at (UTC) |
| --- | --- | --- | --- |
| HPESBNW04888 | [https://csaf.arubanetworking.hpe.com/2025/hpe_aruba_networking_-_hpesbnw04888.json](https://csaf.arubanetworking.hpe.com/2025/hpe_aruba_networking_-_hpesbnw04888.json) | `66822b9d2cfb3de686798a8bb53f4cefea0b69426cf53e8a64ef76807d2240cd` | `2026-11-10T17:48:31.543481+00:00` |
| HPESBNW05027 | [https://csaf.arubanetworking.hpe.com/2026/hpe_aruba_networking_-_hpesbnw05027.json](https://csaf.arubanetworking.hpe.com/2026/hpe_aruba_networking_-_hpesbnw05027.json) | `cb5b3327c97f3dd20718278feec4413c5e3a31a524319c186d0fb6c226f629fd` | `2026-11-10T17:48:32.408683+00:00` |
| ARUBA-PSA-2022-012 | [https://csaf.arubanetworking.hpe.com/2022/hpe_aruba_networking_-_2022-012.json](https://csaf.arubanetworking.hpe.com/2022/hpe_aruba_networking_-_2022-012.json) | `f116fe548a9cee7d9990e751e56994bb35dbed9124e2d2812b0c6b387d21d404` | `2026-11-10T17:48:30.685971+00:00` |
| ARUBA-PSA-2022-004 | [https://csaf.arubanetworking.hpe.com/2022/hpe_aruba_networking_-_2022-004.json](https://csaf.arubanetworking.hpe.com/2022/hpe_aruba_networking_-_2022-004.json) | `6b6ebf1734613aa7dcaeef1946d917dd0686ce4d49183ba6bf0818e7ac182134` | `2026-11-10T17:48:29.473809+00:00` |
| HPESBNW05134 | [https://csaf.arubanetworking.hpe.com/2026/hpe_networking_-_hpesbnw05134.json](https://csaf.arubanetworking.hpe.com/2026/hpe_networking_-_hpesbnw05134.json) | `edad24e7d759b2def8cff6b79161e6a8014e46bc4e57523399d7ec998de72e4c` | `2026-11-10T17:55:17.981260+00:00` |
| 24074-security-advisory-0140 | [https://www.arista.com/en/support/advisories-notices/security-advisory/24074-security-advisory-0140](https://www.arista.com/en/support/advisories-notices/security-advisory/24074-security-advisory-0140) | `4da5c49e326c94903dd4730710303af7006adad407e991d4d64b20655a3093f9` | `2026-11-10T17:48:08.350705+00:00` |
| 12166-security-advisory-62 | [https://www.arista.com/en/support/advisories-notices/security-advisory/12166-security-advisory-62](https://www.arista.com/en/support/advisories-notices/security-advisory/12166-security-advisory-62) | `4a96a39b50469eb0f5239a6d7afca7a12a1a0d2631bfcb3d3e47e167826a7c82` | `2026-11-10T17:48:07.449259+00:00` |
| 19862-security-advisory-0099 | [https://www.arista.com/en/support/advisories-notices/security-advisory/19862-security-advisory-0099](https://www.arista.com/en/support/advisories-notices/security-advisory/19862-security-advisory-0099) | `b86e3910bfaaff9ba0d5bb1b55b9691397dec67ce932fd1add829a5565b779f7` | `2026-11-10T17:48:03.821537+00:00` |
| 19917-security-advisory-0103 | [https://www.arista.com/en/support/advisories-notices/security-advisory/19917-security-advisory-0103](https://www.arista.com/en/support/advisories-notices/security-advisory/19917-security-advisory-0103) | `9d5b5095c661c4d8828423c082aa2d2c308ffe8c2c807f5d66635ce8c2bc50f2` | `2026-11-10T17:48:06.574449+00:00` |

Aruba's five raw pins select CSAF product-parent ownership, exact independently
named affected/fixed leaves, CVE/product IDs, remediation indexes, complete
remediation-details hashes and availability proofs. These are reviewed section
derivations, not publisher-declared relationship objects. The original
remediation availability dates are 2025-11-18T17:00:00.000Z (04888),
2026-03-10T16:00:00.000Z (05027), 2022-08-30T17:00:00.000Z (012),
2022-04-06T17:00:00.000Z (004), and 2026-09-01T16:00:00.000Z (05134).
They remain advisory fix-availability context; none becomes a software release date.

Arista pins the full normalized Resolution plus the explicit CVE div/direct-UL
owner, ordered literal LI expressions and clause hash. Complete Resolution pins:

| Advisory | Normalized Resolution SHA-256 |
| --- | --- |
| SA0140 | `6b9b1f640ef04230e3453e66a991523bed45f49a1e5dde45d0ef72c04d1fcdd3` |
| SA0099 | `5f32fd93d7d6ecf845dc9e513724c31965d7b829d9e98906b4dd3f1c27d3655c` |
| SA0103 | `714cb409663fa52df834cd76c41afe053bbb81b9529c7d3304bf2d806cc261af` |

The shorter EOS-owned hashes for SA0099/0103 are not substitutes for these full
pins. Explicit Hotfix boundaries separate their EOS lists from hotfix material.
No new Arista fixed-list software or availability dates are supplied.

## Replay method and observed changes

`task1-replay.py` with `task1-replay-results.json`, and `task2-replay.py` with
`task2-replay-results.json`, in the external replay directory already validate the exact individual captures through Python
full/compiled, browser full/stream and native streaming validation. The combined
`task3-replay.py` reuses those receipts, rechecks hashes and affected-field equality,
then projects the combined inputs through release and customer delivery.

The controlled baseline disables only the two new extraction helpers and uses
the pre-branch literal parser and pre-branch eligible Aruba release labels on the
same cached bytes. It is an explicitly isolated feature comparison, not a replay
of the hosted retained state. Both sides preserve affected CVE/product/status,
configuration, model and issue evidence exactly. Original remediation fields
remain unchanged except the finite approved fixed-availability upgrades and
new copied links. Claim IDs legitimately change when remediation facts change.

| Source | New affected-to-fix links | New deduplicated remediation publications | Remaining limitation |
| --- | ---: | ---: | --- |
| HPESBNW04888 | 65 | 1 | Model applicability unknown |
| HPESBNW05027 | 20 | 1 | Model applicability unknown |
| ARUBA-PSA-2022-012 | 16 | 1 | 12 disagreeing/unsupported fixed statements retain unknown availability |
| ARUBA-PSA-2022-004 | 15 | 0 | Existing direct remediation publication already counted |
| HPESBNW05134 | 170 | 1 | Distinct publisher leaf labels; remediation index 1 preserved |
| SA0099 | 2 | 1 | Hotfix/MOS/other components excluded |
| SA0103 | 1 | 1 | One malformed literal remains unresolved |
| SA0140 | 0 | 0 | Affected platform evidence is truncated; fixed-only context retained |
| SA0062 (excluded control) | 0 | 0 | Component/configuration-dependent fixes outside this contract |

Aruba adds 286 finite links covering 63 distinct CVEs and four new publications.
Arista adds four fixed CVEs and 15 literal expressions, three copied affected
links and two new publications. Unique fixed CVEs, literal expressions, linked
CVE/product associations and deduplicated publications are separate quantities.
SA0062's entire extraction result stays unchanged. No generic version ordering,
model inference, evidence-limit change or truncation exception is used.

The release selector recognizes only the exact `AOS-CX ` prefix, an optional
terminal period on supported Arista expressions, and the explicitly stated
`and onwards` form. It identifies the first stated literal only, without assigning
any later installed version to the fix. The exact `HPE Networking AOS-CX` product
label is eligible only under the already-resolved `aruba-aoscx` family; extraction
and study aliases do not change. Source claim/remediation expressions remain
literal. `4.28.11Mand later releases in the 4.28.x train.` remains visible as
`fixed_expression_unresolved` (one vendor-fixed and one copied affected reference).
The unchanged availability guard also excludes 20 fixed references from 012: five
CVEs across 10.10.0002, 10.06.0200, 10.08.1060 and 10.09.1020 retain publisher
planned availability. Their historical dates do not automatically turn those
planned statements into released fixes.

## Delivery and interpretation limits

The combined replay stages both v1 and v2 public generations using synthetic
public record scaffolding and exact cached-source switching claims. No release
history source frames are supplied in this attribution-focused replay: every
software release date stays unknown and all five registered history inputs remain
uncollected. Existing release-history capture acceptance is documented in the
[9 November replay](2026-11-09-customer-comparison-replay.md); its dated context
is not substituted for these new literals.

Combined extraction contains 706 → 710 claims and 0 → 289 reviewed copied links.
Affected study CVEs stay exactly 80 Aruba and five Arista. Remediation publication
counts are Aruba 1 → 5 and Arista 0 → 2, counting each advisory once.

| Vendor | Literal release nodes before → after | Vendor-reported fixed CVEs before → after | Affected-scope linked CVEs before → after | Resolved fixed / affected references after |
| --- | ---: | ---: | ---: | ---: |
| Aruba | 18 → 32 | 23 → 75 | 0 → 63 | 336 / 286 |
| Arista | 0 → 10 | 0 → 4 | 0 → 3 | 14 / 10 |

These are distinct literal projection counts across this subset. Aruba's 52-CVE
increase in literal fixed context differs from the 63 CVEs gaining reviewed links:
some fixed CVEs were already visible before their affected scope could be joined.
Arista resolves 14 of its 15 original expressions; the malformed fifteenth yields
two diagnostics because both its fixed and copied affected context retain it.
Existing unknown availability remains separate from explicit fixed-claim context.

Default, Aruba, Arista, 2024 Arista, model-qualified, SA0140-CVE, SA0103-CVE and
empty-CVE selections exercise the customer envelope in each publication format.
Python selection, native JSON and CSV, and browser JSON/CSV/render acceptance
must agree exactly for all sixteen accepted selections. Fixed-only SA0140
context must never add an affected-scope link or remediation-publication event.
CSV totals are repeated and nonadditive. Missing linked evidence remains unknown.

The machine receipt is `/tmp/impact-fix-expansion/task3-replay-results.json`;
accepted JSON/CSV cases are `/tmp/impact-fix-expansion/task3-browser-input.json`.
Staged generation IDs are local test artifacts, not public activation receipts.
The current public baseline in reconnaissance establishes discovery context only;
it cannot replace a hosted retained-byte preview or private retention checks.

## Extension and hosted requirements

For another source, first retain its official public bytes and retrieval receipt,
then independently review exact CVE/product/section ownership, original literal
expressions, remediation details/dates and availability proofs. Add only finite
bindings to the closed trusted registry, regenerate browser contracts, add authored
positive/drift/forgery tests, and run cached-byte extraction/preservation and
Python/browser/native/export parity. Never accept a fresh hash solely because a
route or CVE still matches. Source drift must omit new fixes with a diagnostic
while preserving valid affected evidence; unsupported clauses stay unresolved.

Before hosted apply, an operator must preview/reparse the actual retained bytes
with the candidate normalizer in isolated staging and review the exact source
hashes, fingerprint changes, affected-field diffs, exclusions, unique CVE gains,
publication deduplication and unknowns against the retained baseline. The existing
shared adapter dependency scheme changes all nine built-in fingerprints; registry
resource-only changes affect Aruba/Arista. No forced unrelated replay is requested.
Independent human review and the repository's broad tests, clean public export,
installed-package/build checks and whole-branch review remain release gates.
After explicitly approved hosted activation, build from the full runner retention,
then verify generation identity, source failures, default/archive/custom selectors,
0140 fixed-only behavior and generation-bound JSON/CSV/browser downloads. Keep
prior generations and a rollback route. This report neither performs nor authorizes
that hosted activation.
