# Bounded customer comparison replay — 9 November 2026

Result: the accepted cached public-source replay passed source-to-customer
JSON/CSV and browser acceptance. This is a deliberately bounded integration test,
not the live production dataset, a historical completeness measurement or a fair
vendor comparison. No raw source captures are included in this repository.

The operator receipt records replay observation time
`2026-11-09T19:44:54.925737+00:00`, 41 claims, six reviewed affected-scope links,
26 release nodes, 14 Arista fixed-release nodes and zero model bindings. These
are replay artifact sizes, not additional customer exposure denominators.
The real browser acceptance at `834a670` validated the closed envelope, exact
Python/browser CSV parity (300,446 bytes) and rendering of the retained public
source facts. Task 5 reuses those accepted JSON/CSV facts for the compact overview;
it does not reacquire or renormalize sources.

Aruba CVE-2024-6387 retains three reviewed branches: 10.14.0007 has the explicit
reported release date 2024-07-12; 10.13.1031 and 10.10.1131 remain undated.
The maintained support table supplies literal model/SKU minimum versions only.
Arista 0148 supplies separate notice publication (2026-09-02) and member
publication (2026-09-09), with 30 EOS advisory members; neither date establishes
software availability or a customer upgrade.

Original public capture receipts retain source hashes and actual capture times
for the four release references and three Arista advisories. The Aruba advisory
capture's original retrieval time is unknown: its receipt explicitly identifies
the local replay observation instead. Document dates and file modification times
were not substituted as retrieval times. The four enabled release references are
retained in this replay; Cisco remains explicitly excluded/not collected after
blocked anonymous acquisition. Unknowns are preserved rather than filled from
other vendors or software branches.

Focused synthetic tests cover selection/identity, fixed-only context, unknown
history, CSV escaping and byte parity, v1/v2 publication delivery and the compact
three-vendor overview. Public source-export privacy and installed-wheel resource
checks are part of candidate preparation. Full hosted CI and full runner-state
acceptance remain separate gates. The bounded subset must not replace the
production dataset: after reviewed activation, the existing collector must build
from the full runner state, and the operator must verify live generation identity,
default/archive/browser behavior and generation-bound downloads.
