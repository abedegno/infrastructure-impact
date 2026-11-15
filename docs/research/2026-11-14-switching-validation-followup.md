# Switching validation: source revisions and boundary controls

This follow-up changes validation inputs and explanatory metadata. It does not
change affected assessments, vendor selection, CVE totals, fixes or publication
scheduling. Independent human review remains pending.

The [published run report](2026-11-14-published-switching-run.md) remains frozen
to generation `3591f3596d5e41fe8d50ac633b8357e1`. Its 19-case results are not
retroactively updated by these changes.

## Arista SA-0137

The three existing cases retain their original reviewed raw SHA
`21540eabc1c78ff4d0a6122ff5b03e103017b4e9ef38551712936f26f64d5c7d`,
claim assertions and source locators. The cached 132,228-byte primary HTML
recomputes that SHA and the existing `arista_advisory_body_v1` digest
`fa1e6d7ded50c38b64b4f59263496bdedd3a60bf014a67a94d9f60dc2250ee4f`.
That digest is now attached to the cases, using the same article-scope mechanism
as six other Arista cases.

On a later capture, the query must compute the article digest from the actual
retained raw bytes before a scoped match is possible. The digest retains article
structure, links, conditions and text; it excludes surrounding page content and
the scheme's explicitly normalized email-cloak IDs. A scoped match stays distinct
from an exact raw-byte pass. No maintenance receipt or normalized claim substitutes
for that computation.

A cached-source replay passed all three original assertions. An explicitly
synthetic change outside the article produced three unreviewed revisions without
scope receipts and three scoped matches with correctly bound receipts. This
checks the mechanism; it does not claim recomputation of the hosted generation's
current capture or a new live pass rate.

## Cisco retained alternate revision

Three historical OpenSSH CSAF cases still pin SHA
`6d4f25908f5740ae1144d036930019bc8fbb0a13ead92d4322d1465cc393bb96`.
The current source-selection metadata instead describes unselected SHA
`3581442460f1e05047925241b27434c479548847c51d606755a3cd4e345707e8`.
Those are different reviewed bytes. The cases continue to report `source_missing`.

When validated selection metadata has the same vendor and URL but another SHA,
`source_context.state` is now `retained_unselected_different_revision`. It carries
the reviewed SHA and a sorted list of available revision SHAs and their selected
anchors. This is explanatory metadata, never assessment support or a passing
outcome. Exact-revision metadata takes precedence; unavailable or unanchored
views remain excluded. Blind review packets omit the context.

## Two additional automated source cases

- Cisco OpenSSH HTML SHA
  `efd1e8a9f975b68a6b5c002567b2279a27fd1feb61b5c5a6b8d9d2407b82e7d0`
  explicitly lists Nexus 7000 Series Switches under
  `div#productsconfirmednotvulnerable`. This is an **out-of-family boundary
  control**, not evidence about IOS XE or the selected Catalyst models.
- Arista SA-0158 CSAF SHA
  `0dc70cae7fe0380e01d4872a157c7d97c665da33b9d1fb74996e24c1321a6349`
  marks product `CSAFPID-2`, EOS version 4.34.8, fixed for CVE-2026-73456 and
  explicitly associates its vendor fix with that identity. This is a fixed-only
  control, not a first-fixed or model-applicability assertion.

Both cached primary bodies were hash-verified and replayed through the current
normalizer; both new cases passed locally. No source downloads were needed.
The sample becomes 21 cases (Cisco 6, Aruba 5, Arista 10), still purposive and
incomplete. Aruba already has three unaffected, one affected and one fixed-only
case. A proposed UCS fixed-only control was omitted because its exact primary
bytes were unavailable in the reviewed public caches. No additional bundle,
model-positive or statistical accuracy coverage is claimed.
