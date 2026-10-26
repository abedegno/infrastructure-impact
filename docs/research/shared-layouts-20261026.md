# Shared layout and release-branch review — 26 October 2026

Eight retained primary sources were reviewed to close the preceding parser gaps.
This is maintainer review with synthetic regression tests, not independent human
adjudication. The existing review worksheet is unchanged.

| Primary source | Source SHA-256 |
| --- | --- |
| [23118-security-advisory-0130](https://www.arista.com/en/support/advisories-notices/security-advisory/23118-security-advisory-0130) | `26158363bd0883577bfcb3f197bd4cc5938fd9e7a6f2cd0fb471e06f56ea5765` |
| [23119-security-advisory-0131](https://www.arista.com/en/support/advisories-notices/security-advisory/23119-security-advisory-0131) | `acf76257fc9ee8c95c2c1d2c4f256f39707b295a7b30456dd802bc82a68dace5` |
| [23399-security-advisory-0133](https://www.arista.com/en/support/advisories-notices/security-advisory/23399-security-advisory-0133) | `042d592e72d888dff533933f03cc434af7393561f0ee46df0d4cc7707af64db8` |
| [23784-security-advisory-0135](https://www.arista.com/en/support/advisories-notices/security-advisory/23784-security-advisory-0135) | `3c3216d984e71b3f2126c048108ec7caefddfa114e3ca3892d19b35004c64db1` |
| [24004-security-advisory-0136](https://www.arista.com/en/support/advisories-notices/security-advisory/24004-security-advisory-0136) | `027991e4266a52997110b02961990a218657c82e77f64e3b9e6a1a3d4d8c7a49` |
| [FG-IR-23-494](https://www.fortiguard.com/psirt/FG-IR-23-494) | `e359f7da04ba84f1337c36b9ee23ada0bb97dde7efdad2a1afca12cc4904d281` |
| [CVE-2026-0249](https://security.paloaltonetworks.com/json/CVE-2026-0249) | `f51f90f41f1d15edda257abbdd0db0656bd6f7d2c8a620245cb8c9c38ce3e941` |
| [CVE-2026-0250](https://security.paloaltonetworks.com/json/CVE-2026-0250) | `59dd44bf92e711c35c48518fadc4aec038f25871baef76fe76edbc19e4b82f00` |

## Arista

Advisories 0130 and 0131 are explicitly reposted VMware-era VeloCloud advisories.
The revision-table initial dates are retained with a provenance warning, without
claiming those dates establish first Arista disclosure. Their affected software
lists supply one claim each. Advisory 0131 tracks CVE-2020-3973, but its resolution
names CVE-2019-5533. This mismatch is flagged and supplies no normalized fix.

Advisory 0133 supplies six NGFW CVEs and a shared software list: six shared-scope
claims retain the publisher's per-CVE configuration/mitigation section. Advisory
0135 supplies three runC CVEs across cEOS-lab, the optional Docker SWIX extension
and MOS: nine claims. The standard EOS core-image exclusion and optional-extension
conditions remain context; none of these claims represents blanket EOS exposure.

Advisory 0136 supplies six product scopes for CVE-2026-31431. The AGNI version list
specifically names a physical DCA-AGNI-100 appliance even though its heading also
mentions virtual appliances. The narrower product label and full nested version
expression are retained. No virtual-appliance applicability is inferred.

The reviewed sibling-section parser now handles these heading/list variants with
explicit product maps and exact document routing. This shares structural parsing
without treating unseen layouts as reviewed. Unknown groups, missing required
configuration context and unsupported range conditions still fail closed.

## Palo Alto Networks

CVE-2026-0249 and CVE-2026-0250 repeat product/platform blocks for different release
branches. The CNA adapter combines these only when all other scope metadata and
the version-status sets agree. Every distinct version object, including change
points, and the union of CPEs is retained. Evidence locators identify all contributing
source indices. Differing defaults, modules, statuses or conflicting expressions
with the same start version require review. Version ordering, overlap, disjointness
and exploitability are not inferred. Three and five product/platform claims,
respectively, remain distinct across their platform scopes.

## Fortinet

FG-IR-23-494 explicitly names CVE-2022-23439 and lists affected/unaffected version
lines. It is not a shared-CVE investigation-list layout. Thirty-three product/status
claims preserve literal ranges, the on-premise product qualifier and the full
ordered context including lower-bound markers. Interface-specific solution text
contains mandatory configuration requirements in addition to upgrades. It remains
context, without independently claiming unconditional fix availability.

No source here establishes concealment or a comparative vendor security rate.
See the [coverage matrix](../COVERAGE_MATRIX.md) for collection-depth interpretation.
