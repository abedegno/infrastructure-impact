# Arista exceptional-layout review — 26 October 2026

Three failing archive documents were reviewed against retained primary bytes.
Each has a different normalization boundary:

| Source | Observed structure | Supported result |
| --- | --- | --- |
| [0146](https://www.arista.com/en/support/advisories-notices/security-advisory/24500-security-advisory-0146) | gRPC-go security notice with a GHSA reference, product/version lists and no CVE identifier in the article | Retain dated metadata as an unlinked security notice. Do not invent a CVE mapping or product/CVE assessment. |
| [0147](https://www.arista.com/en/support/advisories-notices/security-advisory/24515-security-advisory-0147) | Product/version blocks with explicit local CVE groups, including an unclosed publisher div | Normalize 15 explicitly bound affected product/CVE statements; retain hardware, description and required-configuration context. No range arithmetic or inferred fixed build. |
| [0148](https://www.arista.com/en/support/advisories-notices/security-advisory/24535-security-advisory-0148) | Informational table linking separate advisories | Retain 45 CVE references with zero product-impact assessments. |

0147's EOS ranges differ between the three-CVE group and CVE-2026-60002. Product
headings reset both the product and group. Required-configuration, platform and
resolution lists cannot become affected software ranges. The Wi-Fi software list
explicitly binds to CVE-2026-60001; description or internal bug references are not
used to replace that binding with another CVE. Source context must be read when
adjudicating applicability. Unlisted-product exclusions and fixes have not been
independently normalized by this scoped parser.

Reviewed raw SHA-256 fingerprints:

- 0146: `4c99192cbfb55c4f94d8aa68c66adb1d4d928209a22aa85b8bcf7fc30210b68c`
- 0147: `7bc76aeae346f869f0732f13fae56bb5d94497c564e68f6291c5f603ebf3a4c9`
- 0148: `d39e3ef1d14e8cd72a62c257e44c194230e2ca97be844decfb94bf117a872f01`

The public repo contains synthetic layout tests, not vendor source captures.
Successful normal collection of a pinned document now also acknowledges matching
archive queue documents for the same vendor and exact/resolved URL. That clears
obsolete queue failures only after validated ingestion; it does not reset unrelated
errors or infer archive completeness. Failed parsing leaves queue errors intact.

This source-led review was automated in the implementation session. It is not
independent human adjudication, and absence of a CVE identifier is not evidence
of concealed exposure. The prior human review packet remains valid against its
saved packet file and is not overwritten by this release.
