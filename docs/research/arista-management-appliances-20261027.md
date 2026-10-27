# CloudVision management-appliance scope — 27 October 2026

Three older Arista archive pages previously failed normalization. The new parser
covers their exact official routes and reviewed software/platform boundaries.
This is an assistant source review and synthetic software verification, not an
independent human adjudication or a statement about other Arista advisories.

| Advisory | CVE | Retained source SHA-256 | Statements |
| --- | --- | --- | --- |
| [0050](https://www.arista.com/en/support/advisories-notices/security-advisory/11705-security-advisory-50) | CVE-2020-13881 | `456226123010fde841cc75d8a91b9a9cfac0ee304553c11c9b0a43015053bc06` | 7 |
| [0051](https://www.arista.com/en/support/advisories-notices/security-advisory/11706-security-advisory-51) | CVE-2020-24333 | `35df57923e55fc90e5d550b72c0ba1cc68ade81e26f3c520403e278725476ccf` | 7 |
| [0052](https://www.arista.com/en/support/advisories-notices/security-advisory/11758-security-advisory-52) | CVE-2020-13100 | `b5a544a7403a9dc21d0471b628cabb6b1855e0b1087900d398aa744ca6f50cb9` | 11 |

Counts include separate explicit product exclusions. They are not unique device
counts, exposure rates, or portfolio denominators. Publisher revision-table dates
remain publisher claims; these captures were obtained on 27 October 2026.

0050 concerns TACACS+ use for the base VM/shell login, rather than web UI login
alone. The normalized context retains the logged-key and captured-traffic
qualifications, plus the publisher's post-upgrade credential-change advice.
An upgrade statement does not prove earlier logged material has been invalidated.

0051 retains the affected expression before 2020.2 alongside the listed fixes
2020.1.2 and 2020.2.0. It flags the different cutoffs without rewriting either
claim or deriving an affected-version interval. The module-access mitigation is
restricted to custom roles; the publisher excludes the default roles from that
mitigation. A changed cutoff or listed-fix pair requires another scope review.

0052 concerns the CVX server and its control-plane agent. Its EOS-named fixed
builds remain attached to CVX; the explicitly excluded client-switch role does
not acquire an affected claim. Literal disjoint version expressions, CP ACL
mitigation, hotfix reference, reboot persistence and agent restart qualifications
remain separate. No hotfix binary was downloaded or executed, and its availability,
contents and historical release time have not been independently verified.

All three pages use a sibling exclusion list after a closed label. That local
structure is checked explicitly; unknown nested model groups are not flattened.
Changed tracked CVEs, software groups, conditions or hotfix links fail for review.
Raw bodies stay in the evidence vault; public tests contain original synthetic
examples. The original independent human-review packet is unchanged, and these
statements do not complete that review or justify vendor rankings or concealment
claims.
