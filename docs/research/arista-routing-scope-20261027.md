# Older Arista routing applicability review — 27 October 2026

Three official 2020 advisories use distinct version, configuration and model
boundaries. This review supports three exact routes, not a generic parser for
all older Arista pages. Retained source hashes identify the reviewed content;
the source vault and full captured pages are private.

| Official source | CVE | Normalized statements | Retained source SHA-256 |
| --- | --- | --- | --- |
| [Arista 0054](https://www.arista.com/en/support/advisories-notices/security-advisory/11760-security-advisory-54) | CVE-2020-15897 | 8 | `d5623b81a0f43f7c4cf939cc8d8b40f5ea0429f08229aae546c8325fb65f50af` |
| [Arista 0055](https://www.arista.com/en/support/advisories-notices/security-advisory/11995-security-advisory-55) | CVE-2020-26568 | 9 | `34668b9c09f0aadf0c75268b53b61c899afaa073c4a0dd61d7b0cffccc33090d` |
| [Arista 0056](https://www.arista.com/en/support/advisories-notices/security-advisory/11996-security-advisory-56) | CVE-2020-15898 | 13 | `866cd01786f9e49abda329f936a8ee270c09420307060b45241d38e4c93a4cb1` |

Counts describe source statements, including separate model and version branches.
They are not unique products, portfolio denominators or vendor exposure rates.
Publisher initial/revision-table dates remain publisher claims. Retrieval times
record when this collector obtained the pages, not historical availability.

## Scope preserved

- **0054:** EOS has five literal affected-version expressions and an explicit
  platform-independent scope within those versions. IS-IS configuration is a
  prerequisite; Ribd and multi-agent modes have different protocol consequences.
  Seven separately named non-EOS products are explicitly excluded. Four listed
  fixed builds are retained as publisher-reported fixes.
- **0055:** EOS has four affected-version expressions and fifteen literal platform
  labels. Both non-default VRFs and VxLAN are required. Seven independent product
  exclusions and five EOS model-group exclusions remain separate. The publisher
  markup places those model labels after a flat family marker; the parser does
  not promote them to independent products or blanket EOS unaffectedness. Five
  normal builds and one special release are reported fixes. The post-upgrade
  decapsulation behavior and core-facing-interface qualifications stay attached.
- **0056:** The 7170 branch has one affected-version expression; X-Series has four.
  Their version ranges and configuration conditions are not crossjoined. X-Series
  requires an SVI with IPv4 or IPv6 routing disabled in its VRF; the 7170 condition
  requires an SVI without that routing-disabled check. The common nine-label
  model list is retained as advisory context, not assigned to each branch. Nine
  independent products and seven EOS model groups are explicitly excluded.
  The explicit 7170 unaffected statement for trains 4.22.x, 4.23.x and 4.24.x is
  separate from its affected 4.21.x expression. X-Series has six normal fixed
  builds and two special releases; 7170 has a separate publisher fixed-train
  expression. Each remediation stays with its own branch.

Listed fixes use `vendor_reports_fixed`. They do not establish first public
availability, support entitlement, automatic device version matches or a new
affected-range cutoff. Special releases remain visibly distinct from other
listed builds. Explicit inter-VRF/inter-VLAN routing is distinguished from the
unintended forwarding described by the publisher.

## Validation and limits

The parser checks the canonical official route, heading, tracked CVE, revision
table, local software/platform lists and reviewed configuration markers. Changed
branch labels, model-family boundaries, unexpected version expressions, new
special-release nesting or changed prerequisite markers require review. Footer
references do not enroll additional CVEs.

Original synthetic tests exercise version-branch isolation, flat and nested model
exclusions, fixed-build separation, configuration changes and identity checks.
The three retained real pages also pass schema validation. This is source-led
implementation verification; it does not complete independent human review or
establish that no other configurations or products are affected.
