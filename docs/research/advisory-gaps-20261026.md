# Arista and Palo Alto advisory gap review — 26 October 2026

This source review closes five parser failures. It is a maintainer review with
synthetic regression tests, not independent human adjudication. The existing
independent-review packet and vendor-comparison eligibility are unchanged.

| Primary source | Result | Source SHA-256 |
| --- | --- | --- |
| [Arista 0138](https://www.arista.com/en/support/advisories-notices/security-advisory/24019-security-advisory-0138) | Three header CVEs, two explicit VeloCloud products, six shared-bulletin claims | `c40cd0f564db8f89de567df6d5a4cc62eb4f4a5190680f94622bcde54658d5ea` |
| [Arista 0139](https://www.arista.com/en/support/advisories-notices/security-advisory/24029-security-advisory-0139) | One CVE, MCS on CVX and DMF, two claims with configuration context | `26f2b3ea68ac259943aa1d4489732c1d6bf30562dd19339555d85da27aa1d933` |
| [Arista 0140](https://www.arista.com/en/support/advisories-notices/security-advisory/24074-security-advisory-0140) | One CVE, EOS, one claim with hardware and Secure Boot prerequisites | `521bf0f62aeeda5687aac2a2ba0006495562a589c0c48439267a90c842565a7b` |
| [Arista 0141](https://www.arista.com/en/support/advisories-notices/security-advisory/24108-security-advisory-0141) | AirSnitch configuration notice, no CVE or product/CVE claim | `37eb1b105023416d4372d344c8ea813f3d96e9b2169904e173bb397c14af6c6a` |
| [PAN-SA-2026-0009 HTML](https://security.paloaltonetworks.com/PAN-SA-2026-0009) | Primary narrative and per-CVE rationale corroborate Prisma SD-WAN ION unaffectedness | `99c6303fd172682dcf0f65e13162a89d83592fc6da42b8cd13e1079b360dd785` |
| [PAN-SA-2026-0009 CSAF](https://security.paloaltonetworks.com/csaf/PAN-SA-2026-0009) | 22 entries contain 17 unique CVEs and five exact repeats; 17 unaffected claims | `cfa782f44ae5e7137e9a5ae3331df69745cf21027dd3ccda0b7f66478db06d85` |
| [Arista 0141 CSAF](https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_141_CSAF.json) | Draft envelope without vulnerabilities or encoded product assessments | `b9449ab7fe56dd1589c809854e6ca7ec42d829d58d8f16a018c1e55f1e8d2024` |

## Scope and limits

Arista 0138 uses nested product/version lists and an affected-software heading at
level four. Its CVEs are CVE-2026-43284, CVE-2026-43500 and CVE-2026-43503. The
Gateway GA-build qualifier remains literal. Platform exclusions and the separate
NetVisor/UNUM/Insight Analytics triage statement remain ordered context, without
becoming affected claims. Resolution text retains the planned 5.2.7.0 release;
no available firmware is inferred from a future-release statement.

Arista 0139 concerns CVE-2025-49844. Its EOS list applies only to Media Control
Service on CloudVision eXchange, not every EOS installation. The parser uses this
specific product label and keeps the local restriction, affected-platform lists,
DMF default-configuration exception and exploitation prerequisites. Arista 0140
concerns CVE-2026-10040: local administrative access and supported, enabled Secure
Boot are required. Its affected and unaffected hardware lists stay in context
with their original labels. Neither advisory automatically matches inventory.

These three documents use narrowly routed, reviewed sibling sections. Unknown
product headings, unbound or repeated lists, missing applicability context and
negative or nested version conditions fail closed. Mitigation and resolution
remain advisory notes; individual fixed ranges are not independently normalized.

Arista 0141 names AirSnitch and an internal bug, but no CVE. Its linked draft CSAF
also supplies no vulnerability entries. The metadata-only record preserves the
configuration prerequisites, mitigations and service-disruption caution. An
"Affected Software: None" list does not establish blanket appliance unaffectedness
for a configuration-dependent risk. No upstream CVE mapping is guessed.

Palo Alto's CSAF repeats entries for CVE-2026-35385, CVE-2026-35386,
CVE-2026-35388, CVE-2026-35387 and CVE-2026-35414. Each repeat is identical across
the entire parsed vulnerability object. The standards adapter normalizes exact
repeats once and records both source indices in a warning. Raw evidence retains
every entry. Distinct rationale, product status or remediation is never silently
overwritten: repeated CVE/product identities still fail validation. Individual
product identifiers, product ancestry, notes and threat rationale remain intact.

All five HTML URLs are pinned for normal collection, allowing successfully
retained documents to acknowledge matching archive errors. Other source errors
remain independently visible. These sources do not establish concealment or
support comparative vendor rates.
