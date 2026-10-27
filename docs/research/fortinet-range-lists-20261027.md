# Fortinet single-CVE range lists — 27 October 2026

Assistant source review; independent human adjudication remains pending. Two
retained HTML sources were rejected because the existing investigation-list
parser expected summaries beginning with individual CVE IDs. These sources use a
single metadata CVE, narrative summary and explicit affected-product range list.

| Advisory | Explicit CVE | Listed product scopes |
| --- | --- | --- |
| [FG-IR-23-165](https://www.fortiguard.com/psirt/FG-IR-23-165) | CVE-2023-37930 | FortiOS and FortiProxy |
| [FG-IR-23-261](https://www.fortiguard.com/psirt/FG-IR-23-261) | CVE-2023-40721 | FortiOS, FortiProxy, FortiPAM and FortiSwitchManager |

Ordinary collector requests retained the reviewed responses at 11:47 UTC.
Raw SHA-256 fingerprints:

- FG-IR-23-165: `c74b9576bdb21b109cff5e12582c6a74fbdef66920e9dd19698164be2bbbf6d0`
- FG-IR-23-261: `435e0c69850c6d89db83f5e32f4edb105122811386cb1af5ecef825af812b424`

The new parser is restricted to these two exact official routes and CVE/product
populations. Separate structural hashes bind title, summary, affected products and
solutions, including link targets and nested workaround structure. Changed scope
fails for review; unrelated navigation cannot supply extra CVEs. Duplicate article
sections or identity metadata are rejected.

## Applicability and prerequisites

Only literal listed affected and explicitly unaffected version expressions are
normalized. A product may have both statuses on different branches. Those
statements remain separate, with stable per-status identities and exact locators.
No generic appliance version ordering, entire-portfolio conclusion or exposure
rate is computed.

The SSL-VPN issue describes an authenticated VPN user and web mode. The CLI issue
requires authenticated privileged access. Neither is promoted to an unauthenticated,
configuration-independent vulnerability. Unknown hardware and deployment scope
remain unknown.

## Solution discrepancy remains unresolved

FG-IR-23-165 includes FortiOS 6.4.14 in the affected interval and separately names
both 6.4.14 and 6.4.15 in Solutions. The parser retains an explicit discrepancy
qualification on the affected FortiOS statement. It certifies neither value as a
safe upgrade boundary. Workarounds and a virtual-patch signature are not full
software fixes. A FortiSASE mention confined to Solutions does not create an
inferred prior-affectedness claim or enlarge the affected-product list.

The initial implementation deliberately extracts no fixed-status or verified-fix
claims from either source. Consult the publisher and reconcile exact branch and
configuration scope before deciding an operational upgrade. Publisher dates are
not historical binary-availability observations.

## Empty structured publication remains a gap

The official [FG-IR-26-187 structured envelope](https://filestore.fortinet.com/fortiguard/psirt/csaf_multiple-node-js-cves_fg-ir-26-187.json)
was retrieved with title/tracking metadata but no vulnerability entries and no
explicit CVE/product scope. Reviewed SHA-256:
`8e9e3c09753825f181a6d0453e5cf76625c0693d4b8a2977d7f722b742f831bf`.
The title alone cannot identify which Node.js CVEs or Fortinet products apply.

A `publisher_scope_unavailable` failure now describes such an empty Fortinet
normalization result. Captures remain retained by transport, the failure stays
visible, and no advisory assessment is created. This is an evidence gap, not
unaffectedness or a finding about disclosure intent. Empty structured envelopes
may resolve to the two HTML sources only after exact-route and reviewed-scope
validation; nonempty structured vulnerability statements keep their own scope.

Tests use inline synthetic documents, with explicit section-hash overrides for
those fixtures. Original publisher pages are not included in source releases.
