# Older Arista applicability and CVE/model matrices — 27 October 2026

Five newly reached archive documents used older paragraph headings or local
CVE/model matrices. They were retained as explicit parser gaps until their scope
was reviewed. These are assistant source reviews and synthetic software checks,
not independent human adjudication or global accuracy measurements.

| Advisory | Normalized scope | Boundaries preserved |
| --- | --- | --- |
| 0057 | CVE-2020-26569; 11 product/model statements | EVPN VxLAN prerequisites; affected X-series models and separate EOS model exclusions. |
| 0058 | CVE-2020-3702; 11 statements | Literal AP aliases and excluded AP models; radio/encryption prerequisites; the publisher's old support claim is not current lifecycle verification. |
| 0061 | Three tracked DNSPooq CVEs; 24 shared statements | Optional DNS-server/proxy configuration and native-Linux customization caveat; shared ranges are not independent per-CVE assessments. |
| 0062 | CVE-2020-28362; 10 statements | CVP/EOS/TerminAttr/MOS version expressions and TLS/certificate/gRIBI conditions; common hardware lists are not cross-joined onto every software row. |
| 0063 | Twelve local matrix CVEs; 36 CVE/model-group statements | Local Y/N cells, literal model groups and dated software expression; reference-only CVE-2020-26135 does not supply a product claim. |

The 0057 publisher markup closes one exclusion label before its nested list. The
parser accepts that reviewed sibling structure only at this boundary. Other
unknown nested exclusion groups fail. EOS and Wi-Fi model exclusions remain
scoped platform lists; they never become blanket unaffectedness for the family.

The 0063 matrix preserves the literal `C-235` label. It does not silently change
that publisher label to a different model. The initial revision row supplies the
publisher publication-date claim. The latest numbered revision supplies the
update-date claim; the stale update header is flagged where it differs. These
are documentation claims, not observations that this collector made in 2021.
Model-specific resolution dates are not independently verified historical fix
availability and are not converted to affected-version cutoffs.

The implementation uses reviewed article/section boundaries and exact local
identity checks. Changed tracked CVEs, unknown model columns, matrix spans,
unknown status cells, missing rows or nested conditions fail explicitly. Matrix
columns may be reordered without losing their associated model/status cells.
No upstream version arithmetic, inventory matching or completeness claim is made.

## Retained primary-source fingerprints

These captures were retrieved independently from the public vendor sources on
27 October 2026. Raw bodies remain in the evidence vault; the public source tree
contains synthetic fixtures only. A future vendor response may have new bytes.

- [11997-security-advisory-57](https://www.arista.com/en/support/advisories-notices/security-advisory/11997-security-advisory-57): `ec896fb09282ab66cd7bd8bc88ec8033cd18d1334eb450282c3775442adbc3fa`.
- [11998-security-advisory-58](https://www.arista.com/en/support/advisories-notices/security-advisory/11998-security-advisory-58): `043578783738deece72e05d72a5e1eb33a96c021274fd84fd19b261b03eb9953`.
- [12135-security-advisory-61](https://www.arista.com/en/support/advisories-notices/security-advisory/12135-security-advisory-61): `b3c957a72ef3b91d92af181c07f7c90751cf7d8fde2b355deeac45c87d3e8a83`.
- [12166-security-advisory-62](https://www.arista.com/en/support/advisories-notices/security-advisory/12166-security-advisory-62): `471fd05f19534038ce0dc763db33a6b20068d3773c27b6afda73670d8005ca6e`.
- [12602-security-advisory-63](https://www.arista.com/en/support/advisories-notices/security-advisory/12602-security-advisory-63): `76f4d58acb78f1ffcdf241f07bc934e1d67f97a6e739ff7db4cc8d65d193e182`.

The original independent human-review packet remains unchanged. Its sampled
assertions do not certify these new statements. Parser gaps that occur on later
archive batches remain visible rather than being generalized into this scope.
