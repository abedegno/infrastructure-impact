# Cisco UCS release-note OpenSSH fix statements

Reviewed 27 October 2026 against the official [Cisco UCS Rack Server 4.2(3)
release notes](https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/release/notes/b_release-notes-for-cisco-ucs-rack-server-software-release-4_2_3.pdf).
Retained PDF: 403,995 bytes, SHA-256
`c16391a3d8086fc259306e64c6db6e94d575019a9c1291192187f31965889f45`.

| CVE            | Publisher defect | Security-fix release section | Literal product scope |
| -------------- | ---------------- | ---------------------------- | --------------------- |
| CVE-2024-6387  | CSCwk62266       | 4.2(3m)                      | Cisco UCS servers     |
| CVE-2023-48795 | CSCwi59840       | 4.2(3l)                      | Cisco IMC             |

These become two CVE-specific, fixed-only assertions in one scoped release-note
record. No prior affected range, exact server-model list, installation inventory
or independently verified download availability is supplied. The product labels
come from their respective defect paragraphs, not the adjacent processor and
S3260 defect scopes. A background reference to CVE-2006-5051 is excluded. The
Terrapin description's upstream OpenSSH range does not establish a component
version shipped in this firmware.

The PDF cover gives an initial date of 2023-01-06 and modification date of
2026-08-05 for the whole document. Neither establishes when these particular CVEs
were added or their fixes first became available. The scoped advisory's
publication/update dates remain unknown. Cisco ASA/FTD and the frozen firewall
study receive no affectedness or fixed claims from this UCS source.

## Extraction and review boundaries

The parser accepts one exact official PDF route and title. Each defect must have
one start/end boundary and the reviewed nearest release heading. SHA-256 values
cover normalized local section context and the entire defect span. They are
layout/scope review guards, not proof of publisher authenticity or a historical
signature. Acquisition retains the original PDF fingerprint separately.

Terrapin crosses a page break. Its span includes a running header that resembles
the next release section; ending extraction at the first matching heading would
truncate the paragraph. The parser instead uses the next unique defect boundary
and verifies the complete reviewed span. Inserted restrictions, changed fix
tense, new CVEs, missing/duplicate defects and page-layout changes require source
review rather than a wider automatic match. Changes elsewhere in the document
can be retained without claiming that this scoped interpretation changed.

Tests use synthetic text with separate fixture span hashes. Actual retained PDF
bytes are checked locally through the installed normalization registry. The
source pin is shared by both bundled configurations; operator configuration can
retain its other choices. Human review of the wider evidence packet remains
pending. This source is affirmative vendor fix documentation, not evidence of an
undisclosed fix or intentional concealment.
