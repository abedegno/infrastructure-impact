# Apstra server OpenSSH scope — 27 October 2026

Two official Juniper release-note PDFs describe AOS-47640, CVE-2024-6387, for
**Apstra Server 4.2.x on Jammy Ubuntu 22.04 with OpenSSH 8.9p1**. The documents
have different remediation wording. Neither source establishes SRX/Junos exposure,
a complete component inventory or the version installed on a running appliance.

| Official document | Bounded source statement | Normalization |
| --- | --- | --- |
| [Apstra 4.2.0 release notes](https://supportportal.juniper.net/sfc/servlet.shepherd/document/download/069Dp00000FJIxcIAH) | AOS-47640 supplies an SSHD configuration workaround | Affected server statement with `partial_mitigation`; no fixed build |
| [Apstra 5.0.0/5.0.1 release notes](https://supportportal.juniper.net/sfc/servlet.shepherd/document/download/069Dp00000FJIqkIAH) | AOS-47640 says 4.2.2.1 and 5.0.0 will include a fixed package | Existing affected server statement retained; fix remains `planned` |

The second document's title does not make its OpenSSH 8.9p1 paragraph a component
inventory for 5.0.x. That paragraph explicitly describes 4.2.x. Passing time and
a printed PDF footer date do not prove that a planned fix became available.
Both normalized advisory publication/update dates remain unknown.

## Issue and document boundaries

The 4.2.0 document places a separate Terrapin/Paramiko client workaround after
AOS-47640. Its 4.2.1.1 upgrade instruction belongs to that neighbouring issue.
The parser stops before that heading. The 5.0.x document places a Python issue
after the OpenSSH resolution; that issue is excluded too. Neither neighbour
contributes CVEs, component versions or fixes to the regreSSHion statement.

The two PDFs have separate normalized advisory identities. The existing
`Apstra-AOS-47640` identity is preserved for the planned-fix document; the 4.2.0
document uses `Apstra-4.2.0-AOS-47640`. Import order cannot replace one with the
other. They are separate document editions, not observations of one URL changing
over time. No temporal change or hidden fix is inferred by comparing them.

The component-reference hook reads the same bounded paragraph and returns only
OpenSSH 8.9p1 for the stated 4.2.x server context. Both sources are validated before
scheduled release-document ingestion. The source component inventory and advisory
assessment remain distinct uses of the same evidence.

## Provenance and verification

Reviewed retained hashes:

- 4.2.0 PDF: `d272c986f3ff3253d445a0b66c657f0e48e6b58748d7f2dee5e0bf25e4fbfbc7`
- 5.0.x PDF: `0dc987fc2cf3b083fd9a19e20d49249b07a2bf6c1f8e69f87d25362de5c0f5d3`

Full captured documents remain in the private evidence vault. The public data
contains bounded normalized statements, source pointers and hashes.

Original synthetic tests check identity changes, exact issue boundaries,
future-tense fixes, workaround scope, component versions, import-order isolation
and rejection of unknown route parameters. Both actual retained PDFs pass schema
validation. The frozen OpenSSH study retains its original enrollment and six
firewall families. Apstra is outside the SRX family; its CVE reference can be
visible as vendor evidence while the SRX family still has no assessment.

A separate request for Juniper's Terrapin JSA76462 returned a community loading/
CSS-error shell without the advisory body. That is a collection gap, not evidence
that Juniper omitted a disclosure or that an appliance is unaffected. Independent
human review, deployed-build equivalence and historical release availability
remain unverified.
