# Official source alternatives — 27 October 2026

This review distinguishes source roles. A working advisory index cannot replace
an appliance release manifest or establish a historical download date. Only
access observations from actual collector requests establish runner access.

| Official source | Role and result | Collection decision |
| --- | --- | --- |
| [Cisco CSAF provider metadata](https://www.cisco.com/.well-known/csaf/provider-metadata.json) and its [index](https://www.cisco.com/.well-known/csaf/index.txt) | The publisher advertises a CSAF directory and identifies Cisco PSIRT. Metadata says aggregator listing is permitted and raw mirroring is not. This is advisory discovery, not firmware/package inventory or binary availability. | Retain existing Cisco advisory discovery. Probe direct access separately; do not mirror raw CSAF or treat provider metadata as signature validation. |
| [Aruba CSAF index](https://csaf.arubanetworking.hpe.com/index.txt) | Existing configured source supplies product/CVE statements, including AOS-CX fixed branch references. It does not contain the Orchestrator remediation procedure or an exact installed package inventory. | Continue the existing index collection. The blocked PDF remains a separate gap. |
| [Cisco SBOM instructions](https://sec.cloudapps.cisco.com/security/center/resources/sbom-form-instructions) | Cisco documents image-hash-based SPDX requests for customers with Cisco.com accounts. The instructions describe the SBOM as proprietary/confidential and restrict sharing. | Account/terms-gated, not a public community feed. No request, account creation, entitlement use, terms acceptance or redistribution was performed. |
| [HPE HFP release listing](https://support.hpe.com/connect/s/softwaredetails?collectionId=MTX-575acc2c0e334c3a&language=fr&softwareId=MTX_c65e615117944819bcdc6219e0) | The current official search rendering lists HFP 24.8.1 with 28 August 2024. Retained direct responses have not supplied a usable independent historical manifest. Current metadata is not proof of public access in August 2024. | Research lead only. Probe ordinary direct access; do not infer availability from the index snippet or attach another HFP version's manifest. |

The existing exact Cisco UCS HTML/PDF, NX-OS HTML and Aruba Orchestrator PDF
probes remain. The expanded manual workflow checks nine exact URLs with bounded
anonymous GETs, and retains only status, size and fingerprint metadata. HTTP 200
still requires content review; an application shell is not an accepted manifest.
No failing alternative is silently installed as a scheduled source.

Official searches included Cisco's security portal, CSAF directory and SBOM
instructions; Aruba's configured CSAF index and remediation guide; and the exact
HPE HFP version and CcNc build. No public, redistributable exact-image SBOM route
was established for the blocked sources. This bounded review cannot prove that
other official channels or earlier customer notices do not exist.

## Runner observations

The [expanded runner probe](https://github.com/abedegno/infrastructure-impact/actions/runs/40483857329)
on 27 October 2026 at approximately 09:50 UTC retrieved the Aruba index and Cisco
SBOM instructions with HTTP 200. Cisco's provider/index, both UCS forms, NX-OS HTML
and the Aruba remediation PDF returned 403. HPE's release-listing lead was rejected
by the existing access/redirect checks. Source metadata and response hashes are in
the workflow artifact; no source bodies, credentials or recovery material are in it.
The accessible Aruba index is already configured, and accessible SBOM instructions
do not make the SBOM itself public. No unsupported collector source was enabled.
