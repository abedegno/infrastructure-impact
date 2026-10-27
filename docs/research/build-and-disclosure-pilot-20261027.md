# Build evidence and disclosure research pilot — 27 October 2026

Assistant primary-source research; independent human review remains pending.
This is a retrospective purposive pilot, not representative sampling. It does
not change the frozen OpenSSH CVE cohort or the 15 product-scope targets.

## Two exact firmware references

The common role is SSH management on switching platforms. The targets are Arista
EOS 4.32.2F and Aruba AOS-CX 10.13.1031 for CVE-2024-6387. They were selected from
accessible explicit vendor fix statements to test field-level evidence, not to
estimate relative security or compare installed deployments.

| Field | Arista EOS 4.32.2F | Aruba AOS-CX 10.13.1031 |
| --- | --- | --- |
| Exact release reference | Explicit EOS fixed-release boundary in advisory 0100 | Explicit CVE-specific fixed product-version node in HPESBNW04669 |
| Exact package/upstream version | Not established | Not established |
| Backport evidence | Publisher describes patching existing OpenSSH packages without incrementing the version string in the fixed EOS trains; not an image manifest | Not established; absence of a statement does not establish absence of backports |
| Exact hardware/build compatibility | Not established by the advisory's applicability list | Not established by the product-version node |
| Image digest, installed configuration, historical support and download availability | Not established | Not established |

The [Arista advisory](https://www.arista.com/en/support/advisories-notices/security-advisory/19904-security-advisory-0100)
also lists separate CVE-2024-6409 fixes in EOS 4.34.1F, 4.33.4M and 4.32.6M.
Those are not substituted for the regreSSHion boundary. Reviewed source SHA-256:
`35762b2fdc7b9674959f19909839677bc72b3d0962c42bf71784f43abc899779`.
The original generic parser retained affected ranges but omitted these EOS fix
and backport statements. The supplemental parser preserves existing assessments,
adds two CVE-specific EOS fix claims and retains qualified backport/mitigation
context. Three bounded section hashes guard resolution, platform and mitigation
scope. Changed scope fails for review; unrelated navigation may change freely.
Hotfix downloads and installation are not performed.

The [Aruba CSAF advisory](https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04669.json)
provides the exact `10.13.1031_aos-cx` fixed-product node. Reviewed source SHA-256:
`07e221b234c64d09ef18a2d291639e2bbca2d6f4bd511dbb6325fee088daa138`.
A remediation's date is not an independently verified binary availability date.
Neither the Orchestrator package example nor Instant On configuration conditions
are transferred to AOS-CX.

The **Product cohorts** report now carries a separately versioned `build_pilot`
with a selection fingerprint. It joins only exact URL/vendor/product/CVE matches,
CVE-specific fixed status and exact reviewed expression or product-version context.
Each field has its own evidence state and source locator. Missing fields stay
null. Neither target is called a verified inventory; no denominator or rate is
produced. Unknown fields identify the exact image/manifest/device evidence needed
for a subsequent inventory pass. This pilot has not obtained that evidence.

## Three disclosure dispositions

| Task | Source-led disposition | Remaining evidence |
| --- | --- | --- |
| FortiProxy 7.2.8 curl edit | Earlier-advisory counter-evidence defeats the narrow inference that the later documentation edit itself establishes nondisclosure. | Historical documents, differing HTML/CSAF date claims, exact image availability and independent review. |
| HPE Cray CcNc/HFP chronology | The 70-day publisher-claim interval remains unresolved, not a verified release-to-disclosure delay. | Original HFP 24.8.1 manifest, platform/component mapping, historical download and earlier-notice evidence. |
| FortiProxy bug 968514 | Security/CVE linkage unresolved. Overflow/CPU wording alone does not establish attacker control, exploitability or a concealed security fix. | Authoritative bug-to-CVE/security-impact statement and exact code/build/prerequisite evidence. |

The FortiProxy chronology uses the retained [resolved issues](https://docs.fortinet.com/document/fortiproxy/7.2.8/release-notes/534553/resolved-issues),
[change log](https://docs.fortinet.com/document/fortiproxy/7.2.8/release-notes/4/change-log)
and [FG-IR-23-385](https://www.fortiguard.com/psirt/FG-IR-23-385). Current publisher
history dates are not historical captures. The original detailed investigation
remains in the packaged `fortiproxy-curl-investigation.txt`.

The [HPE bulletin](https://support.hpe.com/hpesc/public/api/document/hpesbcr04733en_us)
remains separate from the HFP release-listing lead. The indexed listing still
reports 24.8.1 on 28 August 2024, but no usable retained independent historical
manifest was obtained. That does not establish that earlier disclosure was absent.

The exact bug 968514 row is retained in the FortiProxy resolved-issues page. A
bounded official search also surfaced that bug number in the [FortiOS 7.2.8 notes](https://docs.fortinet.com/document/fortigate/7.2.8/fortios-release-notes/289806/resolved-issues)
with integer-overflow wording. That is an uncollected research lead, not proof of
cross-product identity or a CVE association. A no-result PSIRT search cannot prove
that no relevant advisory or private notice exists.

Machine-readable assistant investigations are bound to the complete set of
reviewed source URL/hash pairs, vendor, kind and CVE set. The unlinked defect also
requires its exact bug token. Changed/added/missing source bytes suppress the
current disposition and request re-review; a stale conclusion cannot silently
apply. No gate is marked independently adjudicated, and original private human
review materials are neither read nor changed.
