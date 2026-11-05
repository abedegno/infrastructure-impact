# Source-failure triage after v0.10.0 — 5 November 2026

This audit reconciles the **17 failed source checks** in publication
`07a2e555415148b2be32c3b0f4f40472`, pipeline run 63, with the public
source-audit records. It is a dated observation, not a live dashboard or a
vendor completeness claim. [JSON](2026-11-05-post010-failure-triage.json) and
[CSV](2026-11-05-post010-failure-triage.csv) contain all 17 source URLs,
published error codes/times and separate fresh-probe provenance.

## Reconciliation and method

The published run interval is 2026-11-05T20:34:22.183522+00:00 through
20:36:43.767727+00:00. The public audit contains 71 latest-per-source errors;
17 have checks inside that interval. The other 54 are older latest states:
42 Arista and 12 Palo Alto. They must not be added to the run's 17 failures
or treated as failures newly introduced by v0.10.0.

The manifest, index, bootstrap and source-audit fingerprints were checked
before this join. Their exact hashes are in the JSON report. Public inputs:
[manifest](https://abedegno.github.io/infrastructure-impact/manifest.json),
[index](https://abedegno.github.io/infrastructure-impact/data/index.json),
[source audit](https://abedegno.github.io/infrastructure-impact/source-audit.json).
Those URLs can later serve a newer generation; the recorded fingerprints
identify this audit's inputs.

Thirteen failed public URLs were probed anonymously: 12 returned retained
documents and one returned an explicit redirect. Four Check Point challenges
were not retried. Captures retain exact URLs, retrieval times, bytes and SHA-256
outside Git. The first probe used a declared research user agent; separate
Arista/F5 probes reproduced the parse errors using the collector's exact headers.
The explicit Juniper canonical target was also fetched with those headers.
No authentication, challenge execution, proxy or hosted collection was used.

| Vendor | Run failures | Recorded category | Finding and comparison relevance |
| --- | ---: | --- | --- |
| Arista | 8 | Unsupported extraction | SA-0015 and SA-0017 through SA-0023 have explicit initial revision dates in 2015–2016. Their legacy layouts are extraction gaps, but their initial disclosures lie outside the study's 2021+ window. This does not establish current platform applicability. |
| Palo Alto | 2 | Unsupported extraction | One no-CVE informational bulletin and one CVE-bearing non-impact bulletin need different handling. Neither is evidence of newly affected products. |
| Juniper | 1 | Unsupported/invalid document | The component-reference URL redirects to the same documentation path at `networkingdocs.hpe.com`. Current Juniper policy rejects that host. The existing component hook accepts the fetched target bytes at the original binding and returns an OpenSSH 9.4 reference. This is component-version context, not CVE affectedness. |
| Check Point | 4 | Access verification required | The run retained interactive-access failures for two support articles and two downloads. No bypass was attempted. |
| Fortinet | 1 | Publisher scope unavailable | The retrieved CSAF envelope has zero vulnerability entries. The current guard correctly refuses to invent CVEs or product scope. |
| F5 | 1 | Unsupported extraction | The evaluated-product fingerprint still matches, while critical-scope and guidance fingerprints changed. The reviewed PDF profile requires source review before accepting new facts. |

Totals: **12 unsupported extraction/scope checks, four access challenges and
one publisher-scope-unavailable envelope**. Every failure is accounted for.

## Source-specific findings

### Arista chronology

The revision tables identify initial releases as follows. Later document-header
dates are not substituted for those initial dates.

| Advisory | Initial revision date | Primary source |
| --- | --- | --- |
| SA-0015 | 2015-11-18 | [Advisory](https://www.arista.com/en/support/advisories-notices/security-advisory/1221-security-advisory-15) |
| SA-0017 | 2016-02-16 | [Advisory](https://www.arista.com/en/support/advisories-notices/security-advisory/1255-security-advisory-17) |
| SA-0018 | 2016-03-01 | [Advisory](https://www.arista.com/en/support/advisories-notices/security-advisory/1260-security-advisory-18) |
| SA-0019 | 2016-05-03 | [Advisory](https://www.arista.com/en/support/advisories-notices/security-advisory/1332-security-advisory-19) |
| SA-0020 | 2016-05-06 | [Advisory](https://www.arista.com/en/support/advisories-notices/security-advisory/1334-security-advisory-20) |
| SA-0021 | 2016-06-13 | [Advisory](https://www.arista.com/en/support/advisories-notices/security-advisory/1354-security-advisory-21) |
| SA-0022 | 2016-06-15 | [Advisory](https://www.arista.com/en/support/advisories-notices/security-advisory/1356-security-advisory-22) |
| SA-0023 | 2016-08-15 | [Advisory](https://www.arista.com/en/support/advisories-notices/security-advisory/1461-security-advisory-23) |

These sources are useful for broader history. Supporting them solely to reduce
the displayed error count would not add 2021+ initial disclosures to this study.

### Palo Alto informational scope

[PAN-SA-2021-0002](https://security.paloaltonetworks.com/PAN-SA-2021-0002)
describes NAT-slipstreaming protection, has no literal CVE identifier, and says
a PAN-OS software upgrade is not required for mitigation. A positive no-CVE
informational route needs its own reviewed identity and semantics.

[PAN-SA-2023-0003](https://security.paloaltonetworks.com/PAN-SA-2023-0003)
discusses three MOVEit CVEs and explicitly reports non-impact for Palo Alto
products. A future repair must preserve that CVE-bearing, unaffected scope;
it must not classify every informational title as a no-CVE notice or infer
affectedness from references to another vendor's product.

### Juniper documentation migration

The [configured Juniper URL](https://www.juniper.net/documentation/us/en/software/junos/release-notes/24.2/junos-evo-release-notes-24.2r1/topics/new-features/feature-descriptions/authentication-access-control.html)
returned a 301 to the [exact HPE-hosted canonical page](https://networkingdocs.hpe.com/documentation/us/en/software/junos/release-notes/24.2/junos-evo-release-notes-24.2r1/topics/new-features/feature-descriptions/authentication-access-control.html),
which returned 200. The target currently fails the Juniper source policy.
The correct `parse_component_inventory` hook accepts its bytes using the
original source binding; the ordinary advisory parser is not the correct test
for this release-document source.

A repair should review the exact canonical route, retain HTTPS/host/path
boundaries and test the redirect chain. Broadly trusting HPE domains for all
Juniper inputs or disabling redirect validation is not justified by this probe.
No source policy was changed in this audit.

### F5 scope guard

The current [K000163821 PDF](https://my.f5.com/manage/MyF5_KnowledgeArticlePDF?article=K000163821)
still has the reviewed advisory title for CVE-2026-109618 and CVE-2026-109619.
Its evaluated-product section matches the reviewed fingerprint, but critical
scope and subsequent guidance do not. A fingerprint mismatch establishes changed
text, not which product/version facts changed; the previous text is needed for
a complete semantic diff. No profile hash was refreshed or validator weakened.

The PDF also mentions CVE-2026-115560 in a related-article link. That mention is
outside the advisory-title scope and must not create an additional assessment.

### Access and missing publisher data

The four [Check Point sources](2026-11-05-post010-failure-triage.csv) remain
recorded access challenges. The three source-missing benchmark cases concern
CVE-2024-6387 and CVE-2023-48795. Authorized access or an explicit official
alternative is needed; changing parser rules cannot supply missing bytes.

The [Fortinet CSAF envelope](https://filestore.fortinet.com/fortiguard/psirt/csaf_multiple-node-js-cves_fg-ir-26-187.json)
has no vulnerability entries in the fresh capture. Retain its explicit missing
scope and use ordinary future checks; an empty envelope is not proof of no impact.

## Aruba and Cisco comparison gaps are separate measures

Aruba's 17 unsupported 2021 documents are from the separate opt-in public stage,
not this hosted run. All 19 retained stage documents were rechecked without
network access. Three fail signed-message framing, 12 fail the reviewed section
layout, one fails header continuation and one has ambiguous header CVE scope.
The two supported documents contain explicit AOS-CX text. A lexical search found
no explicit AOS-CX name in the other 17; several name AirWave, ClearPass, Instant,
ArubaOS or SD-WAN. This is a triage lead only: it does not prove absence of CX
impact, exhaustive aliases, complete archive coverage or applicability to the
6300M/6410 models. The original stage retrieval metadata remains separate from
fresh probes in this audit.

Cisco's public audit shows an RSS sample limit of four from a retained 50-entry
response, with no configured archive. Its absence from the failure list does
not establish IOS XE history. The existing optional openVuln integration needs
an authorized authenticated run; none was attempted here. Aruba and Arista also
retain bounded discovery windows, not verified complete vendor histories.

## Prioritized follow-up

1. Establish **2021+ target-family coverage**: enable a separately approved Cisco
   history run when credentials are available; design bounded official-CVE
   reference reconciliation to identify missing IOS XE, AOS-CX and EOS advisories.
   Check newer published Aruba/EOS archives before assuming that all remaining
   2021 layout work advances the selected switching comparison.
2. Review the **current F5 critical/guidance revision** and the **exact Juniper
   canonical route** as small, source-backed repairs. Preserve scope guards,
   component-versus-affectedness distinctions and source provenance.
3. Build the already selected **product/train release and hotfix inventory**.
   Count documented remediation publications/bundles separately from CVEs and
   real customer maintenance windows; do not derive release dates from version
   strings or infer silent security fixes from version changes alone.
4. Extend historical Arista/Aruba and Palo Alto layouts with reviewed source
   patterns. Keep access-blocked and empty-scope sources visible. Broader archive
   coverage remains useful even when it does not change this study's period.
5. Keep the maintainer's human evidence review pending. No error count, CVE total,
   absent notice or Glasswing context establishes relative security or concealment.

This audit changed no parser, schema, source default, credential, hosted setting,
schedule, workflow permission, release tag or runtime pin. Raw captures remain
outside Git; the public tables contain source metadata and research conclusions.
