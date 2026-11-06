# CVE research dossiers

Open **Case files** to read a dossier for the current CVE cohort and vendor
selection. When several supported CVEs are selected, **CVE dossier** chooses the
one displayed. **Download selected dossier JSON** saves that dossier with its
selected scope, publication ID, generation time, source references and limits.
The original case files remain expandable below it.

The initial retrospective, purposively selected scope is:

| CVE | Declared comparison targets | Disclosure context |
| --- | --- | --- |
| CVE-2024-6387 | Arista EOS 4.32.2F and Aruba AOS-CX 10.13.1031; SSH management on switching platforms | Aruba release-date and HPE Cray OpenSSH cases |
| CVE-2023-38545 | No comparable build cohort declared | FortiProxy curl case |
| CVE-2023-38546 | No comparable build cohort declared | FortiProxy curl case |

HPE Cray is disclosure context only. It is not a switching comparison target.
The curl CVEs are separately selectable; a shared bulletin is not an independent
second observation. Other CVEs and empty selections show no dossier, which makes
no exposure or disclosure claim. Selecting a vendor keeps only its relevant
comparison rows, disclosure context and source references, while declared scope
remains visible. Older publications without the report display an unavailable
state; they never borrow newer evidence.

## Reading evidence and unknowns

Comparison evidence preserves literal products, build expressions, prerequisites,
fixes and assessment branches. A fixed-only statement does not establish prior
affectedness. Unknown fields, missing locators and missing exact retained
statements remain explicit. The evidence-gap list describes what artifact or
review could resolve a question. Source access success does not establish
historical release availability, shipped contents or applicable configuration.

Chronology has three separate sections:

- **Publisher date claims** retain the publisher's literal values and precision.
  A date is still a date; a local datetime with unspecified timezone gains no UTC
  precision. These claims do not establish earliest disclosure.
- **Local observations** describe collector events, source revisions and parser
  reinterpretations using their original classifications. A capture timestamp is
  evidence of observation, not a publisher disclosure timestamp.
- **Publisher documentation history** contains publisher-reported changes. It
  is not independently observed disclosure history.

Disclosure context includes earlier-document counter-evidence, source-bound
assistant dispositions, alternative explanations and unresolved questions.
Assistant research does not constitute independent human review.

## Reproducibility and routes

The public report is rebuilt from sanitized retained evidence at publication.
It is available within `research_dossiers` in `/api/state` and `/snapshot.json`,
as `/research-dossiers.json`, and through the read-only
`/api/v1/research-dossiers` endpoint. For example:

```text
/api/v1/research-dossiers?cves=CVE-2024-6387&vendor=hpe
/api/v1/research-dossiers?cves=CVE-2023-38545,CVE-2023-38546
```

Omitting CVEs on this report endpoint returns the declared dossier scope.
Unknown/repeated vendors and malformed CVE controls return a bad request. A native
reader serving an older generation without the report returns 404 with
`Report unavailable for this generation`.

The contracts are `/schemas/research-dossiers-v1.json` and
`/schemas/research-dossier-definition-v1.json`. The bundled definition binds exact
CVE, existing target and case IDs; its version and canonical SHA-256 identify the
scope used. Expand **Source fingerprints and definition identity** for that
identity and each retained source's URL, SHA-256, locators, capture observations,
parser and revision identity when supplied. Different URLs or matching dates do
not establish source independence. The manifest fingerprints exported files;
publication ID and generation time bind the report and downloads to their
containing generation. Static delivery uses that generation's content-addressed
parts, with the same selection policy as the native reader.

## Fixed limits

For this increment, `inventory_verified`, `independent_human_review_completed`,
`independent_release_availability_verified`, `earliest_disclosure_established`
and `concealment_established` are always `false`. `vendor_rate` and
`verified_fix_delay_days` are always `null`. No ranking, verified delay, earliest
disclosure or intent conclusion is calculated. These gates cannot be unlocked by
a download or an operator-supplied report.

This feature imports no private inventory evidence, firmware, SBOM or device
export. It does not change the frozen OpenSSH study, extraction-review packet or
product-cohort enrollment. See [inventory preparation](BUILD_INVENTORY.md) and
[disclosure research](DISCLOSURE_RESEARCH.md) for the existing evidence workflows.
A fresh manual publication is not evidence of scheduled observation or unattended
service reliability. Retained observations remain subject to freshness, source
coverage and scheduler limitations.
