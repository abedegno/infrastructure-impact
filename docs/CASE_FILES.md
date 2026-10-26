# Disclosure research case files

Case files are evidence-linked questions, with separate exposure and chronology
sections. They do not classify an inaccessible source as hidden exposure or a
reported earlier date as concealment. The initial cases remain `incomplete_evidence`:

- HPE Cray / CVE-2024-6387: a 70-day difference between two date claims in one
  bulletin, without independent historic availability or earlier-disclosure proof.
- Aruba AOS-CX / CVE-2024-6387: a fixed-version leaf is retained, but the selected
  release-history date and hardware linkage remain unresolved.
- FortiProxy 7.2.8 / curl: a documented fix, without an independently established
  release chronology; prior-version affectedness is not inferred from that fix.

`resources/disclosure-cases.json` defines product scope, official advisory URLs,
release-source leads, missing evidence and alternative explanations. The strict
`schemas/disclosure-case-definition-v1.json` contract rejects extra fields and
unofficial source URLs. Case IDs must be unique. Initial review was performed by
an automated assistant; independent human adjudication remains outstanding.

The application attaches only matching retained publisher records, hashes,
evidence IDs, source check metadata and bounded timeline event IDs. An optional
exact `claim_context` selector keeps a fixed branch separate from other branches.
Source leads are not promoted to retained or verified release evidence. Browser
captures and private reviewer notes are excluded from public case files.

Exposure summaries use publisher product statements for the selected CVEs. The
case's `cve_ids` preserve shared-document context; `selected_cve_ids` and
`exposure.by_cve` identify the current selection. API and browser filtering must
not transfer one CVE's status to another CVE in the same case. Date gaps preserve
the document-level basis and do not establish notification time or first disclosure.

View Case files in the dashboard, download `casefiles.json`, or query the self-hosted
`/api/v1/casefiles?cves=CVE-2024-6387&vendor=hpe` endpoint. Static and API metadata
include immutable publication IDs. GitHub Pages has no Python API backend.

The existing private research workflow can register independent availability and
CVE/product-link evidence and review candidates. Publication of a reviewed case
conclusion requires a separately reviewed evidence projection; these initial files
do not automatically verify a fix, register a candidate, or infer intent. See
[DISCLOSURE_RESEARCH.md](DISCLOSURE_RESEARCH.md).
