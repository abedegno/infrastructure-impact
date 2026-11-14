# Disclosure timing research

A component CVE does not prove product exploitability. A firmware date preceding
an advisory does not prove that the firmware was publicly available then, that no
earlier disclosure existed, or that a vendor intended to hide a fix.

## Retained release-note revisions

Configured release documents retain their raw fingerprints and parsed text in the
private vault. Successive observations record added/removed CVE references and
new security language, with before/after evidence IDs and capture times. Reversions
(A → B → A) remain observations; repeating an identical state is idempotent.
Capture times bound what this collector saw, not the publisher's first disclosure.
Only signals tied to configured public release sources cross the publication boundary.

## Availability observations and review

A fix candidate needs product/version/CVE linkage and a separate release-availability
observation. Record the exact source locator and classify the evidence:

- `publisher_date_claim`: a date asserted in a bulletin; insufficient alone.
- `public_release_listing`: a reviewed public listing with release metadata.
- `observed_download`: a reviewed availability observation, with a defensible date.

Example workflow, substituting actual retained IDs and reviewed facts:

```sh
impact research release-observation --evidence-id 101 --vendor arista --product 'Example router' --version 1.1 --released-at 2025-01-01 --kind public_release_listing --locator 'Version 1.1 row in dated release listing'
impact research review-fix 7 --status verified --observation-id 3 --earlier-disclosure-search 'Describe official archive, related advisories and release notes searched, including gaps' --note 'Explain the specific product/version/CVE linkage and date basis'
```

The review gate rejects a bare publisher date, a mismatched product/version/date,
missing search history, and the same source URL or bytes reused as independent
release/link evidence. A human or reviewer must still judge whether distinct
sources are truly independent and whether a listing proves availability on the
claimed date. Verification means the recorded evidence passed review; intent and
absence of all earlier disclosures remain unestablished.

The HPE Cray timing lead remains unresolved. Its date claim has not been promoted
to an independently verified release-availability finding. No confirmed concealment
finding is published.

The [26 October pilot](research/disclosure-pilot-20261026.md) records all three
initial investigations and counter-evidence. `publisher-history.json` projects
reviewed documentation change-log entries, including exact source hashes and
row locators. These retrospective entries remain separate from locally observed
revision diffs. The `parse_document_history` vendor hook is optional and pure;
unsupported/changed layouts remain visible. Only configured public release sources
cross the publication boundary. The common contract is
`schemas/publisher-history-v1.json`.

## Investigation queue

The **Disclosure review** view turns eligible fix leads into source-linked tasks.
The older **Disclosure signals** view retains the underlying revision signals.
`/api/v1/disclosure-review` and static `/disclosure-review.json` use
`schemas/disclosure-review-v1.json` and carry the publication generation. The
public projection rebuilds them without copying private notes or review state.

Each task requests exact product/build/CVE linkage, independent release
availability, an earlier-disclosure search including access gaps, historical
document availability, and independent adjudication. All five gates remain
unestablished by this queue. Reviewed availability decisions remain in the
separate private candidate workflow above; this queue does not certify or alter
them, or modify the original independent extraction-review packet.

Related case files require the same vendor, overlapping CVE IDs and an exact
source URL in common. Earlier documents must also reference a lead CVE. Their
publisher dates remain claims, not verified historical availability. Tasks with
counter-evidence direct the reviewer to inspect it first. Component changes and
security wording without CVEs direct the reviewer to establish purpose and scope;
other chronology leads request availability and disclosure evidence. These are
review actions, not suspicion or severity scores.

A component-change task without established CVE linkage keeps an empty CVE list.
No upstream version-range match invents that linkage. Alternative explanations
remain visible. Absence of a task does not establish absence of undocumented
security fixes, and the queue never labels an update as a concealed fix.

Dated [pilot dispositions](research/build-and-disclosure-pilot-20261027.md) now
appear in each matching task. They are assistant research results, not independent
adjudication. The complete reviewed source URL/hash set must match the current
lead. A changed source requests re-review and suppresses the earlier disposition;
new sources, new CVEs or another bug number cannot inherit a prior result. The
five independent evidence gates and concealment state remain unchanged.

See [CVE research dossiers](RESEARCH_DOSSIERS.md) for the initial curated scope,
strict report and definition schemas, selected JSON downloads, chronology meanings
and fixed research limits.

### Explicit Arista paired chronology staging

The offline helper can repair an existing, caller-selected public staging database:

```sh
export IMPACT_HOME=/tmp/impact-arista-staging
export IMPACT_SOURCES="$PWD/infrastructure_impact/resources/sources.json"
export PYTHONPATH="$PWD"
.venv/bin/python -m infrastructure_impact.application.arista_chronology_repair \
  --manifest /tmp/impact-arista-staging/source-manifest.json \
  --database /tmp/impact-arista-staging/staging.sqlite --staging \
  --output-json /tmp/impact-arista-staging/repair.json \
  --output-csv /tmp/impact-arista-staging/repair.csv
```

The database must already contain the exact current primary URL and CSAF bytes
for each corrected advisory. Receipt verification and all primary ownership
checks precede writes. Without `--staging`, an explicit database must still be
absent. Neither mode opens default storage. The helper retains exact paired HTML,
CSAF and optional RSS captures with their supplied receipt times; existing source
capture times remain intact. Repeated identical repair adds no advisory revision.

Ordinary ingest and normalization maintenance revalidate accepted chronology
against these retained bytes without fetching. Changed primary bytes, URL,
identity or CVE scope, incompatible proof, or missing secondary bytes require
review: ingest raises `chronology_unresolved_requires_review`, and maintenance
reports that error code while preserving the previous revision. Rejection does
not establish the current truth of the old source. An operator must review and
explicitly repair a new pair before accepting a replacement chronology.

After review, create a local export using the same explicit staging database:

```sh
IMPACT_DATABASE=/tmp/impact-arista-staging/staging.sqlite \
  .venv/bin/python -m infrastructure_impact.cli snapshot \
  --output /tmp/impact-arista-staging/site --publication-format v2
.venv/bin/python -m infrastructure_impact.cli publication-export \
  --publication /tmp/impact-arista-staging/publications/current \
  --root switching-evidence.json \
  --output /tmp/impact-arista-staging/switching-evidence.json
```

This creates local artifacts only. Hosted activation and independent human
review remain separate operational steps; source-shaped test fixtures do not
constitute historical capture validation.
