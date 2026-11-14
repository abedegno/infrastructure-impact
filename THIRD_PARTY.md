# Third-party material and collected data

The Apache-2.0 license applies to original project code, documentation and synthetic
test inputs. It does not grant rights in collected vendor advisories, PDFs, release
notes, firmware, trademarks or third-party dependencies.

## Test inputs

`tests/fixtures/` contains project-authored synthetic inputs. They retain selected
product/CVE identifiers and literal format markers needed to exercise the parsers,
but are not captured vendor documents or evidence of real product exposure.
`checks/generate_fixtures.py` rebuilds generated examples and fingerprints the
manually maintained authored examples; `manifest.json` records their hashes.
The tiny PDF is authored by that generator without a bundled publisher attachment.
The chronology, model-note and disclosure examples are authored test inputs, not
vendor reproductions. Test-scoped receipt overrides refer only to their authored
bytes; actual source-pinned replay evidence remains external to Git.

Captured vendor fixtures from development are retained only in the ignored private
workspace. Do not add full source captures, logos, embedded scripts or CMS responses
to the public repository. A proposed non-synthetic fixture needs documented origin,
applicable redistribution permission and a review of its contents before inclusion.

## Runtime sources and generated datasets

Collectors retrieve public official sources at the operator's direction. Their
terms, notices and access limits still apply. Preserve source URLs, timestamps and
hashes. Do not circumvent authentication or access controls. A blocked or incomplete
source must remain a visible coverage gap.

Raw collection, normalized records and exports are not automatically offered under
the source-code license. Before redistributing a dataset, review the included
source material and its terms. Keep private notes and correction evidence out of
public exports. A schema-valid record does not establish truth or completeness.

## CISA Known Exploited Vulnerabilities catalogue

The default KEV source retrieves the [CISA-maintained JSON mirror](https://github.com/cisagov/kev-data)
under its [CC0 1.0 dedication](https://github.com/cisagov/kev-data/blob/develop/LICENSE).
Attribute catalogue fields to [CISA's KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
The mirror retrieval URL, retained raw-content SHA-256, source-observed and parsed
times, latest check and catalogue version remain distinct provenance fields. The
application retains a complete membership index and only scoped detailed entries
in public reports; raw captures remain private. See [KEV semantics](docs/cisa-kev.md)
for freshness, history and non-inference limits.

## Dependencies

Python and JavaScript dependencies are declared and locked in the project. Their
individual licenses and notices continue to apply. The runtime container also
installs Poppler and operating-system packages; retain their license information
when distributing images. This repository does not vendor their implementations.

The compiled study-schema validator uses [`jsonschema-rs`](https://pypi.org/project/jsonschema-rs/0.60.3/),
pinned to version 0.60.3, under its [MIT license](https://github.com/Stranger6667/jsonschema/blob/master/LICENSE).

## Reviewed Cisco switching analysis profile

`infrastructure_impact/resources/switching-analysis/campus-switching-openvuln-2026-11-14-v1.json`
contains reviewed, derived public Cisco OpenVuln metadata and the public
[Cisco risk-based disclosure policy](https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure)
receipt. The 59 IOS XE release-query frames retain all 1,800 advisory contexts,
including unresolved ownership, empty first-fixed values and ordering caveats.
Each source URL, SHA-256, capture time and parser revision is preserved. Only
workspace-local `source.evidence_id` references were removed before packaging.
The profile does not include API response bodies, credentials or local datasets.
Cisco's source terms and rights continue to apply; the project license does not
grant rights in Cisco source material. This metadata is publication configuration,
not evidence of product ownership, exposure or security quality. Human review
remains pending, and a first-fixed API observation is not a CVE or patch count.
