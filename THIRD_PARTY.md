# Third-party material and collected data

The Apache-2.0 license applies to original project code, documentation and synthetic
test inputs. It does not grant rights in collected vendor advisories, PDFs, release
notes, firmware, trademarks or third-party dependencies.

## Test inputs

`tests/fixtures/` contains project-authored synthetic inputs. They retain selected
product/CVE identifiers and literal format markers needed to exercise the parsers,
but are not captured vendor documents or evidence of real product exposure.
`checks/generate_fixtures.py` rebuilds them; `manifest.json` records their hashes.
The tiny PDF is authored by that generator without a bundled publisher attachment.

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

## Dependencies

Python and JavaScript dependencies are declared and locked in the project. Their
individual licenses and notices continue to apply. The runtime container also
installs Poppler and operating-system packages; retain their license information
when distributing images. This repository does not vendor their implementations.
