# Synthetic parser fixtures

These are small project-authored test inputs, not captured vendor advisories.
Names, CVE identifiers, versions and literal parser markers exercise scope and
normalization regressions. They must not be used as evidence of real product impact
or disclosure dates. Original full vendor captures are not distributed here.

Rebuild with `uv run python checks/generate_fixtures.py`. The generator also writes
`manifest.json` with SHA-256 fingerprints; `checks/release.py` validates them when
preparing a public source tree. The PDF is a tiny original document authored by the
generator. All inputs are covered by the project's Apache-2.0 license, subject to
the third-party identifier/marker explanation in `THIRD_PARTY.md`.

`kev-valid.json` is a project-authored, two-entry synthetic KEV catalogue.
It tests imported and outside-scope CVE membership, optional publisher fields,
and raw-only extra fields. Its dates, products, actions and exploitation context
are invented test data. It is maintained directly; the generator preserves it
and includes its SHA-256 fingerprint when rebuilding the manifest.

`kev-selection-cases.json` is a project-authored synthetic v1 KEV report and
shared Python/JavaScript selection cases. Its publication identity, publisher
metadata, times and membership claims are invented. Cases exercise retained
historical context, legacy absence, strict CVE joins and verification freshness;
they are not evidence of exploitation or product impact. It is maintained
directly and fingerprinted by the fixture manifest generator.

`switching-arista-bridge.json` is generated from project-authored minimal HTML and
invented normalized adapter outputs. It exercises the switching bridge's strict
reviewed-core boundary with an explicit normalizer stub; it does not claim those
synthetic bodies are supported real advisories. Actual core-parser/bridge source
replays and retrieval receipts remain only in the ignored private workspace.
Production route identifiers and selected parser markers are retained to test
routing, literal metadata, scope separation and rejection behavior.

`switching-cases.json` contains project-authored evidence and shared Python/browser
comparison cases. The cases, scores, dates, publisher metadata and availability
claims are invented. Its frozen-resource digests are integrity assertions, not
vendor source evidence. It is maintained directly and fingerprinted by the fixture
manifest generator. Real source-led review expectations are metadata in the separate
switching-extraction-review resource; synthetic CI results never count as passes
for those retained primary-source cases.

`switching-release-history-vectors.json` contains project-authored study selections
and 14 release-history vectors shared by Python and JavaScript. Dates, releases, claims
and source availability are synthetic contract examples, not publisher captures or
evidence of real vendor impact. It is maintained directly and fingerprinted by the
fixture manifest generator.

`target-import-candidate.json` contains minimal project-authored Cisco CSAF and
Aruba bulletin strings for exact-import stage and installed-wheel checks. Advisory
route shapes and literal parser markers exercise dispatch; all vulnerability,
version, timestamp and applicability content is synthetic. It is maintained
directly and preserved/fingerprinted by the generator. It contains no retained
vendor capture and does not certify real-source acquisition or hosted acceptance.
