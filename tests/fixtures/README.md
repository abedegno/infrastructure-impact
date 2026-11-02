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
