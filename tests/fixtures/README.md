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
