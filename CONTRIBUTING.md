# Contributing

Contributions are welcome, particularly vendor adapters, extraction regressions,
coverage improvements and documentation. Start with the [README](README.md),
[architecture](docs/ARCHITECTURE.md) and [plugin contract](docs/PLUGINS.md).

## Development workflow

1. Install Python 3.11+, uv, Node.js/npm and Poppler (`pdftotext`).
2. Run `uv sync --frozen --group build --group hosted` and `npm ci --ignore-scripts`.
3. Make a focused change with an offline regression case where behavior changes.
4. Run the checks in the README. Test installed packages when changing resources,
   entry points, packaging or plugin contracts.
5. Open a pull request explaining the problem, resulting behavior, validation and
   any coverage limits. Use the provided PR template.

The runtime package is `infrastructure_impact/`. Root service scripts preserve
workspace compatibility; do not create duplicate business logic there. The
historical `impact.py` importer is outside the production package.

## Vendor and evidence contributions

Keep parsers pure, vendor-specific behavior in plugins, database writes in the
writer/repository path, and serving read-only. Unknown layouts must fail visibly.
Preserve CVE/product/platform/version/configuration boundaries, source locators,
shared-bulletin scope and publisher date precision. Distinguish planned fixes,
partial mitigations and reported fixes. Parser changes must not manufacture
publisher disclosure alerts. Follow the plugin guide's acceptance criteria.

Use small synthetic fixtures. See [THIRD_PARTY.md](THIRD_PARTY.md) before proposing
third-party content. Never commit credentials, full captures, databases, generated
publications, backups, private reviews or machine-specific configuration. A
correction should cite an official source and describe the precise claim to amend;
missing data is not an unaffected or concealment finding.

For exact-build component evidence, start with the [inventory proposal workflow](docs/BUILD_INVENTORY.md). Keep the proposal and evidence local until rights and scope have been reviewed. A successful byte audit does not certify the proposed inventory.

## Contracts and migrations

Core field changes need schema, API, documentation and compatibility review.
Breaking contracts require a version/migration plan. SQL migrations are append-only;
never edit an applied migration. Preserve retained evidence and distinguish source
changes from re-normalization.

## Contribution terms and conduct

Submit only material you have the right to contribute. Unless explicitly stated
otherwise, intentional contributions are under Apache-2.0, as described by that
license's contribution terms. There is no additional CLA or sign-off requirement.
Dependencies and third-party material keep their own licenses.

Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). For a vulnerability in this project,
follow [SECURITY.md](SECURITY.md) rather than posting exploit details publicly.
