# Source releases and evidence publications

A source release identifies code, schemas, tests and bundled source configuration.
An evidence publication has a separate generation ID and file hashes. Scheduled
collection can update that dataset without changing the source release. Record
both identities when reporting a result or an extraction problem.

## Verify a candidate

Use a clean checkout rather than a private research workspace, and the locked
development, build and hosted dependencies. Git ignore rules alone do not prove
an arbitrary archive is safe to publish.

```sh
uv sync --frozen --group build --group hosted
uv run --frozen pytest -q
npm ci --ignore-scripts
npm run format:check
uv run --frozen python checks/release.py --output ../infrastructure-impact-reviewed
uv run --frozen --group build python -m build --wheel --no-isolation
uv run --frozen python checks/distribution.py
```

The export command requires a new output directory. It copies an explicit public
source allowlist, verifies synthetic fixtures and checks for private artifacts.
The distribution probe installs the wheel and an external vendor plugin outside
the checkout, then exercises its schema, archive, component-reference, database,
publication and API boundaries. CI additionally runs the declared lint/format
checks, supported Python versions and the reader container.

Inspect the export's manifest and repeat checks from that clean tree in a fresh
environment before building distributable assets. Public tests must work without
a research vault. If the synthetic-fixture generator changed, regenerate fixtures
with `uv run --frozen python checks/generate_fixtures.py` and review their manifest.
Check README links, the license/data policy, changelog, source configuration and
release-specific limits. Inspect the wheel's license/notice files. The source
checker covers selected artifact and credential patterns; review remains required.

Inspect the candidate's diff and the exact CI commit. Verify that root and installed
source configurations agree. Preserve a locally customized `sources.json`; its
private choices do not belong in a source release. Data interpretation changes
need source-led examples and tests for the scope they claim to support. The
original human-review packet remains frozen unless a new packet is deliberately
created; green software checks do not complete that review.

Direct remote workflow actions are pinned to full commits. Review dependency PRs
against their upstream changes, and synchronize `deploy/github-public-service.yaml`
with `.github/workflows/collect.yaml` when updating that workflow. Their byte-parity
check prevents a deployment example from silently retaining older protections.

## Publish the source release

Tag the verified commit without moving an existing release tag. Use the package
version from `pyproject.toml`, and state the research-preview status and known
coverage limits in its release notes. A wheel and its SHA-256 checksum file may
accompany the public source tag. A source release does not certify a complete
vendor portfolio, comparative security rate, first disclosure or fix availability.

Keep private vaults, captures, encryption keys, review submissions and operator
receipts out of release assets. Recovery drafts have tags beginning
`collector-recovery-`; leave them unpublished. Recovery deliberately requires
that draft status and uses its own encrypted-asset manifest, independently of
ordinary source releases.

Keep package version, lock metadata, applicable image references and changelog
consistent when changing a version. Build from the reviewed commit and retain
checksums and any published image digests. A source tag does not imply a PyPI or
container-registry publication.

## Repository settings and dependency changes

For a public repository, configure private vulnerability reporting and dependency
alerts, and check that the contact route in `SECURITY.md` works. Apply passing-CI
and review requirements appropriate to the maintainer team. The quality and
monitor jobs use read-only repository permissions; collection has the separate
write permissions needed for its reviewed recovery and Pages workflow.

When changing Python dependencies, run `uv lock`, regenerate both Docker exports,
and review their diffs:

```sh
uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file requirements.lock
uv export --frozen --only-group build --no-emit-project --format requirements-txt --output-file requirements-build.lock
```

CI checks those exports for drift. Dependency and base-image updates require the
same compatibility checks as other code changes.

## Activate a collector revision

After the exact source commit passes CI, set `IMPACT_SOURCE_COMMIT` to its full SHA.
Use a controlled collection when runtime behavior or source configuration changes.
Check the resulting public manifest, source failures, recovery readback receipt and
monitor report. The hosted runner collects its own public sources; do not seed it
with an existing private native vault.

When a stricter monitor requires a newly deployed asset, stage that transition:
publish the asset with compatible collector code, verify the public output, then
activate the new monitor revision. Keep the runtime pin deliberate during rollout.

For an explicitly needed normalization refresh, follow
[Normalization maintenance](NORMALIZATION_MAINTENANCE.md), inspect its partial
failures and interpretation changes, and reset `IMPACT_REPARSE_LIMIT` to `0` after
the controlled run. An offline correction is not a new source retrieval or proof
of a publisher's disclosure timing. A documentation-only release can keep the
last verified runtime pin when its executable source and configuration are equal.

Read [Hosted service](HOSTED_SERVICE.md), [Draft recovery](DRAFT_RECOVERY.md) and
[Operations](OPERATIONS.md) for capacity bounds, schedules and reliability-review
requirements. Manual workflow success does not satisfy an elapsed observation
window or independent human review.

The distribution checker selects exactly one wheel matching the declared package
version and verifies the installed distribution version. Older files in `dist/`
cannot silently substitute for a newly declared release. Ambiguous current-version
wheels require an explicit clean build directory.
