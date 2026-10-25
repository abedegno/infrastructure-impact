# Preparing a public source release

Use a clean source tree, not the maintainer's research workspace. The workspace may
contain a private vault, captured vendor fixtures, Sites source history, local
scheduler files, screenshots and deployment receipts. `.gitignore` is a safeguard,
not evidence that an arbitrary archive is safe to publish.

## Prepare and verify

1. Run the README development checks. Rebuild synthetic fixtures if their generator
   changed: `uv run python checks/generate_fixtures.py`.
2. Run `uv run python checks/release.py`. It creates a new
   `release/infrastructure-impact` directory from an explicit allowlist and refuses
   to overwrite an existing destination. Use `--output PATH` for another location.
3. Inspect its file manifest and rerun checks **from that clean tree** with a fresh
   environment. The public tests must not depend on a research vault. Build the
   wheel and container there; inspect the wheel's included license files.
4. Check README links, the license/data policy, changelog, source configuration and
   any release-specific limitations. The release checker catches selected artifact
   and credential patterns; review is still required before publication.
5. Initialize a new Git repository on `main` in the clean tree and review the staged
   contents. Do not copy the nested private Sites Git history or push the research
   workspace wholesale.

No GitHub repository or package-registry account is assumed by the source. Choose
the owner/organization and repository name before adding a remote. The current
suggested repository name is `infrastructure-impact`.

## GitHub repository settings

After creating the repository, enable private vulnerability reporting, dependency
alerts and the quality workflow. Require a passing quality workflow and review on
the default branch as appropriate for the maintainer team. Verify that security
reports can be submitted through the channel documented in `SECURITY.md`.
The checked-in workflow uses read-only repository permissions and does not publish
packages, images or sites. Dependabot proposes dependency updates monthly.

When updating Python dependencies, run `uv lock`, then regenerate both Docker
exports and review their changes:

```sh
uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file requirements.lock
uv export --frozen --only-group build --no-emit-project --format requirements-txt --output-file requirements-build.lock
```

CI checks those exports for drift. Dependency and base-image updates require the
same compatibility checks as other code changes.

## Versioned releases

Before tagging, update the package version, lock file, image references and
changelog consistently. Build from the reviewed commit, record image digests and
checksums, and preserve license/notice metadata. The included 0.3.0 source version
is not a claim that a GitHub, PyPI or container-registry release already exists.

Public service/data publication is separate from source release. Do not publish a
collected dataset, raw vendor material, private correction evidence or a previously
private site merely because the source repository is public.
