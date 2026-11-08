"""Exact import shipping and CI coverage are explicit release contracts."""

from pathlib import Path

from checks import distribution, release

ROOT = Path(__file__).resolve().parents[1]
NEW_MODULES = (
    "infrastructure_impact/application/import_candidate.py",
    "infrastructure_impact/application/target_import.py",
    "infrastructure_impact/application/target_import_contracts.py",
    "infrastructure_impact/application/target_import_stage.py",
    "infrastructure_impact/collection/maintenance_operations.py",
    "infrastructure_impact/collection/target_import_profiles.py",
    "infrastructure_impact/collection/transport_budget.py",
    "infrastructure_impact/storage/checkpoint_copy.py",
    "ops/target_import_job.py",
)


def test_new_production_modules_are_in_public_release_allowlist():
    for name in NEW_MODULES:
        assert (ROOT / name).is_file()
        assert name in release.FILES or any(
            name.startswith(directory + "/") for directory in release.DIRECTORIES
        ), name


def test_exact_import_resources_and_monitor_pair_have_installed_hash_probes():
    resources = distribution.public_resource_fingerprints(ROOT)
    for name in (
        "resources/target-imports/campus-switching-public-gap-2026-11-07-v1.json",
        "schemas/target-import-manifest-v1.json",
        "schemas/target-import-preview-v1.json",
        "schemas/target-import-result-v1.json",
        "_standalone/public_health.py",
        "_standalone/switching_health.py",
    ):
        assert name in resources, name


def test_exact_import_test_modules_have_explicit_ci_lint_and_format_coverage():
    commands = [
        line.strip().removeprefix("- run: ")
        for line in (ROOT / ".github/workflows/ci.yaml").read_text().splitlines()
        if "uv run ruff " in line
    ]
    assert len(commands) == 2
    tests = sorted(ROOT.glob("tests/test_target_import_*.py")) + [
        ROOT / "tests/test_hosted_target_import.py"
    ]
    for command in commands:
        for path in tests:
            assert str(path.relative_to(ROOT)) in command.split(), path.name


def test_public_fixture_inventory_includes_authored_candidate():
    release.fixture_check(ROOT)


def test_container_build_context_carries_canonical_monitor_sources():
    # pyproject's wheel force-includes must also exist in the Docker builder.
    dockerfile = (ROOT / "Dockerfile").read_text().splitlines()
    allowed = (ROOT / ".dockerignore").read_text().splitlines()
    assert "!checks/" in allowed
    assert allowed.index("!checks/") < allowed.index("checks/**")
    for name in ("public_health.py", "switching_health.py"):
        assert allowed.index("checks/**") < allowed.index("!checks/" + name)
        assert any(
            line.startswith("COPY ") and "checks/" + name in line.split()[1:-1]
            for line in dockerfile
        ), name
