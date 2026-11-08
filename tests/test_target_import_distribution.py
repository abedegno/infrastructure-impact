"""Exact import shipping and CI coverage are explicit release contracts."""

import ast
import re
from pathlib import Path
from zipfile import ZipFile

import pytest

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
        ROOT / "tests/test_hosted_target_import.py",
        ROOT / "tests/test_browser_bootstrap.py",
        ROOT / "tests/test_target_capture_cache.py",
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
    for name in ("public_health.py", "switching_health.py", "wheel_hook.py"):
        assert allowed.index("checks/**") < allowed.index("!checks/" + name)
        assert any(
            line.startswith("COPY ") and "checks/" + name in line.split()[1:-1]
            for line in dockerfile
        ), name


@pytest.fixture
def wheel_selection(tmp_path):
    """Exercise Hatch's real reservation rules, not merely files it did include."""
    from hatchling.builders.wheel import WheelBuilder

    builder = WheelBuilder(str(ROOT))
    build_data = builder.get_default_build_data()
    builder.set_build_data_defaults(build_data)
    hooks = list(builder.get_build_hooks(str(tmp_path)).values())
    try:
        for hook in hooks:
            hook.initialize("standard", build_data)
        with builder.config.set_build_data(build_data):
            selected = {
                file.distribution_path: Path(file.path).read_bytes()
                for file in builder.recurse_included_files()
            }
        yield selected
    finally:
        temporary_files = list(build_data["force_include"])
        for hook in hooks:
            hook.finalize("standard", build_data, "unused-inventory-only")
        assert all(not Path(path).exists() for path in temporary_files)


def test_wheel_selection_contains_every_public_module_and_asset(wheel_selection, tmp_path):
    selected = wheel_selection
    expected = {
        str(path.relative_to(ROOT)): path.read_bytes()
        for path in (ROOT / "infrastructure_impact").rglob("*")
        if path.is_file() and path.suffix != ".pyc" and "__pycache__" not in path.parts
    }
    for name, data in expected.items():
        assert name in selected, "Missing required wheel file: " + name
        assert selected[name] == data, name
    assert (
        selected["infrastructure_impact/_standalone/publication_codec.py"]
        == selected["infrastructure_impact/publication_codec.py"]
    )
    archive_path = tmp_path / "inventory.whl"
    with ZipFile(archive_path, "w") as archive:
        for name, data in selected.items():
            archive.writestr(name, data)
    assert distribution.verify_wheel_inventory(ROOT, archive_path) == len(selected)


@pytest.mark.parametrize("missing", ["publication_codec.py", "web/publication-v2.js"])
def test_wheel_inventory_rejects_omitted_required_file(wheel_selection, tmp_path, missing):
    archive_path = tmp_path / "incomplete.whl"
    with ZipFile(archive_path, "w") as archive:
        for name, data in wheel_selection.items():
            if name != "infrastructure_impact/" + missing:
                archive.writestr(name, data)
    with pytest.raises(ValueError, match="inventory mismatch: missing="):
        distribution.verify_wheel_inventory(ROOT, archive_path)


def test_codec_hook_cleans_temporary_file_on_initialization_failure(tmp_path, monkeypatch):
    import shutil

    from hatchling.builders.wheel import WheelBuilder

    builder = WheelBuilder(str(ROOT))
    hook = builder.get_build_hooks(str(tmp_path))["custom"]

    def fail(*args):
        raise OSError("synthetic copy failure")

    monkeypatch.setattr(shutil, "copyfile", fail)
    with pytest.raises(OSError, match="synthetic copy failure"):
        hook.initialize("standard", {"force_include": {}})
    assert not Path(hook._temporary.name).exists()


def test_codec_hook_temporary_file_is_reclaimed_after_build_failure(tmp_path, monkeypatch):
    import gc
    import tempfile

    from hatchling.builders.wheel import WheelBuilder

    temporary = tempfile.TemporaryDirectory
    created = []

    def track(*args, **kwargs):
        directory = temporary(*args, **kwargs)
        created.append(Path(directory.name))
        return directory

    def fail(*args, **kwargs):
        raise OSError("synthetic wheel failure")

    monkeypatch.setattr(tempfile, "TemporaryDirectory", track)
    builder = WheelBuilder(str(ROOT))
    monkeypatch.setattr(builder, "get_version_api", lambda: {"standard": fail})
    with pytest.raises(OSError, match="synthetic wheel failure"):
        list(builder.build(directory=str(tmp_path), versions=["standard"]))
    gc.collect()
    assert created and all(not path.exists() for path in created)


def test_quality_workflow_preserves_contexts_and_runs_shared_checks_once():
    """Parse the workflow's scalar/step subset, as for hosted workflow gates."""
    text = (ROOT / ".github/workflows/ci.yaml").read_text()
    header, jobs_text = text.split("\njobs:\n", 1)
    assert re.search(r"^on:\n  push:\n    branches: \[main\]\n  pull_request:", header, re.M)
    assert "paths:" not in header and "paths-ignore:" not in header
    concurrency = dict(re.findall(r"^  (group|cancel-in-progress): (.+)$", header, re.M))
    assert concurrency == {
        "group": "${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
        "cancel-in-progress": "true",
    }
    jobs = dict(re.findall(r"^  (\w+):\n(.*?)(?=^  \w+:|\Z)", jobs_text, re.M | re.S))
    assert set(jobs) == {"python", "container"}
    versions = ast.literal_eval(re.search(r"^        python: (.+)$", jobs["python"], re.M)[1])
    assert versions == ["3.11", "3.13"]
    assert not re.search(r"^    (name|if):", jobs["python"], re.M)
    steps = []
    for block in re.split(r"^      - ", jobs["python"], flags=re.M)[1:]:
        steps.append(dict(re.findall(r"^(?:        )?(run|name|uses|if): (.+)$", block, re.M)))
    pytest_steps = [step for step in steps if step.get("run") == "uv run pytest -q"]
    assert len(pytest_steps) == 1 and "if" not in pytest_steps[0]
    shared = [
        step
        for step in steps
        if (
            step.get("name") == "Check container dependency exports"
            or any(
                token in step.get("run", "")
                for token in (
                    "checks/release.py",
                    "ruff ",
                    "npm ",
                    "node tests/",
                    "python -m build",
                    "checks/distribution.py",
                )
            )
        )
    ]
    assert len(shared) == 16
    for step in shared:
        assert step.get("if") == "matrix.python == '3.11'", step
    assert "docker build" in jobs["container"]
