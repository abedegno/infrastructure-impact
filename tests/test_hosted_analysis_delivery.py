"""Offline operator routes with authored state and installed public profiles."""

import json
from pathlib import Path

import pytest
from test_analysis_delivery_profiles import PROFILE as DELIVERY
from test_analysis_delivery_profiles import expected
from test_hosted_maintenance import forbidden, invoke
from test_hosted_maintenance import recovery as recovery
from test_hosted_switching_analysis import PROFILE as SCIENCE
from test_hosted_workflow_protocol import ROOT, preflight
from test_hosted_workflow_protocol import legacy_workflow as legacy_workflow

from infrastructure_impact import worker
from infrastructure_impact.application import analysis_precomputed, publication
from ops import hosted_job


@pytest.mark.parametrize("kind", ["build", "publish", "collect"])
@pytest.mark.parametrize(
    "fmt,science,delivery",
    [("v1", True, DELIVERY), ("v2", False, DELIVERY), ("v2", True, "unknown"), ("v2", True, None)],
)
def test_invalid_profile_before_any_state(tmp_path, monkeypatch, kind, fmt, science, delivery):
    monkeypatch.setenv("IMPACT_HOME", str(tmp_path / "absent"))
    kwargs = dict(publication_format=fmt, analysis_delivery_profile=delivery)
    with pytest.raises(ValueError):
        if kind == "collect":
            worker.collect_once(**kwargs, switching_analysis_profile=SCIENCE if science else "")
        elif kind == "build":
            publication.build(**kwargs, include_switching_analysis=science)
        else:
            publication.publish(
                {}, tmp_path / "public", **kwargs, include_switching_analysis=science
            )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("extra", [("--validate-encrypted-state",), ("--restore-only", "absent")])
def test_recovery_selection_fails_before_key_or_backend(tmp_path, monkeypatch, capsys, extra):
    monkeypatch.delenv("IMPACT_STATE_KEY", raising=False)
    monkeypatch.setattr(hosted_job, "state_backend", forbidden)
    with pytest.raises(SystemExit):
        invoke(
            monkeypatch,
            tmp_path / "state",
            tmp_path / "public",
            "--publication-format",
            "v2",
            "--switching-analysis-profile",
            SCIENCE,
            "--analysis-delivery-profile",
            DELIVERY,
            *extra,
        )
    assert "recovery-only" in capsys.readouterr().err.lower()


def test_preflight_blocks_incapable_pin_before_private_collector(legacy_workflow):
    source, env, _, _ = legacy_workflow
    (source / "ops/hosted_job.py").write_text(
        "HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\nHOSTED_PUBLICATION_FORMATS = ('v1', 'v2')\nprint('--switching-analysis-profile SCIENCE')\n"
    )
    result = preflight(
        source,
        env
        | dict(
            PUBLICATION_FORMAT="v2",
            SWITCHING_ANALYSIS_PROFILE=SCIENCE,
            ANALYSIS_DELIVERY_PROFILE=DELIVERY,
        ),
    )
    assert result.returncode != 0 and "delivery" in result.stderr.lower()
    assert not Path(env["GITHUB_OUTPUT"]).exists()
    workflow = (ROOT / ".github/workflows/collect.yaml").read_text()
    assert workflow.index("name: Check hosted helper protocol") < workflow.index(
        "name: Collect private VulnCheck evidence"
    )


@pytest.mark.parametrize("mode", ["ordinary", "maintenance", "preview"])
def test_hosted_publication_selects_expected_views(recovery, tmp_path, monkeypatch, mode):
    from test_hosted_maintenance import PROFILE as MAINTENANCE
    from test_hosted_maintenance import effect_values, inject_sources
    from test_hosted_publication_format import offline_collection

    from infrastructure_impact.application import maintenance
    from infrastructure_impact.application.publication_reader import PublicationReader

    state, database, _, effects = recovery
    offline_collection(monkeypatch)
    args = [
        "--publication-format",
        "v2",
        "--switching-analysis-profile",
        SCIENCE,
        "--analysis-delivery-profile",
        DELIVERY,
    ]
    if mode != "ordinary":
        inject_sources(monkeypatch)
        args += [
            "--maintenance-profile",
            MAINTENANCE,
            "--maintenance-mode",
            "preview" if mode == "preview" else "apply",
        ]
    if mode == "maintenance":
        args += [
            "--maintenance-preview-fingerprint",
            maintenance.preview(database, MAINTENANCE)["fingerprint"],
        ]
    output = tmp_path / "selected-public"
    invoke(monkeypatch, state, output, *args)
    if mode == "preview":
        assert effect_values(effects) == {"mode": "preview", "preview_ready": "true"}
        assert not (output / "manifest.json").exists()
    else:
        reader = PublicationReader(output)
        assert analysis_precomputed.ROOT in reader.catalog["roots"]
        assert [v["options"] for v in reader._precomputed_manifest()["views"]] == expected()
        assert effect_values(effects)["publish_ready"] == "true"


def test_native_parity_binds_selected_roots_and_preserves_raw_options(tmp_path, monkeypatch):
    import copy
    from io import StringIO

    from test_static_delivery import dataset

    from infrastructure_impact.application import publication_v2, query, switching_analysis_profiles
    from infrastructure_impact.application.publication_reader import PublicationReader
    from infrastructure_impact.storage import repository

    native = dataset()
    data = copy.deepcopy(native)
    data["research"]["switching_analysis_input"] = switching_analysis_profiles.profile(
        SCIENCE
    ).build_options()["switching_analysis_input"]
    monkeypatch.setattr(repository, "connect", lambda *a, **k: StringIO())
    queries = []

    def query_state(db):
        queries.append(db)
        return copy.deepcopy(native)

    monkeypatch.setattr(query, "state", query_state)

    def parity(path, **kwargs):
        publication_v2.native_parity(
            "fixture",
            path,
            tmp_path,
            PublicationReader(path),
            switching_analysis_profile=SCIENCE,
            **kwargs,
        )

    plain = publication.publish(
        data, tmp_path / "plain", publication_format="v2", include_switching_analysis=True
    )
    with pytest.raises(ValueError, match="root"):
        parity(plain, analysis_delivery_profile=DELIVERY)
    out = publication.publish(
        data,
        tmp_path / "named",
        publication_format="v2",
        include_switching_analysis=True,
        analysis_delivery_profile=DELIVERY,
    )
    before = len(queries)
    parity(out, analysis_delivery_profile=DELIVERY)
    assert len(queries) == before + 1
    with pytest.raises(ValueError, match="root"):
        parity(out)
    with pytest.raises(ValueError, match="raw"):
        parity(out, analysis_delivery_profile=DELIVERY, analysis_precomputed_options=expected())

    with pytest.raises(ValueError, match="raw"):
        parity(out, analysis_delivery_profile=DELIVERY, analysis_precomputed_options=None)

    raw = tmp_path / "raw"
    data["publication"] = PublicationReader(out).identity["publication"]
    data["current_evidence"]["publication"] = data["publication"]
    projected = publication.public_projection(
        data, publication_format="v2", include_switching_analysis=True
    )
    options = [dict(vendor="arista")]
    publication_v2.write_bundle(
        raw, projected, analysis_precomputed_delivery=True, analysis_precomputed_options=options
    )
    parity(raw, analysis_precomputed_options=options)
    with pytest.raises(ValueError, match="membership"):
        parity(raw, analysis_delivery_profile=DELIVERY)
    defaults = tmp_path / "prototype-defaults"
    publication_v2.write_bundle(defaults, projected, analysis_precomputed_delivery=True)
    parity(defaults, analysis_precomputed_options=None)


@pytest.mark.parametrize(
    "value,science,fmt,ok",
    [
        ("", "", "v1", True),
        (DELIVERY, SCIENCE, "v2", True),
        ("unknown", SCIENCE, "v2", False),
        (DELIVERY, "", "v2", False),
        (DELIVERY, SCIENCE, "v1", False),
    ],
)
def test_workflow_invocation_validates_and_forwards_selected_profile(
    legacy_workflow, value, science, fmt, ok
):
    import subprocess
    import sys

    from test_hosted_workflow_protocol import script

    source, env, _, _ = legacy_workflow
    # Only capture the invocation. The test does not start the helper.
    shim = source.parent / "uv"
    shim.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
    env.update(
        HOSTED_PROTOCOL="effects-v1",
        PUBLICATION_FORMAT=fmt,
        SWITCHING_ANALYSIS_PROFILE=science,
        ANALYSIS_DELIVERY_PROFILE=value,
    )
    result = subprocess.run(
        ["bash", "-c", script("Restore, collect, audit and back up privately")],
        env=env,
        cwd=source,
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) is ok
    if ok:
        argv = json.loads(result.stdout)
        if value:
            assert argv[argv.index("--analysis-delivery-profile") + 1] == DELIVERY
        else:
            assert "--analysis-delivery-profile" not in argv
    else:
        assert not result.stdout


def test_workflow_preflight_loads_current_installed_profiles(legacy_workflow):
    source, env, _, _ = legacy_workflow
    (source / "ops/hosted_job.py").write_bytes((ROOT / "ops/hosted_job.py").read_bytes())
    result = preflight(
        source,
        env
        | dict(
            PUBLICATION_FORMAT="v2",
            SWITCHING_ANALYSIS_PROFILE=SCIENCE,
            ANALYSIS_DELIVERY_PROFILE=DELIVERY,
        ),
    )
    assert result.returncode == 0, result.stderr
    assert Path(env["GITHUB_OUTPUT"]).read_text().strip() == "protocol=effects-v1"


def test_wheel_profile_probe_uses_installed_resource_and_identity():
    import infrastructure_impact
    from checks.package_probe import check_analysis_delivery_profile

    check_analysis_delivery_profile(Path(infrastructure_impact.__file__).parent)


@pytest.mark.parametrize(
    "suffix",
    [
        ["v2", "--analysis-delivery-profile", DELIVERY],
        ["v1", "--switching-analysis-profile", SCIENCE, "--analysis-delivery-profile", DELIVERY],
        ["v2", "--switching-analysis-profile", SCIENCE, "--analysis-delivery-profile", ""],
        ["v2", "--switching-analysis-profile", SCIENCE, "--analysis-delivery-profile", "unknown"],
    ],
)
def test_isolated_cli_rejects_delivery_before_opening_candidate(monkeypatch, suffix):
    import sys

    from infrastructure_impact.application import import_candidate

    monkeypatch.setattr(
        sys, "argv", ["internal", "--worker", "absent-db", "absent-public", *suffix]
    )
    monkeypatch.setattr(import_candidate, "_paths", forbidden)
    with pytest.raises((SystemExit, ValueError)):
        import_candidate.main()


def test_snapshot_refresh_removes_previous_selected_assets(recovery, tmp_path, monkeypatch):
    from infrastructure_impact.application.publication_v2 import inspect_bundle
    from infrastructure_impact.cli import main

    _, database, _, _ = recovery
    monkeypatch.setenv("IMPACT_DATABASE", str(database))
    monkeypatch.setenv("IMPACT_BASE_PATH", "/")
    output = tmp_path / "reused"
    args = [
        "snapshot",
        "--publication-format",
        "v2",
        "--include-switching-analysis",
    ]
    main([*args, "--output", str(output), "--analysis-delivery-profile", DELIVERY])
    initial = inspect_bundle(output, {})
    selected_gzip = {
        part["part"]["path"]
        for view in initial._precomputed_manifest()["views"]
        for part in view["chunks"]
    }
    assert len(selected_gzip) >= 1
    with monkeypatch.context() as local:
        local.chdir(output)
        main([*args, "--output", "."])
        assert Path("manifest.json").read_bytes() == (output / "manifest.json").read_bytes()
    facts = {}
    final = inspect_bundle(output, facts)
    assert analysis_precomputed.ROOT not in final.catalog["roots"]
    assert all(not (output / path).exists() for path in selected_gzip)
    assert facts["public_bytes"] == sum(p.stat().st_size for p in output.rglob("*") if p.is_file())


@pytest.mark.parametrize(
    "extra",
    [
        "unmanaged",
        "edited",
        "forged",
        "extra_directory",
        "symlink",
        "destination_link",
        "parent_link",
    ],
)
def test_snapshot_refresh_preserves_unmanaged_entries(recovery, tmp_path, monkeypatch, extra):
    from infrastructure_impact.cli import main

    _, database, _, _ = recovery
    monkeypatch.setenv("IMPACT_DATABASE", str(database))
    monkeypatch.setenv("IMPACT_BASE_PATH", "/")
    output = tmp_path / "exports/public"

    def build(target):
        main(["snapshot", "--output", str(target), "--publication-format", "v2"])

    build(output)
    sentinel = tmp_path / "keep"
    sentinel.write_text("keep")
    target = output
    if extra == "unmanaged":
        (output / "owner.txt").write_text("keep")
    elif extra == "forged":
        from hashlib import sha256

        (output / "owner.txt").write_text("keep")
        manifest = json.loads((output / "manifest.json").read_bytes())
        manifest["sha256"]["owner.txt"] = sha256(b"keep").hexdigest()
        (output / "manifest.json").write_text(json.dumps(manifest))
    elif extra == "edited":
        (output / "index.html").write_text("keep")
    elif extra == "extra_directory":
        (output / "owner").mkdir()
    elif extra == "symlink":
        (output / "index.html").unlink()
        (output / "index.html").symlink_to(sentinel)
    elif extra == "destination_link":
        target = tmp_path / "output-link"
        target.symlink_to(output, target_is_directory=True)
    else:
        link = tmp_path / "parent-link"
        link.symlink_to(output.parent, target_is_directory=True)
        target = link / output.name
    original = (output / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="snapshot"):
        build(target)
    assert (output / "manifest.json").read_bytes() == original
    assert sentinel.read_text() == "keep"
    if extra in ("unmanaged", "forged"):
        assert (output / "owner.txt").read_text() == "keep"
    elif extra == "extra_directory":
        assert (output / "owner").is_dir()
    elif extra == "edited":
        assert (output / "index.html").read_text() == "keep"
    elif extra == "symlink":
        assert (output / "index.html").is_symlink()


def _fixture_generations(directory):
    from hashlib import sha256

    old, new = (directory / "generations" / (char * 32) for char in "ab")
    for path in (old, new):
        path.mkdir(parents=True)
        (path / "data").mkdir()
        for name in ("index.html", "data/view.json"):
            (path / name).write_text(path.name)
        digest = sha256(path.name.encode()).hexdigest()
        (path / "manifest.json").write_text(
            json.dumps(
                {
                    "generation": path.name,
                    "sha256": {"index.html": digest, "data/view.json": digest},
                }
            )
        )
    return old, new


@pytest.mark.parametrize("boundary", ["held_directory", "mount"])
def test_snapshot_refresh_keeps_existing_directory_identity(tmp_path, monkeypatch, boundary):
    import errno
    import os

    old, new = _fixture_generations(tmp_path)
    destination = tmp_path / "snapshot"
    destination.mkdir()
    if boundary == "mount":
        rename = Path.rename

        def mounted(source, target):
            if destination in (source, target):
                raise OSError(errno.EBUSY, "mount root is busy")
            if source.is_relative_to(destination) != target.is_relative_to(destination):
                raise OSError(errno.EXDEV, "cross-device rename")
            return rename(source, target)

        monkeypatch.setattr(Path, "rename", mounted)
    fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for generation in (old, new):
            publication._export_generation(generation, destination)
            with os.fdopen(os.open("manifest.json", os.O_RDONLY, dir_fd=fd), "rb") as stream:
                assert json.load(stream)["generation"] == generation.name
            assert os.path.samestat(os.fstat(fd), destination.stat())
    finally:
        os.close(fd)


@pytest.mark.parametrize("failure", ["replace", "concurrent_edit"])
def test_snapshot_refresh_rolls_back_on_replacement_failure(tmp_path, monkeypatch, failure):
    old, new = _fixture_generations(tmp_path)
    destination = tmp_path / "snapshot"
    publication._export_generation(old, destination)
    rename = Path.rename

    def interrupted(source, target):
        if (
            failure == "replace"
            and source.parent.name == "new"
            and target == destination / "manifest.json"
        ):
            raise OSError("simulated failed rename")
        if (
            failure == "concurrent_edit"
            and source == destination / "index.html"
            and target.parent.name == "previous"
        ):
            (destination / "owner.txt").write_text("keep")
        return rename(source, target)

    monkeypatch.setattr(Path, "rename", interrupted)
    with pytest.raises((ValueError, OSError), match="changed|simulated"):
        publication._export_generation(new, destination)
    assert (destination / "index.html").read_text() == old.name
    assert not list(destination.glob(".snapshot-*"))
    if failure == "concurrent_edit":
        assert (destination / "owner.txt").read_text() == "keep"


@pytest.mark.parametrize("rename_fails", [False, True])
@pytest.mark.parametrize("note", ["operator-note.txt", "view.json"])
def test_snapshot_refresh_preserves_edits_in_newly_installed_tree(
    tmp_path, monkeypatch, rename_fails, note
):
    old, new = _fixture_generations(tmp_path)
    destination = tmp_path / "snapshot"
    publication._export_generation(old, destination)
    rename = Path.rename
    content = b"concurrent operator edit"

    def edit_before_manifest(source, target):
        if source.parent.name == "new" and target == destination / "manifest.json":
            (destination / "data" / note).write_bytes(content)
            if rename_fails:
                raise OSError("simulated manifest rename failure")
        return rename(source, target)

    monkeypatch.setattr(Path, "rename", edit_before_manifest)
    with pytest.raises(ValueError) as error:
        publication._export_generation(new, destination)
    assert (destination / "manifest.json").read_bytes() == (old / "manifest.json").read_bytes()
    assert (destination / "data/view.json").read_text() == old.name
    preserved = [p for p in destination.rglob(note) if p.read_bytes() == content]
    assert len(preserved) == 1
    assert any(
        str(parent) in str(error.value)
        for parent in preserved[0].parents
        if parent.is_relative_to(destination) and parent != destination
    )
