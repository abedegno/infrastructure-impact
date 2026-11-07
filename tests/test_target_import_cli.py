"""Early explicit CLI preview and shared collector lock ownership."""

import json
from contextlib import closing
from pathlib import Path

import pytest

from infrastructure_impact.cli import main
from infrastructure_impact.collection.target_import_profiles import PROFILE_ID
from infrastructure_impact.storage.locking import writer_lock
from infrastructure_impact.storage.repository import connect


def arguments(database, output, selected=PROFILE_ID):
    return [
        "target-import",
        "preview",
        "--database",
        str(database),
        "--profile",
        selected,
        "--output",
        str(output),
    ]


def test_early_preview_ignores_ambient_configuration(tmp_path, monkeypatch, capsys):
    database = tmp_path / "input.sqlite3"
    with closing(connect(database)):
        pass
    from infrastructure_impact.settings import Paths

    monkeypatch.setattr(Paths, "from_env", lambda: pytest.fail("ambient Paths startup"))
    monkeypatch.setenv("IMPACT_SOURCES", str(tmp_path / "PRIVATE-sources.json"))
    output = tmp_path / "receipt.json"
    assert main(arguments(database, output)) == 0
    result = json.loads(output.read_bytes())
    assert result == json.loads(capsys.readouterr().out)
    assert output.stat().st_mode & 0o777 == 0o600
    assert not (tmp_path / "data").exists()


@pytest.mark.parametrize(
    "kind",
    ["existing", "symlink", "parent_symlink", "overlap", "wal", "shm", "journal", "ancestor"],
)
def test_unsafe_output_rejected_before_copy(tmp_path, monkeypatch, kind):
    from infrastructure_impact.application import target_import

    database = tmp_path / "source.sqlite3"
    output = tmp_path / "receipt.json"
    if kind == "existing":
        output.write_text("preserve")
    elif kind == "symlink":
        output.symlink_to(database)
    elif kind == "parent_symlink":
        (tmp_path / "linked").symlink_to(tmp_path, target_is_directory=True)
        output = tmp_path / "linked/receipt.json"
    elif kind == "overlap":
        output = database
    elif kind == "ancestor":
        output = tmp_path
    else:
        output = Path(str(database) + "-" + kind)
    monkeypatch.setattr(target_import, "preview", lambda *a: pytest.fail("copied input"))
    with pytest.raises(SystemExit) as error:
        main(arguments(database, output))
    assert error.value.code == 2
    if kind == "existing":
        assert output.read_text() == "preserve"


def test_unknown_profile_has_no_filesystem_startup(tmp_path, monkeypatch):
    from infrastructure_impact.application import target_import

    monkeypatch.setattr(target_import, "preview", lambda *a: pytest.fail("preview startup"))
    with pytest.raises(SystemExit) as error:
        main(arguments(tmp_path / "missing", tmp_path / "receipt", "unknown"))
    assert error.value.code == 2 and list(tmp_path.iterdir()) == []


def test_stage_requires_explicit_arguments(tmp_path):
    with pytest.raises(SystemExit) as error:
        main(["target-import", "stage"])
    assert error.value.code == 2 and list(tmp_path.iterdir()) == []


def test_lock_scope_accepts_canonical_pair_without_ambient_lookup(tmp_path, monkeypatch):
    from infrastructure_impact.application.target_import import validate_lock_scope

    monkeypatch.delenv("IMPACT_HOME", raising=False)
    monkeypatch.delenv("IMPACT_DATABASE", raising=False)
    validate_lock_scope(tmp_path, tmp_path / "data/intel.sqlite3")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "home_env,db_env",
    [
        (False, False),
        (True, False),
        (False, True),
        (True, "mismatch"),
        ("mismatch", True),
        (True, True),
    ],
)
def test_custom_lock_scope_requires_explicit_matching_pair(tmp_path, monkeypatch, home_env, db_env):
    from infrastructure_impact.application.target_import import validate_lock_scope

    database = tmp_path / "custom.sqlite3"
    for name, enabled, actual in (
        ("IMPACT_HOME", home_env, tmp_path),
        ("IMPACT_DATABASE", db_env, database),
    ):
        monkeypatch.delenv(name, raising=False)
        if enabled:
            monkeypatch.setenv(
                name, str(tmp_path / "mismatch" if enabled == "mismatch" else actual)
            )
    if home_env is True and db_env is True:
        validate_lock_scope(tmp_path, database)
    else:
        with pytest.raises(ValueError, match="ambiguous_target_import_lock_scope"):
            validate_lock_scope(tmp_path, database)
    assert list(tmp_path.iterdir()) == []


def test_explicit_home_lock_contends_with_real_collector(tmp_path, monkeypatch):
    import infrastructure_impact.worker as worker

    home = tmp_path / "collector"
    monkeypatch.setenv("IMPACT_HOME", str(home))
    monkeypatch.setenv("IMPACT_DATABASE", str(home / "custom.sqlite3"))
    with writer_lock(home=home) as acquired:
        assert acquired
        assert worker.collect_once()["outcome"] == "skipped"
        with writer_lock() as ordinary:
            assert not ordinary
    with writer_lock() as ordinary:
        assert ordinary
    assert not (home / "custom.sqlite3").exists()


def test_stage_cli_validates_preview_before_stage(tmp_path, monkeypatch, capsys):
    from infrastructure_impact.application import target_import_stage
    from infrastructure_impact.application.target_import import preview
    from infrastructure_impact.application.target_import_contracts import preview_bytes

    database = tmp_path / "source/data/intel.sqlite3"
    with closing(connect(database)):
        pass
    preview_path = tmp_path / "preview.json"
    preview_path.write_bytes(preview_bytes(preview(database, PROFILE_ID)))
    output = tmp_path / "stage"
    with writer_lock(home=database.parent.parent):
        code = main(
            [
                "target-import",
                "stage",
                "--database",
                str(database),
                "--profile",
                PROFILE_ID,
                "--output",
                str(output),
                "--preview",
                str(preview_path),
                "--home",
                str(database.parent.parent),
            ]
        )
    result = json.loads(capsys.readouterr().out)
    assert code != 0 and result["outcome"] == "skipped_writer_lock"
    assert not output.exists()
    preview_path.write_text('{"private":"invalid receipt"}')
    monkeypatch.setattr(
        target_import_stage, "stage", lambda *a, **kw: pytest.fail("invalid receipt reached stage")
    )
    with pytest.raises(SystemExit) as error:
        main(
            [
                "target-import",
                "stage",
                "--database",
                str(database),
                "--profile",
                PROFILE_ID,
                "--output",
                str(output),
                "--preview",
                str(preview_path),
                "--home",
                str(database.parent.parent),
            ]
        )
    assert error.value.code == 2 and not output.exists()


@pytest.mark.parametrize("operation", ["import", "invalid_receipt_cli"])
def test_fresh_stage_startup_never_resolves_ambient_paths(tmp_path, operation):
    """Catch import-time roots that already-imported in-process sentinels miss."""
    import subprocess
    import sys
    import textwrap

    receipt = tmp_path / "invalid.json"
    receipt.write_text('{"invalid": "preview"}')
    script = textwrap.dedent("""
        import os
        import sys
        from pathlib import Path
        from infrastructure_impact.settings import Paths

        def forbidden():
            raise AssertionError("ambient Paths.from_env invoked during fresh startup")

        Paths.from_env = forbidden
        before = dict(os.environ)
        root = Path(sys.argv[1])
        if sys.argv[2] == "import":
            import infrastructure_impact.application.target_import_stage
        else:
            from infrastructure_impact.cli import main
            from infrastructure_impact.collection.target_import_profiles import PROFILE_ID
            try:
                main(["target-import", "stage", "--database", str(root / "source/data/intel.sqlite3"),
                      "--profile", PROFILE_ID, "--output", str(root / "stage"),
                      "--preview", str(root / "invalid.json"), "--home", str(root / "source")])
            except SystemExit as error:
                assert error.code == 2
            else:
                raise AssertionError("invalid preview was accepted")
        assert dict(os.environ) == before
        assert sorted(p.name for p in root.iterdir()) == ["invalid.json"]
        print("isolated startup confirmed")
    """)
    result = subprocess.run(
        [sys.executable, "-B", "-c", script, str(tmp_path), operation],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated startup confirmed\n"
    if operation == "invalid_receipt_cli":
        assert "target_import_failed" in result.stderr
