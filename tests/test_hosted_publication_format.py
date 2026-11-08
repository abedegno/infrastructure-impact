"""Default-off hosted v2 uses authored sources and ephemeral recovery only."""

import json
import os
import subprocess
from pathlib import Path

import pytest
from jsonschema.exceptions import ValidationError
from test_hosted_maintenance import (
    PROFILE,
    effect_values,
    forbidden,
    inject_sources,
    invoke,
)
from test_hosted_maintenance import recovery as recovery
from test_hosted_target_import import apply as target_apply
from test_hosted_target_import import recovery as _target_recovery
from test_hosted_target_import import state_bytes
from test_hosted_workflow_protocol import legacy_workflow as legacy_workflow
from test_hosted_workflow_protocol import preflight, script
from test_target_import_stage import passing_verifier, serve
from test_target_import_stage import setup as setup

from infrastructure_impact import worker
from infrastructure_impact.application import maintenance, target_import, target_import_stage
from ops import hosted_job as hosted


@pytest.fixture
def target_recovery(setup, tmp_path, monkeypatch):
    return _target_recovery.__wrapped__(setup, tmp_path, monkeypatch)


def offline_collection(monkeypatch):
    monkeypatch.setattr(worker, "run", lambda *_args, **_kwargs: (0, 0))
    monkeypatch.setattr(worker, "benchmark", lambda: (0, 0))
    monkeypatch.setattr("infrastructure_impact.collection.archive.run", lambda *_: (0, 0))


@pytest.mark.parametrize("format", ["v1", "v2"])
def test_ordinary_rebuild_uses_explicit_format_and_verified_recovery(
    recovery, tmp_path, monkeypatch, format
):
    state, _, _, effects = recovery
    offline_collection(monkeypatch)
    output = tmp_path / "public"
    invoke(monkeypatch, state, output, "--publication-format", format)
    index = json.loads((output / "data/index.json").read_bytes())
    assert index["schema_version"] == (2 if format == "v2" else 1)
    assert (output / "publication-v2.json").exists() is (format == "v2")
    assert effect_values(effects) == {
        "mode": "ordinary",
        "recovery_ready": "true",
        "publish_ready": "true",
    }


def test_worker_rejects_invalid_format_before_creating_state(tmp_path, monkeypatch):
    monkeypatch.setenv("IMPACT_HOME", str(tmp_path / "absent"))
    monkeypatch.setattr(worker, "execute", forbidden)
    with pytest.raises(ValueError, match="publication_format"):
        worker.collect_once(publication_format="invalid")
    assert not (tmp_path / "absent").exists()


def test_targeted_maintenance_rebuilds_v2(recovery, tmp_path, monkeypatch):
    state, database, _, effects = recovery
    inject_sources(monkeypatch)
    output = tmp_path / "public"
    invoke(
        monkeypatch,
        state,
        output,
        "--publication-format",
        "v2",
        "--maintenance-profile",
        PROFILE,
        "--maintenance-mode",
        "apply",
        "--maintenance-preview-fingerprint",
        maintenance.preview(database, PROFILE)["fingerprint"],
    )
    assert json.loads((output / "data/index.json").read_bytes())["schema_version"] == 2
    assert effect_values(effects) == {
        "mode": "apply",
        "recovery_ready": "true",
        "publish_ready": "true",
    }


def verifier_v2(database, public, selected, *, publication_format="v1"):
    assert publication_format == "v2"
    checked = passing_verifier(database, public, selected)
    checked.update(schema_version=2, publication_format="v2")
    checked["candidate"].update(
        archive_scope="snapshot-v1", representation="publication-v2-physical"
    )
    return checked


@pytest.mark.parametrize("wrong_result", [False, True])
def test_exact_apply_binds_v2_stage_and_receipt_before_recovery(
    target_recovery, tmp_path, monkeypatch, capsys, wrong_result
):
    state, _, _, effects, selected, raws = target_recovery
    serve(monkeypatch, selected, raws)
    monkeypatch.setattr(target_import_stage, "verify", verifier_v2)
    if wrong_result:
        real_stage = target_import_stage.stage

        def changed(*args, **kwargs):
            value = real_stage(*args, **kwargs)
            value.pop("publication_format", None)
            value["schema_version"] = 1
            value["candidate"].pop("archive_scope", None)
            value["candidate"].pop("representation", None)
            return value

        monkeypatch.setattr(target_import_stage, "stage", changed)
        monkeypatch.setattr(hosted, "backup_verified", forbidden)
    before = state_bytes(state)
    output = tmp_path / "public"
    if wrong_result:
        with pytest.raises(ValidationError):
            target_apply(target_recovery, monkeypatch, output, extra=("--publication-format", "v2"))
        assert state_bytes(state) == before
        assert not output.exists()
        assert effect_values(effects) == {"mode": "apply"}
    else:
        target_apply(target_recovery, monkeypatch, output, extra=("--publication-format", "v2"))
        value = json.loads(capsys.readouterr().out)
        assert value["maintenance"]["publication_format"] == "v2"
        assert value["maintenance"]["schema_version"] == 2
        assert effect_values(effects) == {
            "mode": "apply",
            "recovery_ready": "true",
            "publish_ready": "true",
        }


def test_v2_preview_keeps_v1_binding_and_cannot_publish(target_recovery, tmp_path, monkeypatch):
    state, database, _, effects, selected, _ = target_recovery
    before = state_bytes(state)
    accepted = target_import.preview(database, selected.profile_id)
    monkeypatch.setattr(target_import_stage, "stage", forbidden)
    monkeypatch.setattr(hosted, "backup_verified", forbidden)
    monkeypatch.setattr("infrastructure_impact.collection.transport.build_opener", forbidden)
    output = tmp_path / "preview"
    invoke(
        monkeypatch,
        state,
        output,
        "--publication-format",
        "v2",
        "--maintenance-profile",
        selected.profile_id,
        "--maintenance-mode",
        "preview",
    )
    receipt = json.loads((output / "maintenance-preview.json").read_bytes())
    assert receipt["schema_version"] == 1
    assert receipt["fingerprint"] == accepted["fingerprint"]
    assert "publication_format" not in receipt
    assert state_bytes(state) == before
    assert effect_values(effects) == {"mode": "preview", "preview_ready": "true"}


@pytest.mark.parametrize("format", ["V2", "v3", "v2 "])
def test_invalid_hosted_format_fails_before_keys_restore_and_effects(tmp_path, monkeypatch, format):
    monkeypatch.delenv("IMPACT_STATE_KEY", raising=False)
    monkeypatch.setattr(hosted, "state_backend", forbidden)
    effects = tmp_path / "effects"
    monkeypatch.setenv("GITHUB_OUTPUT", str(effects))
    with pytest.raises(SystemExit) as error:
        invoke(monkeypatch, tmp_path / "state", tmp_path / "public", "--publication-format", format)
    assert error.value.code == 2
    assert not effects.exists()


@pytest.mark.parametrize(
    "helper,format,valid",
    [
        (None, "v1", True),
        (None, "v2", False),
        ("HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\n", "v1", True),
        ("HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\n", "v2", False),
        (
            "HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\nHOSTED_PUBLICATION_FORMATS = ('v1','v2')\n",
            "v2",
            True,
        ),
        (
            "HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\nHOSTED_PUBLICATION_FORMATS = ['v1','v2']\n",
            "v2",
            False,
        ),
        (
            "HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\nHOSTED_PUBLICATION_FORMATS = ('v1','v2')\nHOSTED_PUBLICATION_FORMATS = ('v1',)\n",
            "v2",
            False,
        ),
        (
            "HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\nHOSTED_PUBLICATION_FORMATS: tuple = ('v1','v2')\n",
            "v2",
            False,
        ),
        (
            "HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\nHOSTED_PUBLICATION_FORMATS = tuple(('v1','v2'))\n",
            "v2",
            False,
        ),
        (None, "V2", False),
    ],
)
def test_workflow_capability_preflight_is_static_and_precedes_keys(
    legacy_workflow, helper, format, valid
):
    source, env, _, effects = legacy_workflow
    if helper is not None:
        (source / "ops/hosted_job.py").write_text(
            helper + "raise RuntimeError('must not execute')\n"
        )
    result = preflight(source, env | {"PUBLICATION_FORMAT": format})
    assert (result.returncode == 0) is valid, result.stderr
    assert effect_values(Path(env["GITHUB_OUTPUT"])) == (
        {"protocol": "legacy-ordinary-v0" if helper is None else "effects-v1"} if valid else {}
    )
    assert not effects.exists()
    assert not Path(env["TEST_INVOKED"]).exists()


@pytest.mark.parametrize("format", ["v1", "v2"])
def test_workflow_passes_v2_explicitly_and_omits_v1_flag(tmp_path, format):
    shim = tmp_path / "uv"
    shim.write_text("#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
    shim.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "PUBLICATION_FORMAT": format,
        "HOSTED_PROTOCOL": "effects-v1",
        "VAULT_PROFILE": "standard",
        "RECOVERY_STORAGE": "git",
        "REPARSE_LIMIT": "0",
        "REPARSE_VENDOR": "",
        "MAINTENANCE_PROFILE": "",
        "MAINTENANCE_MODE": "",
        "MAINTENANCE_PREVIEW_FINGERPRINT": "",
        "PRIVATE_STATE": str(tmp_path / "state"),
        "PUBLIC_OUTPUT": str(tmp_path / "public"),
        "PREVIEW_OUTPUT": str(tmp_path / "preview"),
        "BASE_PATH": "/example/",
    }
    result = subprocess.run(
        ["bash", "-c", script("Restore, collect, audit and back up privately")],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    argv = json.loads(result.stdout)
    if format == "v2":
        assert argv[argv.index("--publication-format") + 1] == "v2"
    else:
        assert "--publication-format" not in argv


@pytest.mark.parametrize("failure", ["backup", "readback", "copy"])
def test_v2_exact_apply_preserves_readiness_order_on_failure(
    target_recovery, tmp_path, monkeypatch, capsys, failure
):
    state, _, key, effects, selected, raws = target_recovery
    before = state_bytes(state)
    serve(monkeypatch, selected, raws)
    monkeypatch.setattr(target_import_stage, "verify", verifier_v2)
    output = tmp_path / "public"
    if failure == "backup":

        def fail(*_args, **_kwargs):
            raise RuntimeError("authored backup failure")

        monkeypatch.setattr(hosted, "backup", fail)
    elif failure == "readback":
        real_restore = hosted.restore

        def fail(state, destination, *args, **kwargs):
            if Path(destination).name == "readback.sqlite3":
                raise ValueError("authored readback failure")
            return real_restore(state, destination, *args, **kwargs)

        monkeypatch.setattr(hosted, "restore", fail)
    else:
        real_copy = hosted.shutil.copytree

        def fail(source, destination, *args, **kwargs):
            if Path(destination) == output:
                raise OSError("authored public copy failure")
            return real_copy(source, destination, *args, **kwargs)

        monkeypatch.setattr(hosted.shutil, "copytree", fail)
    with pytest.raises((RuntimeError, ValueError, OSError)):
        target_apply(target_recovery, monkeypatch, output, extra=("--publication-format", "v2"))
    expected = {"mode": "apply"}
    if failure == "copy":
        expected["recovery_ready"] = "true"
        assert hosted.validate_encrypted_state(state, key)
    else:
        assert state_bytes(state) == before
    assert effect_values(effects) == expected
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["stage"] == ("public_copy" if failure == "copy" else "backup")
    assert receipt.get("private_recovery") == ("verified" if failure == "copy" else None)
