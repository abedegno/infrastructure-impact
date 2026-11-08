"""Hosted exact imports promote only completed test-owned isolated stages."""

import importlib
import importlib.util
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from test_hosted_maintenance import effect_values, forbidden, invoke
from test_target_import_contracts import passing_candidate
from test_target_import_stage import passing_verifier, serve
from test_target_import_stage import setup as setup

from infrastructure_impact.application import target_import, target_import_stage
from infrastructure_impact.collection import target_import_profiles, transport
from ops import hosted_job as hosted

PROFILE = "campus-switching-public-gap-2026-11-07-v1"


def operations():
    name = "infrastructure_impact.collection.maintenance_operations"
    assert importlib.util.find_spec(name) is not None, "closed operation dispatch is absent"
    return importlib.import_module(name)


@pytest.fixture
def recovery(setup, tmp_path, monkeypatch):
    database, selected, raws, _, home = setup
    # These synthetic sources and this ephemeral key own the entire recovery tree.
    key = Fernet.generate_key()
    state = tmp_path / "encrypted-state"
    hosted.backup(state, database, key)
    effects = tmp_path / "effects"
    monkeypatch.setenv("IMPACT_STATE_KEY", key.decode())
    monkeypatch.setenv("GITHUB_OUTPUT", str(effects))
    monkeypatch.setattr(target_import_profiles, "profile", lambda _: selected)
    config = tmp_path / "test-sources.json"
    config.write_text('{"vendors": []}')
    monkeypatch.setenv("IMPACT_SOURCES", str(config))
    monkeypatch.setattr("infrastructure_impact.worker.collect_once", forbidden)
    monkeypatch.setattr("infrastructure_impact.application.maintenance.apply_profile", forbidden)
    monkeypatch.setattr("infrastructure_impact.application.maintenance.preview", forbidden)
    monkeypatch.setattr(target_import_stage, "verify", passing_verifier)
    return state, database, key, effects, selected, raws


def apply(recovery, monkeypatch, output, *, fingerprint=None, extra=()):
    state, database, _, _, selected, _ = recovery
    invoke(
        monkeypatch,
        state,
        output,
        "--maintenance-profile",
        selected.profile_id,
        "--maintenance-mode",
        "apply",
        "--maintenance-preview-fingerprint",
        fingerprint or target_import.preview(database, selected.profile_id)["fingerprint"],
        *extra,
    )


def state_bytes(state):
    return {p.name: p.read_bytes() for p in state.iterdir()}


def test_closed_dispatch_preserves_arista_and_unknown_error():
    module = operations()
    kind, selected = module.resolve_profile("arista-reviewed-2024-0099-0103-v1")
    assert kind == "arista-refresh" and selected.vendor == "arista"
    kind, selected = module.resolve_profile(PROFILE)
    assert kind == "target-import" and len(selected.targets) == 174
    with pytest.raises(ValueError, match="^unknown_maintenance_profile$"):
        module.resolve_profile("operator-manifest.json")


@pytest.mark.parametrize("flags", [(), ("--reparse-limit", "1"), ("--restore-only", "unused")])
def test_invalid_profile_controls_precede_keys_and_recovery(tmp_path, monkeypatch, capsys, flags):
    monkeypatch.delenv("IMPACT_STATE_KEY", raising=False)
    monkeypatch.setattr(hosted, "state_backend", forbidden)
    profile = PROFILE if flags else "unknown"
    with pytest.raises(SystemExit) as error:
        invoke(
            monkeypatch,
            tmp_path / "missing",
            tmp_path / "output",
            "--maintenance-profile",
            profile,
            "--maintenance-mode",
            "preview",
            *flags,
        )
    assert error.value.code == 2
    assert ("conflict" if flags else "unknown_maintenance_profile") in capsys.readouterr().err
    assert not (tmp_path / "output").exists()


def test_preview_is_distinct_read_only_and_never_backs_up(recovery, tmp_path, monkeypatch, capsys):
    state, database, key, effects, selected, _ = recovery
    before = state_bytes(state)
    monkeypatch.setattr(transport, "build_opener", forbidden)
    monkeypatch.setattr(target_import_stage, "stage", forbidden)
    monkeypatch.setattr(hosted, "backup_verified", forbidden)
    output = tmp_path / "preview"
    invoke(
        monkeypatch,
        state,
        output,
        "--maintenance-profile",
        selected.profile_id,
        "--maintenance-mode",
        "preview",
    )
    assert [p.name for p in output.iterdir()] == ["maintenance-preview.json"]
    receipt = json.loads((output / "maintenance-preview.json").read_bytes())
    assert receipt["format"] == "impact-target-import-preview"
    assert len(receipt["targets"]) == 2
    assert state_bytes(state) == before
    assert effect_values(effects) == {"mode": "preview", "preview_ready": "true"}
    assert json.loads(capsys.readouterr().out)["outcome"] == "preview"


@pytest.mark.parametrize(
    "failure", ["stale", "preflight", "audit", "capacity", "late_preservation"]
)
def test_failed_stage_cannot_change_recovery_or_public_output(
    recovery, tmp_path, monkeypatch, capsys, failure
):
    state, database, _, effects, selected, raws = recovery
    before = state_bytes(state)
    if failure == "preflight":
        raws["cisco"] += b"source drift"
    serve(monkeypatch, selected, raws)
    if failure in ("audit", "capacity"):

        def reject(*_):
            return {
                "audit_passed": failure != "audit",
                "candidate_validated": False,
                "capacity_passed": False,
                "candidate": {**passing_candidate(), "outcome": failure + "_failed"},
            }

        monkeypatch.setattr(target_import_stage, "verify", reject)
    elif failure == "late_preservation":

        def mutate_source(staged, public, profile):
            checked = passing_verifier(staged, public, profile)
            restored[0].write_bytes(restored[0].read_bytes() + b"late source mutation")
            return checked

        restored = []
        real_stage = target_import_stage.stage

        def stage(database, *args, **kwargs):
            restored.append(database)
            return real_stage(database, *args, **kwargs)

        monkeypatch.setattr(target_import_stage, "stage", stage)
        monkeypatch.setattr(target_import_stage, "verify", mutate_source)
    monkeypatch.setattr(hosted, "backup_verified", forbidden)
    output = tmp_path / "public"
    with pytest.raises((RuntimeError, ValueError)):
        apply(recovery, monkeypatch, output, fingerprint="0" * 64 if failure == "stale" else None)
    assert state_bytes(state) == before
    assert not output.exists()
    assert effect_values(effects) == {"mode": "apply"}
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["outcome"] == "error"
    assert "private_recovery" not in receipt
    if failure == "late_preservation":
        assert receipt["maintenance"]["candidate"]["outcome"] == "passed"
        assert receipt["maintenance"]["outcome"] == "failed"


def test_success_backs_up_stage_only_after_readback_and_copies_public_only(
    recovery, tmp_path, monkeypatch, capsys
):
    state, source, key, effects, selected, raws = recovery
    serve(monkeypatch, selected, raws)
    real_backup, real_restore = hosted.backup_verified, hosted.restore
    events = []

    def checked_restore(*args, **kwargs):
        result = real_restore(*args, **kwargs)
        if Path(args[1]).name == "readback.sqlite3":
            assert result
            events.append("authenticated_readback")
        return result

    def checked_backup(state, database, *args, **kwargs):
        assert database != source and database.parts[-3:] == ("private", "data", "intel.sqlite3")
        with closing(sqlite3.connect(database)) as db:
            assert db.execute("SELECT count(*) FROM pipeline_runs").fetchone()[0] == 1
            assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 2
        result = real_backup(state, database, *args, **kwargs)
        assert effect_values(effects) == {"mode": "apply", "recovery_ready": "true"}
        return result

    monkeypatch.setattr(hosted, "restore", checked_restore)
    monkeypatch.setattr(hosted, "backup_verified", checked_backup)
    real_effect = hosted.workflow_effect

    def effect(name, value="true"):
        if name == "publish_ready":
            assert events == ["authenticated_readback"]
        real_effect(name, value)

    monkeypatch.setattr(hosted, "workflow_effect", effect)
    output = tmp_path / "public"
    apply(recovery, monkeypatch, output)
    assert [p.name for p in output.iterdir()] == ["index.html"]
    assert "private" not in {p.name for p in output.rglob("*")}
    assert effect_values(effects) == {
        "mode": "apply",
        "recovery_ready": "true",
        "publish_ready": "true",
    }
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["outcome"] == "completed" and receipt["private_recovery"] == "verified"
    restored = tmp_path / "accepted.sqlite3"
    assert hosted.restore(state, restored, key)
    with closing(sqlite3.connect(restored)) as db:
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 2
    assert effects.read_text().splitlines() == [
        "mode=apply",
        "recovery_ready=true",
        "publish_ready=true",
    ]


@pytest.mark.parametrize("failure", ["backup", "copy"])
def test_effects_and_receipt_report_post_stage_failure_accurately(
    recovery, tmp_path, monkeypatch, capsys, failure
):
    state, _, key, effects, selected, raws = recovery
    before = state_bytes(state)
    serve(monkeypatch, selected, raws)
    if failure == "backup":

        def fail(*args, **kwargs):
            raise RuntimeError("authored backup failure")

        monkeypatch.setattr(hosted, "backup", fail)
    else:
        # Fail only final public copy, not stage internals or encrypted backup promotion.
        real = hosted.shutil.copytree

        def fail(source, target, *args, **kwargs):
            if Path(target) == tmp_path / "public":
                raise OSError("authored copy failure")
            return real(source, target, *args, **kwargs)

        monkeypatch.setattr(hosted.shutil, "copytree", fail)
    with pytest.raises((RuntimeError, OSError)):
        apply(recovery, monkeypatch, tmp_path / "public")
    expected = {"mode": "apply"}
    if failure == "copy":
        expected["recovery_ready"] = "true"
        assert state_bytes(state) != before
        assert hosted.validate_encrypted_state(state, key)
    else:
        assert state_bytes(state) == before
    assert effect_values(effects) == expected
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["stage"] == ("backup" if failure == "backup" else "public_copy")
    assert receipt.get("private_recovery") == ("verified" if failure == "copy" else None)
    assert receipt["outcome"] == "error"


@pytest.mark.parametrize("bad", ["missing_candidate", "check", "extra", "binding", "path"])
def test_invalid_completed_stage_receipt_is_rejected_before_backup(
    recovery, tmp_path, monkeypatch, capsys, bad
):
    from infrastructure_impact.application.target_import_contracts import binding_fingerprint

    state, _, _, effects, selected, raws = recovery
    before = state_bytes(state)
    serve(monkeypatch, selected, raws)
    real = target_import_stage.stage

    def changed(*args, **kwargs):
        result = real(*args, **kwargs)
        assert result["outcome"] == "completed"
        if bad == "missing_candidate":
            del result["candidate"]
        elif bad == "check":
            result["checks"]["audit_passed"] = False
        elif bad == "extra":
            result["raw"] = "private"
        elif bad == "binding":
            result["baseline_fingerprint"] = "0" * 64
            result["fingerprint"] = binding_fingerprint(result)
        else:
            result["staged_database"] = str(args[0])
        return result

    monkeypatch.setattr(target_import_stage, "stage", changed)
    monkeypatch.setattr(hosted, "backup_verified", forbidden)
    with pytest.raises((RuntimeError, ValueError)):
        apply(recovery, monkeypatch, tmp_path / "public")
    assert state_bytes(state) == before
    assert effect_values(effects) == {"mode": "apply"}
    assert json.loads(capsys.readouterr().out)["outcome"] == "error"


def test_stage_rechecks_fresh_hosted_preview_independently_under_lock(
    recovery, tmp_path, monkeypatch, capsys
):
    from infrastructure_impact.plugins.registry import default_registry
    from infrastructure_impact.storage.repository import connect, ingest

    state, _, _, effects, selected, raws = recovery
    before = state_bytes(state)
    real = target_import_stage.stage

    def drift(database, *args, **kwargs):
        assert kwargs["accepted_preview"]["fingerprint"] == args[1]
        target = next(t for t in selected.targets if t.vendor == "cisco")
        with closing(connect(database)) as db:
            ingest(db, raws["cisco"], target.fetch_url, default_registry().normalize, "cisco")
        return real(database, *args, **kwargs)

    monkeypatch.setattr(target_import_stage, "stage", drift)
    monkeypatch.setattr(transport, "build_opener", forbidden)
    monkeypatch.setattr(hosted, "backup_verified", forbidden)
    with pytest.raises(RuntimeError):
        apply(recovery, monkeypatch, tmp_path / "public")
    assert state_bytes(state) == before
    assert effect_values(effects) == {"mode": "apply"}
    assert json.loads(capsys.readouterr().out)["maintenance"]["failure_code"] == "stale_preview"


@pytest.mark.parametrize("bad_readback", [False, True])
def test_remote_readback_precedes_pointer_and_public_readiness(
    recovery, tmp_path, monkeypatch, capsys, bad_readback
):
    from test_remote_recovery import FakeAPI

    from infrastructure_impact.storage import remote_recovery

    state, _, _, effects, selected, raws = recovery
    before = state_bytes(state)
    serve(monkeypatch, selected, raws)
    api = FakeAPI()
    api.corrupt_download = bad_readback
    store = remote_recovery.GitHubDraftStore("example/recovery", "SYNTHETIC_TOKEN", opener=api)
    monkeypatch.setattr(remote_recovery, "GitHubDraftStore", lambda *_: store)
    output = tmp_path / "public"
    if bad_readback:
        with pytest.raises(ValueError):
            apply(recovery, monkeypatch, output, extra=("--recovery-storage", "github-draft"))
        assert state_bytes(state) == before
        assert effect_values(effects) == {"mode": "apply"}
        assert not output.exists()
    else:
        apply(recovery, monkeypatch, output, extra=("--recovery-storage", "github-draft"))
        pointer = json.loads((state / "current.json").read_bytes())
        assert pointer["remote_readback_verified_at"]
        assert effect_values(effects)["publish_ready"] == "true"


@pytest.mark.parametrize("base_path", ["/", "/infrastructure-impact/"])
def test_hosted_fresh_worker_preserves_explicit_base_path(
    recovery, tmp_path, monkeypatch, capsys, base_path
):
    from infrastructure_impact.application import import_candidate

    state, database, key, effects, selected, raws = recovery
    # Retain one authored public-scope record: the exact two imported targets
    # exercise intentionally excluded models and are not a whole public corpus.
    from infrastructure_impact.adapters.common import assessment, base
    from infrastructure_impact.storage.repository import connect, ingest

    record = base(
        "juniper",
        "https://www.juniper.net/synthetic/retained",
        "RETAINED",
        "Authored baseline",
        "2025-01-01T00:00:00Z",
    )
    record["cves"] = ["CVE-2024-6387"]
    record["assessments"] = [assessment("CVE-2024-6387", "Junos OS", "affected", "Synthetic")]
    with closing(connect(database)) as db:
        ingest(db, b"authored baseline", record["source_url"], lambda *a: record, "juniper")
    hosted.backup(state, database, key)
    serve(monkeypatch, selected, raws)
    monkeypatch.setenv("IMPACT_BASE_PATH", "https://hostile.invalid/escape/")

    def verify(database, public, profile):
        result = import_candidate.verify(database, public, profile)
        log = database.parent.parent / "home/target-import-worker.log"
        if result["candidate_validated"] is not True:
            pytest.fail(log.read_text())
        return result

    monkeypatch.setattr(target_import_stage, "verify", verify)
    output = tmp_path / "public"
    apply(recovery, monkeypatch, output, extra=("--base-path", base_path))
    assert effect_values(effects)["publish_ready"] == "true"
    html = (output / "index.html").read_text()
    assert 'href="' + base_path + "assets/" in html
    assert 'src="' + base_path + "assets/" in html
    assert "hostile.invalid" not in html
    assert hosted.validate_encrypted_state(state, key)
    assert json.loads(capsys.readouterr().out)["maintenance"]["candidate"]["outcome"] == "passed"


def test_target_preview_authenticates_before_artifacts(recovery, tmp_path, monkeypatch):
    from cryptography.fernet import InvalidToken

    state, _, _, effects, selected, _ = recovery
    before = state_bytes(state)
    monkeypatch.setenv("IMPACT_STATE_KEY", Fernet.generate_key().decode())
    with pytest.raises(InvalidToken):
        invoke(
            monkeypatch,
            state,
            tmp_path / "preview",
            "--maintenance-profile",
            selected.profile_id,
            "--maintenance-mode",
            "preview",
        )
    assert state_bytes(state) == before
    assert not (tmp_path / "preview").exists()
    assert effect_values(effects) == {"mode": "preview"}


def test_target_output_operator_symlink_refused_before_keys(
    recovery, tmp_path, monkeypatch, capsys
):
    state, _, _, effects, selected, _ = recovery
    output = tmp_path / "link"
    output.symlink_to(tmp_path / "absent", target_is_directory=True)
    monkeypatch.delenv("IMPACT_STATE_KEY", raising=False)
    monkeypatch.setattr(hosted, "state_backend", forbidden)
    with pytest.raises(SystemExit):
        invoke(
            monkeypatch,
            state,
            output,
            "--maintenance-profile",
            selected.profile_id,
            "--maintenance-mode",
            "preview",
        )
    assert "symbolic links" in capsys.readouterr().err
    assert effect_values(effects) == {}


@pytest.mark.parametrize("failure", ["vault", "envelope"])
def test_promotion_capacity_and_envelope_gates_precede_backup(
    recovery, tmp_path, monkeypatch, capsys, failure
):
    from ops import target_import_job

    state, database, _, effects, selected, raws = recovery
    before = state_bytes(state)
    serve(monkeypatch, selected, raws)
    monkeypatch.setattr(hosted, "backup_verified", forbidden)
    if failure == "vault":
        # The input fits but the fully ingested staged vault does not.
        monkeypatch.setattr(hosted, "vault_limit", lambda _: database.stat().st_size)
    else:
        monkeypatch.setattr(target_import_job, "MAX_RECEIPT_BYTES", 500)
    with pytest.raises(ValueError):
        apply(recovery, monkeypatch, tmp_path / "public")
    assert state_bytes(state) == before
    assert effect_values(effects) == {"mode": "apply"}
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["outcome"] == "error"
    if failure == "envelope":
        assert receipt["failure_code"] == "target_import_receipt_size"
        assert "maintenance" not in receipt


@pytest.mark.parametrize("base_path", ["//external/", "/../", "https://external/", "/a?b/"])
def test_hosted_unsafe_base_path_refused_before_keys(tmp_path, monkeypatch, capsys, base_path):
    monkeypatch.delenv("IMPACT_STATE_KEY", raising=False)
    monkeypatch.setattr(hosted, "state_backend", forbidden)
    with pytest.raises(SystemExit):
        invoke(
            monkeypatch,
            tmp_path / "state",
            tmp_path / "public",
            "--maintenance-profile",
            PROFILE,
            "--maintenance-mode",
            "preview",
            "--base-path",
            base_path,
        )
    assert "invalid_target_import_base_path" in capsys.readouterr().err


def test_hosted_stage_lock_refusal_does_not_promote_or_fetch(
    recovery, tmp_path, monkeypatch, capsys
):
    from infrastructure_impact.storage.locking import writer_lock

    state, _, _, effects, _, _ = recovery
    before = state_bytes(state)
    real_stage = target_import_stage.stage

    def contended(*args, **kwargs):
        with writer_lock(home=kwargs["lock_home"]) as acquired:
            assert acquired
            return real_stage(*args, **kwargs)

    monkeypatch.setattr(target_import_stage, "stage", contended)
    monkeypatch.setattr(transport, "build_opener", forbidden)
    monkeypatch.setattr(hosted, "backup_verified", forbidden)
    with pytest.raises(RuntimeError):
        apply(recovery, monkeypatch, tmp_path / "public")
    assert state_bytes(state) == before
    assert effect_values(effects) == {"mode": "apply"}
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["maintenance"]["outcome"] == "skipped_writer_lock"
    assert receipt["maintenance"]["failure_code"] == "writer_lock"


def test_acquisition_checkpoint_survives_rejection_and_retries_without_http(
    recovery, tmp_path, monkeypatch, capsys
):
    state, _, key, effects, selected, raws = recovery
    pointer = (state / "current.json").read_bytes()
    accepted_before = state_bytes(state)
    serve(monkeypatch, selected, raws)

    def reject(*_):
        acquisition = state.parent / "acquisitions" / selected.fingerprint
        assert (acquisition / "current.json").is_file()
        assert hosted.validate_encrypted_state(acquisition, key)
        assert effect_values(effects) == {"mode": "apply", "acquisition_ready": "true"}
        return {"candidate_validated": False}

    monkeypatch.setattr(target_import_stage, "verify", reject)
    with pytest.raises(RuntimeError):
        apply(recovery, monkeypatch, tmp_path / "rejected", extra=("--acquisition-cache",))
    first = json.loads(capsys.readouterr().out)
    assert first["maintenance"]["failure_code"] == "candidate_validation"
    assert (state / "current.json").read_bytes() == pointer
    assert state_bytes(state) == accepted_before
    assert hosted.validate_current(state, key)
    assert hosted.validate_current(state.parent / "acquisitions" / selected.fingerprint, key)
    assert not (tmp_path / "rejected").exists()
    assert effect_values(effects) == {"mode": "apply", "acquisition_ready": "true"}
    monkeypatch.setattr(transport, "build_opener", forbidden)
    monkeypatch.setattr(target_import_stage, "verify", passing_verifier)
    apply(recovery, monkeypatch, tmp_path / "accepted", extra=("--acquisition-cache",))
    second = json.loads(capsys.readouterr().out)
    assert second["maintenance"]["counters"]["http_attempts"] == 0
    assert second["maintenance"]["counters"]["received_bytes"] == 0
    assert (tmp_path / "accepted/index.html").is_file()
    assert hosted.validate_current(state, key)
    assert hosted.validate_current(state.parent / "acquisitions" / selected.fingerprint, key)


def test_acquisition_readback_failure_cannot_emit_ready_or_verify(
    recovery, tmp_path, monkeypatch, capsys
):
    state, _, _, effects, selected, raws = recovery
    pointer = (state / "current.json").read_bytes()
    serve(monkeypatch, selected, raws)
    actual_restore = hosted.restore

    def bad_readback(state, destination, *args, **kwargs):
        if destination.name == "readback.sqlite3":
            raise ValueError("synthetic failed authentication")
        return actual_restore(state, destination, *args, **kwargs)

    monkeypatch.setattr(hosted, "restore", bad_readback)
    monkeypatch.setattr(target_import_stage, "verify", forbidden)
    with pytest.raises(RuntimeError):
        apply(recovery, monkeypatch, tmp_path / "rejected", extra=("--acquisition-cache",))
    assert effect_values(effects) == {"mode": "apply"}
    assert (state / "current.json").read_bytes() == pointer
    assert not (state.parent / "acquisitions" / selected.fingerprint / "current.json").exists()
    assert json.loads(capsys.readouterr().out)["maintenance"]["failure_code"] == "storage"


@pytest.mark.parametrize(
    "flags", [(), ("--maintenance-profile", PROFILE, "--maintenance-mode", "preview")]
)
def test_acquisition_flag_is_restricted_before_keys_or_restore(tmp_path, monkeypatch, flags):
    monkeypatch.delenv("IMPACT_STATE_KEY", raising=False)
    monkeypatch.setattr(hosted, "restore_current", forbidden)
    with pytest.raises(SystemExit) as error:
        invoke(monkeypatch, tmp_path / "state", tmp_path / "output", "--acquisition-cache", *flags)
    assert error.value.code == 2
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("location", ["root", "profile", "another_profile"])
def test_acquisition_tree_cannot_overlap_public_output(recovery, monkeypatch, location):
    state, _, _, effects, selected, _ = recovery
    root = state.parent / "acquisitions"
    output = (
        root
        if location == "root"
        else root / (selected.fingerprint if location == "profile" else "another-profile")
    )
    before = state_bytes(state)
    monkeypatch.setattr(target_import_stage, "stage", forbidden)
    with pytest.raises(ValueError, match="separate directory trees"):
        apply(recovery, monkeypatch, output, extra=("--acquisition-cache",))
    assert state_bytes(state) == before
    assert effect_values(effects) == {"mode": "apply"}
    assert not root.exists()
