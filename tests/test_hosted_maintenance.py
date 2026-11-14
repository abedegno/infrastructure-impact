"""Hosted modes use only synthetic encrypted recovery and exact offline sources."""

import importlib
import json
import sqlite3
import sys
from contextlib import closing
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from test_arista_hosted_batch import authored_batch  # noqa: F401 -- shared authored pytest fixture
from test_targeted_maintenance import PROFILE, sources

from infrastructure_impact.adapters.arista_reconciliation import CSAF103, URL103
from infrastructure_impact.application import maintenance
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.storage.locking import writer_lock
from infrastructure_impact.storage.repository import connect, ingest
from ops import hosted_job as hosted


def forbidden(*args, **kwargs):
    pytest.fail("Forbidden hosted side effect")


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    # The test owns every byte, including the encryption key and legacy proof.
    for name in (
        "IMPACT_HOME",
        "IMPACT_DATABASE",
        "IMPACT_SNAPSHOT",
        "IMPACT_BASE_PATH",
        "IMPACT_DELIVERY_MODE",
        "IMPACT_PUBLICATIONS",
    ):
        monkeypatch.setenv(
            name,
            str(tmp_path / name)
            if name in ("IMPACT_HOME", "IMPACT_DATABASE", "IMPACT_SNAPSHOT", "IMPACT_PUBLICATIONS")
            else "",
        )
    config = tmp_path / "synthetic-sources.json"
    config.write_text('{"vendors": []}')
    monkeypatch.setenv("IMPACT_SOURCES", str(config))
    raw = sources()[CSAF103]
    monkeypatch.setattr(
        importlib.import_module("infrastructure_impact.plugins.arista_current_evidence"),
        "REVIEWED_SHA256",
        sha256(raw).hexdigest(),
    )
    database = tmp_path / "synthetic.sqlite3"
    registry = default_registry()
    with closing(connect(database)) as db:
        legacy = registry.finalize(structured(raw, CSAF103, "arista"), CSAF103, "arista")
        legacy["adapter_version"] = "synthetic-historical"
        ingest(db, raw, CSAF103, lambda *_: legacy, "arista")
    key = Fernet.generate_key()
    state = tmp_path / "state"
    hosted.backup(state, database, key)
    monkeypatch.setenv("IMPACT_STATE_KEY", key.decode())
    effects = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(effects))
    return state, database, key, effects


def invoke(monkeypatch, state, output, *flags):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hosted_job.py",
            "--state-dir",
            str(state),
            "--output",
            str(output),
            "--encrypted-state",
            *flags,
        ],
    )
    return hosted.main()


def effect_values(path):
    return (
        dict(line.split("=", 1) for line in path.read_text().splitlines()) if path.exists() else {}
    )


@pytest.mark.parametrize(
    "flags,message",
    [
        (
            ["--maintenance-profile", "unknown", "--maintenance-mode", "preview"],
            "unknown_maintenance_profile",
        ),
        (["--maintenance-profile", PROFILE], "explicit maintenance mode"),
        (["--maintenance-mode", "preview"], "requires a maintenance profile"),
        (["--maintenance-profile", PROFILE, "--maintenance-mode", "apply"], "fingerprint"),
        (
            [
                "--maintenance-profile",
                PROFILE,
                "--maintenance-mode",
                "apply",
                "--maintenance-preview-fingerprint",
                "bad",
            ],
            "fingerprint",
        ),
        (
            [
                "--maintenance-profile",
                PROFILE,
                "--maintenance-mode",
                "preview",
                "--maintenance-preview-fingerprint",
                "a" * 64,
            ],
            "fingerprint",
        ),
        (
            [
                "--maintenance-profile",
                PROFILE,
                "--maintenance-mode",
                "preview",
                "--reparse-limit",
                "1",
            ],
            "conflict",
        ),
        (
            [
                "--maintenance-profile",
                PROFILE,
                "--maintenance-mode",
                "preview",
                "--reparse-vendor",
                "arista",
            ],
            "conflict",
        ),
        (
            [
                "--maintenance-profile",
                PROFILE,
                "--maintenance-mode",
                "preview",
                "--validate-encrypted-state",
            ],
            "conflict",
        ),
        (
            [
                "--maintenance-profile",
                PROFILE,
                "--maintenance-mode",
                "preview",
                "--restore-only",
                "unused",
            ],
            "conflict",
        ),
    ],
)
def test_invalid_controls_refuse_before_key_or_recovery(
    tmp_path, monkeypatch, capsys, flags, message
):
    monkeypatch.delenv("IMPACT_STATE_KEY", raising=False)
    monkeypatch.setattr(hosted, "state_backend", forbidden)
    effects = tmp_path / "effects"
    monkeypatch.setenv("GITHUB_OUTPUT", str(effects))
    with pytest.raises(SystemExit) as error:
        invoke(monkeypatch, tmp_path / "missing", tmp_path / "output", *flags)
    assert error.value.code == 2
    assert message in capsys.readouterr().err
    assert effect_values(effects).get("recovery_ready") != "true"
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    "selected_profile,expected_targets",
    [
        (PROFILE, 2),
        ("arista-reviewed-sa0137-chronology-0165-0198-v1", 34),
    ],
)
def test_hosted_preview_has_no_writer_or_publication_side_effects(
    recovery, tmp_path, monkeypatch, capsys, selected_profile, expected_targets
):
    state, database, key, effects = recovery
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    original = database.read_bytes()
    for target in (
        "infrastructure_impact.storage.repository.migrate",
        "infrastructure_impact.storage.locking.writer_lock",
        "infrastructure_impact.collection.transport.fetch",
        "infrastructure_impact.worker.collect_once",
        "infrastructure_impact.application.benchmark.run",
        "infrastructure_impact.application.publication.build",
        "ops.hosted_job.backup",
        "ops.hosted_job.backup_remote",
    ):
        monkeypatch.setattr(target, forbidden)
    output = tmp_path / "preview"
    invoke(
        monkeypatch,
        state,
        output,
        "--maintenance-profile",
        selected_profile,
        "--maintenance-mode",
        "preview",
    )
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before
    assert database.read_bytes() == original
    restored = tmp_path / "verified-original.sqlite3"
    assert hosted.restore(state, restored, key)
    with closing(sqlite3.connect(database)) as left, closing(sqlite3.connect(restored)) as right:
        assert list(left.iterdump()) == list(right.iterdump())
    assert [p.name for p in output.iterdir()] == ["maintenance-preview.json"]
    raw = (output / "maintenance-preview.json").read_bytes()
    assert len(raw) <= 2_000_000
    receipt = json.loads(raw)
    assert receipt["format"] == "impact-maintenance-preview"
    assert len(receipt["targets"]) == expected_targets
    assert "raw" not in receipt and "synthetic" not in raw.decode()
    assert effect_values(effects) == {"mode": "preview", "preview_ready": "true"}
    assert json.loads(capsys.readouterr().out)["outcome"] == "preview"


def inject_sources(monkeypatch, *, fail=None):
    bodies = sources()
    if fail == "second_primary":
        bodies[URL103] = b"<html>invalid synthetic primary</html>"
    calls = []

    def fetch(db, url, vendor, *, max_bytes, allowed_urls):
        with writer_lock() as acquired:
            assert not acquired, "one writer lock must cover all acquisition"
        calls.append(url)
        assert vendor == "arista" and max_bytes == 2_000_000 and url in allowed_urls
        return bodies[url]

    monkeypatch.setattr("infrastructure_impact.collection.transport.fetch", fetch)
    monkeypatch.setattr("infrastructure_impact.worker.collect_once", forbidden)
    monkeypatch.setattr("infrastructure_impact.application.benchmark.run", forbidden)
    return calls


def apply(monkeypatch, state, database, output, fingerprint=None):
    return invoke(
        monkeypatch,
        state,
        output,
        "--maintenance-profile",
        PROFILE,
        "--maintenance-mode",
        "apply",
        "--maintenance-preview-fingerprint",
        fingerprint or maintenance.preview(database, PROFILE)["fingerprint"],
    )


def test_apply_rebuilds_under_one_lock_and_authenticates_before_publication(
    recovery, tmp_path, monkeypatch, capsys
):
    state, database, key, effects = recovery
    calls = inject_sources(monkeypatch)
    reached = []
    for module_name, attr in (
        ("infrastructure_impact.application.reporting", "report"),
        ("infrastructure_impact.storage.audit", "audit"),
        ("infrastructure_impact.application.publication", "build"),
        ("ops.hosted_job", "backup"),
        ("ops.hosted_job", "restore"),
    ):
        module = importlib.import_module(module_name)
        real = getattr(module, attr)

        def checked(*args, _real=real, _attr=attr, **kwargs):
            if _attr != "restore" or reached:
                with writer_lock() as acquired:
                    assert not acquired, _attr
                reached.append(_attr)
            return _real(*args, **kwargs)

        monkeypatch.setattr(module, attr, checked)
    output = tmp_path / "public"
    apply(monkeypatch, state, database, output)
    assert set(calls) == set(sources()) and len(calls) == 3
    assert reached == ["report", "audit", "build", "backup", "restore"]
    assert (output / "current-evidence.json").is_file()
    report = json.loads((output / "current-evidence.json").read_text())
    assert len(report["decisions"]) == 1 and report["issues"] == []
    assert effect_values(effects) == {
        "mode": "apply",
        "recovery_ready": "true",
        "publish_ready": "true",
    }
    captured = capsys.readouterr()
    receipt = json.loads(captured.out.splitlines()[-1])
    events = [json.loads(line) for line in captured.err.splitlines()]
    assert all(not event["phase"].startswith("collection.") for event in events)
    assert all(
        label in [event["phase"] for event in events]
        for label in (
            "maintenance.apply",
            "report",
            "maintenance.audit",
            "publication.build",
            "backup.local",
        )
    )
    assert receipt["outcome"] == "partial"
    assert receipt["maintenance"]["outcome"] == "completed"
    assert receipt["maintenance"]["alternate_outcomes"][0]["outcome"] == "expected_scope_conflict"
    assert receipt["benchmark_acquisition"] == "not_run"
    restored = tmp_path / "applied.sqlite3"
    # Undo the lock-inspecting restore wrapper for this independent verification.
    monkeypatch.undo()
    assert hosted.restore(state, restored, key)
    with closing(connect(restored, read_only=True)) as db:
        run = dict(db.execute("SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT 1").fetchone())
        assert run["outcome"] == "partial"
        assert run["failures"] == 1
        assert run["details"] == (
            "Targeted maintenance completed; expected alternate scope conflict; "
            "benchmark acquisition not run."
        )
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 3


def test_apply_baseline_drift_stops_before_http_and_state_commit(recovery, tmp_path, monkeypatch):
    state, database, key, effects = recovery
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    monkeypatch.setattr("infrastructure_impact.collection.transport.fetch", forbidden)
    monkeypatch.setattr(hosted, "backup", forbidden)
    with pytest.raises((RuntimeError, maintenance.MaintenanceBaselineChanged)):
        apply(monkeypatch, state, database, tmp_path / "public", "f" * 64)
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before
    assert effect_values(effects) == {"mode": "apply"}
    assert not (tmp_path / "public").exists()


@pytest.mark.parametrize(
    "failure", ["second_primary", "sql", "audit", "policy", "build", "backup", "readback"]
)
def test_apply_failure_never_publishes_or_emits_success(
    recovery, tmp_path, monkeypatch, capsys, failure
):
    state, database, key, effects = recovery
    before = (state / "current.json").read_bytes()
    inject_sources(monkeypatch, fail=failure)

    def failed(*args, **kwargs):
        raise RuntimeError("synthetic boundary failure")

    if failure == "sql":

        def failed_sql(*args, **kwargs):
            raise sqlite3.OperationalError("synthetic storage failure")

        monkeypatch.setattr("infrastructure_impact.storage.repository.ingest", failed_sql)
    elif failure == "policy":
        monkeypatch.setattr(
            "infrastructure_impact.plugins.arista_current_evidence.REVIEWED_SHA256", "f" * 64
        )
    elif failure in ("audit", "build", "backup"):
        target = {
            "audit": "infrastructure_impact.storage.audit.audit",
            "build": "infrastructure_impact.application.publication.build",
            "backup": "ops.hosted_job.backup",
        }[failure]
        monkeypatch.setattr(target, failed)
    elif failure == "readback":
        real = hosted.restore

        def readback(*args, **kwargs):
            if args[0] != state:
                raise ValueError("synthetic readback failure")
            return real(*args, **kwargs)

        monkeypatch.setattr(hosted, "restore", readback)
    with pytest.raises((RuntimeError, ValueError)):
        apply(monkeypatch, state, database, tmp_path / "public")
    assert not (tmp_path / "public").exists()
    values = effect_values(effects)
    assert values.get("publish_ready") != "true"
    assert '"private_recovery": "verified"' not in capsys.readouterr().out
    if failure in ("backup", "readback"):
        assert (state / "current.json").read_bytes() == before
        assert values.get("recovery_ready") != "true"
    else:
        assert values["recovery_ready"] == "true"
        assert hosted.validate_encrypted_state(state, key)


def workflow_steps():
    """Read just step-level scalars; evaluate the actual dispatch gates below."""
    import re

    text = (Path(__file__).resolve().parents[1] / ".github/workflows/collect.yaml").read_text()
    result = []
    for block in re.split(r"^      - ", text, flags=re.M)[1:]:
        values = dict(re.findall(r"^(?:        )?(name|uses|if|id): (.+)$", block, re.M))
        result.append(values)
    return result


def gate(step, effects, *, success=True, protocol="effects-v1", hosted_outcome=None):
    """Small evaluator for the workflow's trusted boolean/string gate subset."""
    from types import SimpleNamespace

    class Outputs(dict):
        def __getattr__(self, name):
            return self.get(name, "")

    expression = step.get("if", "success()")
    expression = expression.removeprefix("${{").removesuffix("}}").strip()
    expression = expression.replace("&&", " and ").replace("||", " or ")
    return bool(
        eval(
            expression,
            {"__builtins__": {}},
            {
                "always": lambda: True,
                "success": lambda: success,
                "steps": SimpleNamespace(
                    hosted=SimpleNamespace(
                        outputs=Outputs(effects),
                        outcome=hosted_outcome or ("success" if success else "failure"),
                    ),
                    protocol=SimpleNamespace(outputs=Outputs(protocol=protocol)),
                ),
            },
        )
    )


@pytest.mark.parametrize(
    "effects,success,retain,pages,preview",
    [
        ({}, False, False, False, False),  # Rejected profile/arguments: no key/state cleanup.
        ({"mode": "preview", "preview_ready": "true"}, True, False, False, True),
        ({"mode": "preview"}, False, False, False, False),
        ({"mode": "apply"}, False, False, False, False),
        ({"mode": "apply", "recovery_ready": "true"}, False, True, False, False),
        (
            {"mode": "apply", "recovery_ready": "true", "publish_ready": "true"},
            True,
            True,
            True,
            False,
        ),
        (
            {"mode": "ordinary", "recovery_ready": "true", "publish_ready": "true"},
            True,
            True,
            True,
            False,
        ),
        ({"mode": "ordinary", "recovery_ready": "true"}, False, True, False, False),
        (
            {"mode": "apply", "recovery_ready": "true", "publish_ready": "true"},
            False,
            True,
            False,
            False,
        ),
    ],
)
def test_workflow_effects_gate_cleanup_every_pages_step_and_preview(
    effects, success, retain, pages, preview
):
    steps = workflow_steps()
    cleanup = next(s for s in steps if s.get("name") == "Retain only encrypted recovery copies")
    assert gate(cleanup, effects, success=success) is retain
    public = [
        s
        for s in steps
        if any(
            n in s.get("uses", "")
            for n in ("configure-pages@", "upload-pages-artifact@", "deploy-pages@")
        )
        or s.get("name") == "Verify public availability and freshness"
    ]
    assert len(public) == 4
    assert all(gate(s, effects, success=success) is pages for s in public)
    artifacts = [s for s in steps if "actions/upload-artifact@" in s.get("uses", "")]
    assert len(artifacts) == 1
    assert gate(artifacts[0], effects, success=success) is preview


def test_empty_controls_keep_ordinary_collection(recovery, tmp_path, monkeypatch, capsys):
    state, database, key, effects = recovery

    def collect():
        # The ordinary collector still receives a restored, writable evidence DB.
        with closing(connect()) as db:
            assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 1
        return {"outcome": "partial", "failures": 1}

    monkeypatch.setattr("infrastructure_impact.worker.collect_once", collect)
    monkeypatch.setattr(maintenance, "apply_profile", forbidden)
    monkeypatch.setattr(maintenance, "preview", forbidden)
    invoke(
        monkeypatch,
        state,
        tmp_path / "public",
        "--maintenance-profile",
        "",
        "--maintenance-mode",
        "",
        "--maintenance-preview-fingerprint",
        "",
    )
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "ordinary" and result["outcome"] == "partial"
    assert result["private_recovery"] == "verified"
    assert effect_values(effects) == {
        "mode": "ordinary",
        "recovery_ready": "true",
        "publish_ready": "true",
    }


def test_preview_missing_checkpoint_cannot_bootstrap_or_publish(tmp_path, monkeypatch):
    monkeypatch.setenv("IMPACT_STATE_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(hosted, "backup", forbidden)
    with pytest.raises(RuntimeError, match="existing recovery checkpoint"):
        invoke(
            monkeypatch,
            tmp_path / "missing",
            tmp_path / "public",
            "--maintenance-profile",
            PROFILE,
            "--maintenance-mode",
            "preview",
        )
    assert not (tmp_path / "missing").exists() and not (tmp_path / "public").exists()


def test_unverified_apply_emits_no_candidate_success_receipt(
    recovery, tmp_path, monkeypatch, capsys
):
    state, database, key, effects = recovery
    inject_sources(monkeypatch)

    def failed(*args, **kwargs):
        raise RuntimeError("synthetic backup failure")

    monkeypatch.setattr(hosted, "backup", failed)
    with pytest.raises(RuntimeError):
        apply(monkeypatch, state, database, tmp_path / "public")
    for line in capsys.readouterr().out.splitlines():
        receipt = json.loads(line)
        assert "generation" not in receipt
        assert receipt.get("outcome") == "error"


def test_failed_primary_emits_bounded_operational_failure_receipt(
    recovery, tmp_path, monkeypatch, capsys
):
    state, database, key, effects = recovery
    inject_sources(monkeypatch, fail="second_primary")
    with pytest.raises(RuntimeError):
        apply(monkeypatch, state, database, tmp_path / "public")
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["mode"] == "apply" and receipt["outcome"] == "error"
    assert receipt["maintenance"]["outcome"] == "failed_primary_validation"
    assert receipt["benchmark_acquisition"] == "not_run"
    assert len(json.dumps(receipt).encode()) < 2_000_000


def test_apply_pointer_promotion_failure_preserves_all_original_recovery_bytes(
    recovery, tmp_path, monkeypatch
):
    state, database, key, effects = recovery
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    inject_sources(monkeypatch)
    real = Path.replace

    def refuse_pointer(path, target):
        if target == state / "current.json":
            raise OSError("synthetic promotion failure")
        return real(path, target)

    monkeypatch.setattr(Path, "replace", refuse_pointer)
    with pytest.raises(OSError):
        apply(monkeypatch, state, database, tmp_path / "public")
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before
    assert effect_values(effects) == {"mode": "apply"}


@pytest.mark.parametrize("bad_readback", [False, True])
def test_apply_remote_recovery_readback_gates_pointer_and_pages(
    recovery, tmp_path, monkeypatch, bad_readback
):
    from test_remote_recovery import FakeAPI

    from infrastructure_impact.storage import remote_recovery

    state, database, key, effects = recovery
    original = (state / "current.json").read_bytes()
    inject_sources(monkeypatch)
    api = FakeAPI()
    api.corrupt_download = bad_readback
    store = remote_recovery.GitHubDraftStore("example/recovery", "SYNTHETIC_TOKEN", opener=api)
    monkeypatch.setattr(remote_recovery, "GitHubDraftStore", lambda *_: store)

    def run():
        invoke(
            monkeypatch,
            state,
            tmp_path / "public",
            "--maintenance-profile",
            PROFILE,
            "--maintenance-mode",
            "apply",
            "--maintenance-preview-fingerprint",
            maintenance.preview(database, PROFILE)["fingerprint"],
            "--recovery-storage",
            "github-draft",
            "--recovery-repository",
            "example/recovery",
        )

    if bad_readback:
        with pytest.raises(ValueError):
            run()
        assert (state / "current.json").read_bytes() == original
        assert effect_values(effects) == {"mode": "apply"}
        assert not (tmp_path / "public").exists()
    else:
        run()
        assert effect_values(effects)["publish_ready"] == "true"
        assert json.loads((state / "current.json").read_text())["remote_readback_verified_at"]
        assert hosted.validate_current(state, key, store=store)


@pytest.mark.parametrize(
    "profile,mode,fingerprint,budget,vendor",
    [
        ("", "", "", "0", ""),
        (PROFILE, "preview", "", "0", ""),
        (PROFILE, "apply", "a" * 64, "0", ""),
        ("unknown profile with spaces", "invalid-mode", "bad fingerprint", "3", "arista"),
    ],
)
def test_workflow_forwards_controls_as_literal_arguments(
    tmp_path, profile, mode, fingerprint, budget, vendor
):
    import os
    import re
    import subprocess

    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/collect.yaml").read_text()
    block = next(
        block
        for block in re.split(r"^      - ", workflow, flags=re.M)
        if block.startswith("name: Restore, collect, audit and back up privately")
    )
    script = block.split("        run: |\n", 1)[1]
    script = "\n".join(line[10:] for line in script.splitlines())
    shim = tmp_path / "uv"
    shim.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
    shim.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "HOSTED_PROTOCOL": "effects-v1",
        "VAULT_PROFILE": "standard",
        "RECOVERY_STORAGE": "git",
        "REPARSE_LIMIT": budget,
        "REPARSE_VENDOR": vendor,
        "MAINTENANCE_PROFILE": profile,
        "MAINTENANCE_MODE": mode,
        "MAINTENANCE_PREVIEW_FINGERPRINT": fingerprint,
        "PRIVATE_STATE": str(tmp_path / "synthetic-state"),
        "PUBLIC_OUTPUT": str(tmp_path / "public"),
        "PREVIEW_OUTPUT": str(tmp_path / "preview"),
        "BASE_PATH": "/example/",
    }
    result = subprocess.run(
        ["bash", "-c", script], env=env, check=True, capture_output=True, text=True
    )
    argv = json.loads(result.stdout)
    for flag, value in (
        ("--maintenance-profile", profile),
        ("--maintenance-mode", mode),
        ("--maintenance-preview-fingerprint", fingerprint),
        ("--reparse-vendor", vendor),
    ):
        if value:
            assert argv[argv.index(flag) + 1] == value
        else:
            assert flag not in argv
    if int(budget):
        assert argv[argv.index("--reparse-limit") + 1] == budget
    expected = tmp_path / ("preview" if mode == "preview" else "public")
    assert argv[argv.index("--output") + 1] == str(expected)


@pytest.mark.parametrize("mode", ["unexpected", "PREVIEW", "preview "])
def test_unknown_modes_fail_before_recovery(tmp_path, monkeypatch, capsys, mode):
    monkeypatch.delenv("IMPACT_STATE_KEY", raising=False)
    monkeypatch.setattr(hosted, "state_backend", forbidden)
    with pytest.raises(SystemExit) as error:
        invoke(
            monkeypatch,
            tmp_path / "missing",
            tmp_path / "output",
            "--maintenance-profile",
            PROFILE,
            "--maintenance-mode",
            mode,
        )
    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_preview_rejects_unauthenticated_recovery_without_any_artifact(
    recovery, tmp_path, monkeypatch
):
    state, database, key, effects = recovery
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    monkeypatch.setenv("IMPACT_STATE_KEY", Fernet.generate_key().decode())
    from cryptography.fernet import InvalidToken

    with pytest.raises(InvalidToken):
        invoke(
            monkeypatch,
            state,
            tmp_path / "preview",
            "--maintenance-profile",
            PROFILE,
            "--maintenance-mode",
            "preview",
        )
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before
    assert not (tmp_path / "preview").exists()
    assert effect_values(effects) == {"mode": "preview"}


def test_apply_retains_existing_three_copy_budget(recovery, tmp_path, monkeypatch):
    state, database, key, effects = recovery
    hosted.backup(state, database, key)
    hosted.backup(state, database, key)
    prior = {p.name for p in state.glob("vault-*")}
    assert len(prior) == 3
    inject_sources(monkeypatch)
    apply(monkeypatch, state, database, tmp_path / "public")
    after = {p.name for p in state.glob("vault-*")}
    assert len(after) == 3 and len(after & prior) == 2
    assert json.loads((state / "current.json").read_text())["archive"] in after
    assert hosted.validate_encrypted_state(state, key)


def test_new_arista_batch_missing_owners_preserves_recovery_without_publication(
    recovery, tmp_path, monkeypatch, capsys
):
    state, database, key, effects = recovery
    selected = "arista-reviewed-sa0137-chronology-0165-0198-v1"
    accepted = maintenance.preview(database, selected)
    for target in (
        "infrastructure_impact.collection.transport.fetch",
        "infrastructure_impact.application.reporting.report",
        "infrastructure_impact.application.publication.build",
    ):
        monkeypatch.setattr(target, forbidden)
    output = tmp_path / "failed-batch"
    with pytest.raises(RuntimeError):
        invoke(
            monkeypatch,
            state,
            output,
            "--maintenance-profile",
            selected,
            "--maintenance-mode",
            "apply",
            "--maintenance-preview-fingerprint",
            accepted["fingerprint"],
        )
    assert effect_values(effects)["recovery_ready"] == "true"
    assert hosted.validate_encrypted_state(state, key)
    assert effect_values(effects).get("publish_ready") != "true"
    assert not output.exists()
    receipt = json.loads(capsys.readouterr().out)["maintenance"]
    assert receipt["outcome"] == "failed_primary_validation"
    assert receipt["imported"] == 0


def test_new_arista_batch_success_records_ok_without_expected_conflict(
    authored_batch,  # noqa: F811 -- shared authored pytest fixture
    recovery,
    tmp_path,
    monkeypatch,
    capsys,
):
    from infrastructure_impact.collection.maintenance_profiles import profile

    authored_db, _, _, _ = authored_batch
    state, _, key, effects = recovery
    database = tmp_path / "authored-batch.sqlite3"
    with closing(connect(database)) as db:
        authored_db.backup(db)
    hosted.backup(state, database, key)
    selected = profile("arista-reviewed-sa0137-chronology-0165-0198-v1")
    accepted = maintenance.preview(database, selected.profile_id)
    monkeypatch.setattr("infrastructure_impact.collection.transport.fetch", forbidden)
    monkeypatch.setattr("infrastructure_impact.application.reporting.report", lambda: None)
    monkeypatch.setattr("infrastructure_impact.storage.audit.audit", lambda: None)

    def build(*, output, **kwargs):
        assert kwargs["publication_format"] == "v2"
        output.mkdir()
        (output / "authored-candidate.txt").write_text("authored candidate")

    monkeypatch.setattr("infrastructure_impact.application.publication.build", build)
    output = tmp_path / "public-batch"
    invoke(
        monkeypatch,
        state,
        output,
        "--maintenance-profile",
        selected.profile_id,
        "--maintenance-mode",
        "apply",
        "--maintenance-preview-fingerprint",
        accepted["fingerprint"],
        "--publication-format",
        "v2",
        "--switching-analysis-profile",
        "campus-switching-openvuln-2026-11-14-v1",
    )
    receipt = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert receipt["outcome"] == "completed"
    assert receipt["maintenance"]["outcome"] == "completed"
    assert receipt["maintenance"]["imported"] == 34
    assert all(r["outcome"] == "validated" for r in receipt["maintenance"]["alternate_outcomes"])
    assert receipt["benchmark_acquisition"] == "not_run"
    assert receipt["private_recovery"] == "verified"
    assert effect_values(effects) == {
        "mode": "apply",
        "recovery_ready": "true",
        "publish_ready": "true",
    }
    assert (output / "authored-candidate.txt").read_text() == "authored candidate"
    restored = tmp_path / "recovered-authored-batch.sqlite3"
    assert hosted.restore(state, restored, key)
    with closing(connect(restored, read_only=True)) as db:
        run = dict(db.execute("SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT 1").fetchone())
        assert run["outcome"] == "ok"
        assert run["failures"] == 0
        assert run["imported"] == 34
        assert run["details"] == "Targeted maintenance completed; benchmark acquisition not run."
