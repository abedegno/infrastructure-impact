"""Non-publishing certification boundaries; all executed evidence and keys are synthetic."""

import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from test_target_import_contracts import result as receipt_result

from infrastructure_impact.collection.target_import_profiles import PROFILE_ID, profile

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy/github-candidate-certification.yaml"


def script(name):
    blocks = re.split(r"^      - ", TEMPLATE.read_text(), flags=re.M)
    block = next(b for b in blocks if b.startswith("name: " + name + "\n"))
    return "\n".join(line[10:] for line in block.split("        run: |\n", 1)[1].splitlines())


def execute(name, tmp_path, **extra):
    shim = tmp_path / "uv"
    shim.write_text(f'#!/bin/sh\nshift; shift; shift; exec "{sys.executable}" "$@"\n')
    shim.chmod(0o755)
    return subprocess.run(
        ["bash", "-c", script(name)],
        cwd=ROOT,
        env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], **extra},
        capture_output=True,
        text=True,
    )


def test_template_is_manual_non_publishing_with_explicit_draft_read_credential():
    text = TEMPLATE.read_text()
    assert TEMPLATE.parent == ROOT / "deploy"
    assert "  workflow_dispatch:" in text
    assert "  contents: write\n  actions: read" in text
    assert "timeout-minutes: 60" in text
    for forbidden in (
        "schedule:",
        "cron:",
        "pages: write",
        "id-token: write",
        "git push",
        "git commit",
        "collect_once",
        "actions/deploy-pages",
        "actions/upload-pages",
        "backup_verified",
        "backup_remote",
        "IMPACT_SOURCE_COMMIT }}",
        "gh variable",
        "maintenance-mode",
    ):
        assert forbidden not in text
    assert text.index("name: Validate manual inputs") < text.index("uses: actions/checkout")
    assert text.index("name: Validate manual inputs") < text.index("secrets.")
    assert text.count("persist-credentials: false") == 2
    blocks = re.split(r"^      - ", text, flags=re.M)
    stage = next(b for b in blocks if b.startswith("name: Stage disposable full candidate\n"))
    assert "GH_TOKEN" not in stage and "IMPACT_STATE_KEY" not in stage
    capture = next(b for b in blocks if b.startswith("name: Checkpoint private captures\n"))
    assert "GH_TOKEN" not in capture
    for action in re.findall(r"uses: (\S+)", text):
        assert re.fullmatch(r"actions/[a-z-]+@[a-f0-9]{40}", action)
    assert "ref: ${{ inputs.source_commit }}" in text
    assert "ref: publication-state" in text
    assert "--restore-only" in text and "--recovery-storage github-draft" in text
    assert "--group hosted" in text
    assert "--publication-format v2" in text and PROFILE_ID in text
    assert '"$RUNNER_TEMP/private-home/data/intel.sqlite3"' in text
    assert '"$RUNNER_TEMP/private-stage"' in text
    assert "resources/sources.json" in text
    uploads = [
        b for b in re.split(r"^      - ", text, flags=re.M) if "uses: actions/upload-artifact" in b
    ]
    assert len(uploads) == 2
    for block in uploads:
        assert "retention-days: 14" in block
        path = re.search(r"^          path: (.+)$", block, flags=re.M)[1]
        assert path in (
            "${{ runner.temp }}/certification-captures",
            "${{ runner.temp }}/certification-result/result.json",
        )


def test_installed_certification_matches_template_and_existing_vault_profile():
    installed = ROOT / ".github/workflows/candidate-certification.yaml"
    assert installed.read_bytes() == TEMPLATE.read_bytes()
    text = TEMPLATE.read_text()
    assert "VAULT_PROFILE: ${{ vars.IMPACT_VAULT_PROFILE || 'standard' }}" in text
    assert '--vault-profile "$VAULT_PROFILE"' in script("Restore accepted baseline privately")


@pytest.mark.parametrize(
    "error,expected",
    [
        (
            "PRIVATE/path\nValueError: Recovery API returned HTTP 404\n",
            {"category": "remote_http", "http_status": 404},
        ),
        ("PRIVATE/key\ncryptography.fernet.InvalidToken\n", {"category": "authentication"}),
        (
            "error: Encrypted public-runner state requires IMPACT_STATE_KEY\nPRIVATE",
            {"category": "missing_key"},
        ),
        ("PRIVATE/path and unknown error", {"category": "unclassified"}),
    ],
)
def test_restore_failure_metadata_is_available_without_stage_and_excludes_details(
    tmp_path, error, expected
):
    (tmp_path / "restore-stderr").write_text(error)
    result = execute(
        "Sanitize result metadata",
        tmp_path,
        RUNNER_TEMP=str(tmp_path),
        SOURCE_COMMIT="a" * 40,
        STAGE_OUTCOME="skipped",
        RESTORE_OUTCOME="failure",
    )
    assert result.returncode == 0, result.stderr
    value = json.loads((tmp_path / "certification-result/result.json").read_text())
    assert value["restore_error"] == expected
    assert "PRIVATE" not in json.dumps(value)
    text = TEMPLATE.read_text()
    metadata = text.split("      - name: Sanitize result metadata", 1)[1]
    assert "steps.restore.outcome != 'skipped'" in metadata


@pytest.mark.parametrize(
    "commit,run_id,ok",
    [
        ("a" * 40, "", True),
        ("0" * 40, "12345", True),
        ("A" * 40, "", False),
        ("a" * 39, "", False),
        ("main", "", False),
        ("a" * 40 + "\n", "", False),
        ("a" * 40, "12; touch owned", False),
        ("a" * 40, "-1", False),
        ("a" * 40, "1\n2", False),
    ],
)
def test_manual_inputs_fail_closed_before_checkout(tmp_path, commit, run_id, ok):
    result = execute(
        "Validate manual inputs", tmp_path, SOURCE_COMMIT=commit, PREVIOUS_RUN_ID=run_id
    )
    assert (result.returncode == 0) is ok
    assert not (tmp_path / "owned").exists()


@pytest.fixture
def cache(tmp_path):
    home = tmp_path / "private-home"
    database = home / "captures" / (profile(PROFILE_ID).fingerprint + ".sqlite3")
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE synthetic (value TEXT)")
        db.execute("INSERT INTO synthetic VALUES ('private publisher bytes')")
    return database, {
        "RUNNER_TEMP": str(tmp_path),
        "IMPACT_STATE_KEY": Fernet.generate_key().decode(),
        "IMPACT_SOURCE_COMMIT": "a" * 40,
    }


def test_checkpoint_and_authenticated_restore_round_trip(cache, tmp_path):
    database, env = cache
    result = execute("Checkpoint private captures", tmp_path, **env)
    assert result.returncode == 0, result.stderr
    state = tmp_path / "certification-captures"
    assert sorted(p.suffix for p in state.iterdir()) == [".fernet", ".json"]
    assert all(b"private publisher bytes" not in p.read_bytes() for p in state.iterdir())
    state.rename(tmp_path / "previous-captures")
    database.unlink()
    result = execute("Authenticate prior captures", tmp_path, **env)
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT value FROM synthetic").fetchall() == [
            ("private publisher bytes",)
        ]


@pytest.mark.parametrize("bad", ["missing", "wrong-key", "corrupt", "plaintext"])
def test_prior_capture_failure_never_falls_back_to_acquisition(cache, tmp_path, bad):
    database, env = cache
    result = execute("Checkpoint private captures", tmp_path, **env)
    assert result.returncode == 0, result.stderr
    state = tmp_path / "certification-captures"
    state.rename(tmp_path / "previous-captures")
    state = tmp_path / "previous-captures"
    database.unlink()
    if bad == "missing":
        (state / "current.json").unlink()
    elif bad == "wrong-key":
        env["IMPACT_STATE_KEY"] = Fernet.generate_key().decode()
    elif bad == "corrupt":
        next(state.glob("*.fernet")).write_bytes(b"unauthenticated")
    else:
        (state / "raw.sqlite3").write_bytes(b"private bytes")
    result = execute("Authenticate prior captures", tmp_path, **env)
    assert result.returncode != 0
    assert not database.exists()


def test_metadata_excludes_raw_receipt_and_logs(tmp_path):
    receipt = receipt_result(profile(PROFILE_ID))
    receipt.update(schema_version=2, publication_format="v2")
    (tmp_path / "stage-result.json").write_text(json.dumps(receipt))
    (tmp_path / "stage-stderr").write_text(
        "private publisher bytes\n"
        + json.dumps(
            {
                "event": "phase",
                "phase": "publication.query",
                "state": "completed",
                "elapsed_seconds": 2.5,
                "process_cpu_seconds": 1.2,
                "peak_resident_bytes": 1024,
                "raw": "private bytes",
            }
        )
        + "\n"
        + json.dumps(
            {
                "event": "candidate_worker",
                "state": "timeout",
                "elapsed_seconds": 2400,
                "raw": "private bytes",
            }
        )
        + "\n"
    )
    result = execute(
        "Sanitize result metadata",
        tmp_path,
        RUNNER_TEMP=str(tmp_path),
        SOURCE_COMMIT="a" * 40,
        STAGE_OUTCOME="failure",
    )
    assert result.returncode == 0, result.stderr
    raw = (tmp_path / "certification-result/result.json").read_text()
    assert len(raw) < 65536
    assert not any(s in raw for s in ("private", "secret URL", "targets", "staged_database"))
    value = json.loads(raw)
    assert value["failure_code"] == "candidate_capacity"
    assert value["counters"] == {
        "http_attempts": 2,
        "received_bytes": 200,
        "input_bytes": 200,
        "imported": 0,
        "unchanged": 0,
    }
    assert value["diagnostics"][0]["peak_resident_bytes"] == 1024
    assert value["diagnostics"][-1] == {
        "event": "candidate_worker",
        "state": "timeout",
        "elapsed_seconds": 2400,
    }


def test_stage_invokes_only_disposable_v2_candidate_and_keeps_failure(tmp_path):
    shim = tmp_path / "uv"
    shim.write_text(
        f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\nsys.exit(1)\n"
    )
    shim.chmod(0o755)
    result = subprocess.run(
        ["bash", "-c", script("Stage disposable full candidate")],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_WORKSPACE": str(tmp_path / "workspace"),
        },
        capture_output=True,
    )
    assert result.returncode == 1
    argv = json.loads((tmp_path / "stage-result.json").read_text())
    assert argv[:5] == ["run", "--no-sync", "impact", "target-import", "stage"]
    assert argv[argv.index("--database") + 1] == str(tmp_path / "private-home/data/intel.sqlite3")
    assert argv[argv.index("--home") + 1] == str(tmp_path / "private-home")
    assert argv[argv.index("--output") + 1] == str(tmp_path / "private-stage")
    assert argv[argv.index("--publication-format") + 1] == "v2"


def test_no_capture_does_not_create_an_artifact_directory(tmp_path):
    result = execute(
        "Checkpoint private captures",
        tmp_path,
        RUNNER_TEMP=str(tmp_path),
        IMPACT_STATE_KEY=Fernet.generate_key().decode(),
    )
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "certification-captures").exists()


@pytest.mark.parametrize(
    "state,returncode", [("timeout", None), ("nonzero", 3), ("launch_error", None)]
)
def test_diagnostics_preserve_terminal_classification_and_drop_hostile_values(state, returncode):
    from infrastructure_impact.application.import_candidate import parse_worker_diagnostics

    terminal = {"event": "candidate_worker", "state": state, "elapsed_seconds": 2400.2}
    if returncode is not None:
        terminal["returncode"] = returncode
    invalid = [
        {**terminal, "state": "PRIVATE/path"},
        *({**terminal, "elapsed_seconds": v} for v in (True, -1, float("nan"), float("inf"))),
        [],
        None,
    ]
    raw = b"PRIVATE publisher bytes\n" + b"\n".join(json.dumps(v).encode() for v in invalid)
    raw += b"\n" + json.dumps({**terminal, "path": "PRIVATE/path", "raw": "PRIVATE"}).encode()
    assert parse_worker_diagnostics(raw) == [terminal]
    assert "PRIVATE" not in json.dumps(parse_worker_diagnostics(raw))


@pytest.mark.parametrize("bad", [True, -1, 349, "PRIVATE"])
def test_invalid_counters_are_never_uploaded(tmp_path, bad):
    receipt = receipt_result(profile(PROFILE_ID))
    receipt.update(schema_version=2, publication_format="v2")
    receipt["counters"]["http_attempts"] = bad
    (tmp_path / "stage-result.json").write_text(json.dumps(receipt))
    result = execute(
        "Sanitize result metadata",
        tmp_path,
        RUNNER_TEMP=str(tmp_path),
        SOURCE_COMMIT="a" * 40,
        STAGE_OUTCOME="failure",
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads((tmp_path / "certification-result/result.json").read_text())
    assert "counters" not in summary
    assert "PRIVATE" not in json.dumps(summary)


def test_phase_event_cap_preserves_terminal_summary():
    from infrastructure_impact.application.import_candidate import parse_worker_diagnostics

    phase = {
        "event": "phase",
        "phase": "publication.query",
        "state": "completed",
        "elapsed_seconds": 1,
    }
    terminal = {
        "event": "candidate_worker",
        "state": "nonzero",
        "elapsed_seconds": 10,
        "returncode": 3,
    }
    raw = (json.dumps(phase) + "\n").encode() * 40 + json.dumps(terminal).encode()
    values = parse_worker_diagnostics(raw)
    assert len(values) == 33
    assert values[-1] == terminal


def test_monitor_capacity_diagnostics_are_closed_and_bounded():
    from infrastructure_impact.application.import_candidate import parse_worker_diagnostics

    event = dict(
        event="monitor_capacity",
        mode="default",
        reason="default_transfer",
        resource="v2_part",
        observed_bytes=32_000_001,
        limit_bytes=32_000_000,
    )
    raw = json.dumps(dict(event, private="PRIVATE")).encode()
    assert parse_worker_diagnostics(raw) == [event]
    assert parse_worker_diagnostics(raw + b"\n" + raw + b"\n" + raw) == [event, event]
    for key, bad in (
        ("mode", "PRIVATE"),
        ("resource", "PRIVATE"),
        ("reason", "PRIVATE"),
        ("observed_bytes", True),
        ("limit_bytes", -1),
        ("observed_bytes", 2**50),
    ):
        assert parse_worker_diagnostics(json.dumps(dict(event, **{key: bad})).encode()) == []


@pytest.mark.parametrize(
    "mode,run_id,ok",
    [
        ("", "", True),
        ("false", "123", True),
        ("true", "", True),
        ("true", "123", False),
        ("PRIVATE", "", False),
    ],
)
def test_retained_mode_input_conflict_is_rejected_before_restore(tmp_path, mode, run_id, ok):
    result = execute(
        "Validate manual inputs",
        tmp_path,
        SOURCE_COMMIT="a" * 40,
        PREVIOUS_RUN_ID=run_id,
        RETAINED_ONLY=mode,
    )
    assert (result.returncode == 0) is ok


def test_retained_mode_disables_import_and_captures_and_has_no_credentials():
    text = TEMPLATE.read_text()
    assert "retained_only:" in text and "default: false" in text
    blocks = re.split(r"^      - ", text, flags=re.M)
    names = (
        "Download prior encrypted captures",
        "Authenticate prior captures",
        "Preview full hosted baseline",
        "Stage disposable full candidate",
        "Checkpoint private captures",
    )
    for name in names:
        block = next(b for b in blocks if b.startswith("name: " + name + "\n"))
        assert "!inputs.retained_only" in block.split("        run:")[0]
    retained = next(b for b in blocks if b.startswith("name: Preview retained switching fixes\n"))
    assert "if: ${{ inputs.retained_only }}" in retained
    assert "timeout-minutes: 40" in retained
    assert "GH_TOKEN" not in retained and "IMPACT_STATE_KEY" not in retained
    uploads = [b for b in blocks if "uses: actions/upload-artifact" in b]
    capture = next(b for b in uploads if "name: candidate-certification-captures" in b)
    assert "!inputs.retained_only" in capture


@pytest.mark.parametrize("mutation", ["missing", "invalid", "oversized", "private"])
def test_retained_receipt_sanitizer_never_copies_hostile_metadata(tmp_path, mutation):
    from ops.switching_fix_preview import _empty

    value = _empty("a" * 40)
    raw = json.dumps(value)
    if mutation == "invalid":
        raw = "{PRIVATE"
    elif mutation == "oversized":
        raw = "PRIVATE" * 10000
    elif mutation == "private":
        value["raw"] = "PRIVATE/path"
        raw = json.dumps(value)
    if mutation != "missing":
        (tmp_path / "retained-preview-result.json").write_text(raw)
    (tmp_path / "stage-stderr").write_text("PRIVATE raw logs")
    result = execute(
        "Sanitize result metadata",
        tmp_path,
        RUNNER_TEMP=str(tmp_path),
        SOURCE_COMMIT="a" * 40,
        STAGE_OUTCOME="skipped",
        RETAINED_ONLY="true",
        RETAINED_OUTCOME="failure",
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads((tmp_path / "certification-result/result.json").read_text())
    assert summary["retained_receipt_status"] == ("missing" if mutation == "missing" else "invalid")
    assert "retained_preview" not in summary
    assert "PRIVATE" not in json.dumps(summary)


def test_retained_receipt_sanitizer_embeds_only_validated_receipt(tmp_path):
    from ops.switching_fix_preview import _empty

    value = _empty("a" * 40)
    (tmp_path / "retained-preview-result.json").write_text(json.dumps(value))
    result = execute(
        "Sanitize result metadata",
        tmp_path,
        RUNNER_TEMP=str(tmp_path),
        SOURCE_COMMIT="a" * 40,
        STAGE_OUTCOME="skipped",
        RETAINED_ONLY="true",
        RETAINED_OUTCOME="failure",
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads((tmp_path / "certification-result/result.json").read_text())
    assert summary["retained_preview"] == value
    assert summary["diagnostics"] == []


def test_retained_step_invokes_only_offline_helper_and_preserves_failure(tmp_path):
    shim = tmp_path / "uv"
    shim.write_text(
        f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\nsys.exit(1)\n"
    )
    shim.chmod(0o755)
    result = subprocess.run(
        ["bash", "-c", script("Preview retained switching fixes")],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_WORKSPACE": str(tmp_path / "workspace"),
            "SOURCE_COMMIT": "a" * 40,
        },
        capture_output=True,
    )
    assert result.returncode == 1
    argv = json.loads(result.stdout)
    assert argv[:4] == ["run", "--no-sync", "python", "ops/retained_preview_progress.py"]
    assert argv[argv.index("--database") + 1] == str(tmp_path / "private-home/data/intel.sqlite3")
    assert argv[argv.index("--public") + 1] == str(tmp_path / "private-retained-public")
    assert argv[argv.index("--output") + 1] == str(tmp_path / "retained-preview-result.json")
    assert argv[argv.index("--source-commit") + 1] == "a" * 40


@pytest.mark.parametrize("bad", [False, True])
def test_retained_progress_is_fresh_validated_inside_existing_artifact(tmp_path, bad):
    value = {
        "schema_version": 1,
        "events": [
            {
                "event": "phase",
                "phase": "retained.sources",
                "state": "started",
                "elapsed_seconds": 0,
            }
        ],
    }
    if bad:
        value["events"][0]["raw"] = "PRIVATE"
    (tmp_path / "retained-preview-progress.json").write_text(json.dumps(value))
    result = execute(
        "Sanitize result metadata",
        tmp_path,
        RUNNER_TEMP=str(tmp_path),
        SOURCE_COMMIT="a" * 40,
        STAGE_OUTCOME="skipped",
        RETAINED_ONLY="true",
        RETAINED_OUTCOME="failure",
    )
    assert result.returncode == 0, result.stderr
    raw = (tmp_path / "certification-result/result.json").read_text()
    summary = json.loads(raw)
    assert "PRIVATE" not in raw
    if bad:
        assert "retained_progress" not in summary
    else:
        assert summary["retained_progress"] == value
    assert summary["retained_receipt_status"] == "missing"
