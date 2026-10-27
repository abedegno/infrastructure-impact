"""Opt-in recovery headroom remains bounded and never changes retained evidence."""

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from checks.backup_storage import summarize
from infrastructure_impact.recovery_policy import VAULT_PROFILES, checked_limit, vault_limit
from infrastructure_impact.storage.profiling import storage_profile
from infrastructure_impact.storage.repository import connect
from ops import hosted_job as hosted

ROOT = Path(__file__).resolve().parents[1]


def synthetic_vault(path):
    with connect(path) as db:
        db.execute(
            "INSERT INTO evidence(source_url,sha256,observed_at,raw,media_type) VALUES(?,?,?,?,?)",
            (
                "https://private.example/PRIVATE_SENTINEL",
                "a" * 64,
                "2026-10-27T00:00:00Z",
                b"PRIVATE_SENTINEL" * 1000,
                "test",
            ),
        )
        db.execute("CREATE TABLE private_extension(secret TEXT)")
        db.execute("INSERT INTO private_extension VALUES('PRIVATE_SENTINEL')")
    return path


def test_storage_profile_is_read_only_aggregate_and_counts_unicode_bytes(tmp_path):
    database = synthetic_vault(tmp_path / "source.sqlite3")
    with sqlite3.connect(database) as db:
        db.execute(
            "INSERT INTO documents(evidence_id,vendor,product,document_type,source_url,text) VALUES(1,'test','test','test','https://private.example',?)",
            ("é🦅",),
        )
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    db = connect(database, read_only=True)
    try:
        profile = storage_profile(db)
        assert not db.in_transaction
        assert {r["table"] for r in profile["tables"]} <= {
            "evidence",
            "revisions",
            "changes",
            "documents",
            "reference_documents",
            "collection_runs",
            "pipeline_runs",
            "browser_captures",
        }
        doc = next(r for r in profile["tables"] if r["table"] == "documents")
        assert doc["tracked_payload_bytes"] == len("é🦅".encode())
        assert "PRIVATE_SENTINEL" not in json.dumps(profile)
        assert "private.example" not in json.dumps(profile)
        assert "private_extension" not in json.dumps(profile)
        db.execute("BEGIN")
        storage_profile(db)
        assert db.in_transaction  # Never close a caller's transaction.
        db.rollback()
    finally:
        db.close()
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("profile", ["standard", "large"])
def test_profile_flows_through_backup_and_recovery_without_manifest_selecting_limit(
    tmp_path, profile
):
    source = synthetic_vault(tmp_path / "source.sqlite3")
    key = Fernet.generate_key()
    selected = vault_limit(profile)
    manifest = hosted.backup(tmp_path / "state", source, key, vault_limit_bytes=selected)
    assert manifest["vault_limit_bytes"] == selected
    assert manifest["storage_profile"]["database_page_bytes"] == manifest["database_bytes"]
    assert hosted.restore(
        tmp_path / "state", tmp_path / "restored.sqlite3", key, vault_limit_bytes=selected
    )
    with sqlite3.connect(source) as before, sqlite3.connect(tmp_path / "restored.sqlite3") as after:
        assert list(before.iterdump()) == list(after.iterdump())
    # A manifest cannot enlarge the caller's selected recovery bound.
    manifest["vault_limit_bytes"] = VAULT_PROFILES["large"]
    (tmp_path / "state/current.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="exceeds supported"):
        hosted.restore(
            tmp_path / "state", tmp_path / "too-small.sqlite3", key, vault_limit_bytes=1024
        )
    assert not (tmp_path / "too-small.sqlite3").exists()


@pytest.mark.parametrize("value", [True, 0, -1, 1024 * 1024 * 1024 + 1, float("inf"), "large"])
def test_internal_byte_budgets_cannot_be_unbounded(value):
    with pytest.raises(ValueError):
        checked_limit(value)


def test_monitor_uses_configured_profile_and_keeps_other_budgets_unchanged():
    tree = [[dict(path="state/vault-test.xz.fernet", type="blob", size=100, sha="synthetic")]]
    manifest = dict(
        archive="vault-test.xz.fernet",
        encryption="fernet-v1",
        database_bytes=600 * 1024 * 1024,
        vault_limit_bytes=VAULT_PROFILES["large"],
    )
    standard = summarize(tree, 1, manifest)
    large = summarize(tree, 1, manifest, vault_profile="large")
    assert standard["storage_review_required"] and not large["storage_review_required"]
    assert large["uncompressed_vault_limit_bytes"] == 1024 * 1024 * 1024
    assert (
        standard["repository_review_budget_bytes"]
        == large["repository_review_budget_bytes"]
        == 512 * 1024 * 1024
    )
    assert (
        standard["per_archive_limit_bytes"] == large["per_archive_limit_bytes"] == 50 * 1024 * 1024
    )
    with pytest.raises(ValueError):
        summarize(tree, 1, {**manifest, "vault_limit_bytes": 2**50}, vault_profile="large")
    with pytest.raises(ValueError):
        vault_limit("unlimited")


def test_storage_cli_and_standalone_monitor_need_no_writer_or_runtime_dependencies(
    tmp_path, capsys
):
    from infrastructure_impact.cli import main

    source = synthetic_vault(tmp_path / "source.sqlite3")
    with patch.dict("os.environ", IMPACT_DATABASE=str(source)):
        main(["audit", "--storage"])
    assert json.loads(capsys.readouterr().out)["tables"]
    # -S excludes site packages and -I ignores checkout PYTHONPATH. The policy
    # import must still work without jsonschema, cryptography or the runtime.
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(ROOT / "checks/backup_storage.py"), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0 and "--vault-profile" in result.stdout


def test_profile_policy_is_shared_with_installed_operator_code():
    import infrastructure_impact.recovery_policy as policy

    assert hosted.MAX_ARCHIVE_BYTES == policy.ARCHIVE_LIMIT
    assert hosted.MAX_DECODER_MEMORY == policy.DECODER_MEMORY_LIMIT
    assert hosted.MAX_VAULT_BYTES == policy.vault_limit("standard")
    assert policy.vault_limit("large") == 2 * policy.vault_limit("standard")


def test_distribution_probe_cannot_silently_select_an_older_wheel(tmp_path):
    from checks.distribution import release_wheel

    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.5.0"\n')
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/infrastructure_impact-0.4.1-py3-none-any.whl").touch()
    with pytest.raises(ValueError, match="declared package version"):
        release_wheel(tmp_path)
    current = tmp_path / "dist/infrastructure_impact-0.5.0-py3-none-any.whl"
    current.touch()
    assert release_wheel(tmp_path) == current
    (tmp_path / "dist/infrastructure_impact-0.5.0-py3-none-other.whl").touch()
    with pytest.raises(ValueError, match="exactly one"):
        release_wheel(tmp_path)


def test_hosted_workflow_profiles_and_declared_schedule_stay_aligned():
    collection = (ROOT / ".github/workflows/collect.yaml").read_text()
    monitor = (ROOT / ".github/workflows/monitor.yaml").read_text()
    assert collection == (ROOT / "deploy/github-public-service.yaml").read_text()
    assert "cron: '43 12 * * *'" in collection
    assert "--schedule-utc 12:43" in collection
    assert "recovery_args+=(--recovery-storage" in collection
    assert "VAULT_PROFILE" in collection and '--vault-profile "$VAULT_PROFILE"' in collection
    assert "cron: '23 */6 * * *'" in monitor
    assert '--vault-profile "$VAULT_PROFILE"' in monitor
    assert "IMPACT_SCHEDULE_OBSERVATION_START" in monitor
    assert "IMPACT_RELIABILITY_START" in monitor
