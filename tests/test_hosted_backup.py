"""Recovery compatibility, bounded decoding and failure atomicity for private state."""

import gzip
import hashlib
import json
import lzma
import os
import sqlite3
import subprocess
import sys
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from ops import hosted_job as hosted


def vault(path):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE retained(value BLOB)")
        db.execute("INSERT INTO retained VALUES(?)", (b"PRIVATE SYNTHETIC EVIDENCE" * 2000,))


@pytest.mark.parametrize("compression", ["gzip", "xz"])
@pytest.mark.parametrize("encrypted", [False, True])
def test_recovery_formats_preserve_all_evidence(tmp_path, compression, encrypted):
    database = tmp_path / "source.sqlite3"
    vault(database)
    key = Fernet.generate_key() if encrypted else None
    state = tmp_path / "state"
    receipt = hosted.backup(state, database, key, compression=compression)
    assert receipt["compression"] == compression
    assert receipt["encryption"] == ("fernet-v1" if encrypted else None)
    target = tmp_path / "restored.sqlite3"
    assert hosted.restore(state, target, key)
    with sqlite3.connect(target) as db:
        assert (
            db.execute("SELECT value FROM retained").fetchone()[0]
            == b"PRIVATE SYNTHETIC EVIDENCE" * 2000
        )
    payload = (state / receipt["archive"]).read_bytes()
    if key:
        payload = Fernet(key).decrypt(payload)
    expected = gzip.decompress(payload) if compression == "gzip" else lzma.decompress(payload)
    assert target.read_bytes() == expected
    assert not list(tmp_path.glob(".restore-*"))


def test_legacy_gzip_manifest_without_compression_still_restores(tmp_path):
    database = tmp_path / "source.sqlite3"
    vault(database)
    key = Fernet.generate_key()
    state = tmp_path / "state"
    manifest = hosted.backup(state, database, key, compression="gzip")
    manifest.pop("compression")
    (state / "current.json").write_text(json.dumps(manifest))
    assert hosted.restore(state, tmp_path / "legacy.sqlite3", key)


def state_bytes(folder, compressed, compression):
    folder.mkdir()
    name = "vault-synthetic.sqlite3." + compression
    (folder / name).write_bytes(compressed)
    (folder / "current.json").write_text(
        json.dumps(
            {
                "archive": name,
                "sha256": hashlib.sha256(compressed).hexdigest(),
                "compression": compression,
            }
        )
    )


@pytest.mark.parametrize(
    "fault",
    [
        "truncated",
        "trailing",
        "concatenated",
        "decoder_memory",
        "expanded_limit",
        "not_sqlite",
        "unknown_compression",
    ],
)
def test_invalid_recovery_never_leaves_a_partial_database(tmp_path, monkeypatch, fault):
    database = tmp_path / "source.sqlite3"
    vault(database)
    compressed = lzma.compress(database.read_bytes(), preset=6)
    compression = "xz"
    if fault == "truncated":
        compressed = compressed[:-3]
    elif fault == "trailing":
        compressed += b"unexpected"
    elif fault == "concatenated":
        compressed += lzma.compress(b"second stream")
    elif fault == "decoder_memory":
        monkeypatch.setattr(hosted, "MAX_DECODER_MEMORY", 1024)
    elif fault == "expanded_limit":
        monkeypatch.setattr(hosted, "MAX_VAULT_BYTES", 1024)
    elif fault == "not_sqlite":
        compressed = lzma.compress(b"")
    else:
        compression = "unknown"
    folder = tmp_path / "state"
    state_bytes(folder, compressed, compression)
    target = tmp_path / "target.sqlite3"
    with pytest.raises(ValueError):
        hosted.restore(folder, target)
    assert not target.exists()
    assert not list(tmp_path.glob(".restore-*"))


@pytest.mark.parametrize("fault", ["expanded_limit", "truncated"])
def test_gzip_expansion_limit_and_truncation_are_atomic_too(tmp_path, monkeypatch, fault):
    folder = tmp_path / "state"
    compressed = gzip.compress(b"X" * 4000)
    if fault == "truncated":
        compressed = compressed[:-3]
    else:
        monkeypatch.setattr(hosted, "MAX_VAULT_BYTES", 1024)
    state_bytes(folder, compressed, "gzip")
    with pytest.raises((ValueError, EOFError)):
        hosted.restore(folder, tmp_path / "target.sqlite3")
    assert not (tmp_path / "target.sqlite3").exists()
    assert not list(tmp_path.glob(".restore-*"))


def test_existing_recovery_target_is_never_overwritten(tmp_path):
    source = tmp_path / "source.sqlite3"
    vault(source)
    folder = tmp_path / "state"
    hosted.backup(folder, source)
    target = tmp_path / "keep.sqlite3"
    target.write_bytes(b"KEEP EXISTING DATA")
    with pytest.raises(FileExistsError):
        hosted.restore(folder, target)
    assert target.read_bytes() == b"KEEP EXISTING DATA"
    assert not list(tmp_path.glob(".restore-*"))


def test_failed_backup_keeps_current_manifest_and_no_plaintext_pending_file(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite3"
    vault(source)
    folder = tmp_path / "state"
    key = Fernet.generate_key()
    manifest = hosted.backup(folder, source, key)
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    with pytest.raises(ValueError):
        hosted.backup(folder, source, b"invalid key")
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before
    monkeypatch.setattr(hosted, "MAX_ARCHIVE_BYTES", 1)
    with pytest.raises(ValueError, match="storage budget"):
        hosted.backup(folder, source, key)
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before
    monkeypatch.setattr(hosted, "MAX_ARCHIVE_BYTES", manifest["compressed_bytes"] + 1)
    with pytest.raises(ValueError, match="Encrypted backup"):
        hosted.backup(folder, source, key)
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


def test_missing_source_does_not_create_an_empty_database_backup(tmp_path):
    source = tmp_path / "missing.sqlite3"
    with pytest.raises(sqlite3.OperationalError):
        hosted.backup(tmp_path / "state", source)
    assert not source.exists()
    assert not list((tmp_path / "state").iterdir())


def test_xz_decoder_output_is_yielded_in_bounded_blocks(monkeypatch):
    monkeypatch.setattr(hosted, "BLOCK_BYTES", 1024)
    data = b"source evidence" * 2000
    blocks = list(hosted.expanded_chunks(lzma.compress(data), "xz"))
    assert b"".join(blocks) == data and max(map(len, blocks)) <= 1024


def test_storage_report_checks_compression_and_uncompressed_size():
    from checks.backup_storage import VAULT_LIMIT, summarize

    assert VAULT_LIMIT == hosted.MAX_VAULT_BYTES
    tree = [
        [
            {
                "path": "state/vault-synthetic.xz.fernet",
                "type": "blob",
                "size": 100,
                "sha": "synthetic",
            }
        ]
    ]
    manifest = {
        "archive": "vault-synthetic.xz.fernet",
        "encryption": "fernet-v1",
        "compression": "xz",
        "database_bytes": VAULT_LIMIT,
    }
    report = summarize(tree, 1, manifest)
    assert report["compression"] == "xz" and report["latest_database_bytes"] == VAULT_LIMIT
    assert report["storage_review_required"] and any(
        "Uncompressed" in f for f in report["findings"]
    )
    legacy = summarize(tree, 1, {"archive": manifest["archive"], "encryption": "fernet-v1"})
    assert legacy["compression"] == "gzip" and legacy["latest_database_bytes"] is None
    with pytest.raises(ValueError):
        summarize(tree, 1, {**manifest, "compression": "unknown"})
    with pytest.raises(ValueError):
        summarize(tree, 1, {**manifest, "database_bytes": True})


def test_precommit_validation_authenticates_all_recovery_copies(tmp_path):
    from cryptography.fernet import InvalidToken

    source = tmp_path / "source.sqlite3"
    vault(source)
    state = tmp_path / "state"
    key = Fernet.generate_key()
    hosted.backup(state, source, key, compression="gzip")
    manifest = hosted.backup(state, source, key)
    assert hosted.validate_encrypted_state(state, key)
    archive = state / manifest["archive"]
    # A suffix and matching checksum do not prove that the file is encrypted.
    archive.write_bytes(gzip.compress(b"PLAINTEXT COMPRESSED SYNTHETIC EVIDENCE"))
    manifest["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    (state / "current.json").write_text(json.dumps(manifest))
    with pytest.raises(InvalidToken):
        hosted.validate_encrypted_state(state, key)


def test_precommit_validation_rejects_pending_files_and_incomplete_manifest(tmp_path):
    source = tmp_path / "source.sqlite3"
    vault(source)
    state = tmp_path / "state"
    key = Fernet.generate_key()
    hosted.backup(state, source, key)
    pending = state / ".pending.fernet"
    pending.write_bytes(b"incomplete")
    with pytest.raises(ValueError, match="Unexpected file"):
        hosted.validate_encrypted_state(state, key)
    pending.unlink()
    (state / "current.json").write_text(json.dumps({"encryption": "fernet-v1"}))
    with pytest.raises(ValueError, match="Invalid encrypted recovery manifest"):
        hosted.validate_encrypted_state(state, key)


def test_process_exit_during_encryption_cannot_leave_plaintext_in_tracked_state(tmp_path):
    source = tmp_path / "source.sqlite3"
    vault(source)
    state = tmp_path / "state"
    key = Fernet.generate_key()
    hosted.backup(state, source, key)
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    private_temp = tmp_path / "child-private"
    private_temp.mkdir()
    script = """import os
from pathlib import Path
from unittest.mock import patch
from cryptography.fernet import Fernet
from ops.hosted_job import backup
with patch.object(Fernet, "encrypt", lambda *_: os._exit(19)):
    backup(Path(os.environ["TEST_STATE"]), Path(os.environ["TEST_DATABASE"]), os.environ["TEST_KEY"])
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        env={
            **os.environ,
            "TMPDIR": str(private_temp),
            "TEST_STATE": str(state),
            "TEST_DATABASE": str(source),
            "TEST_KEY": key.decode(),
        },
        check=False,
    )
    assert result.returncode == 19
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before
    assert hosted.validate_encrypted_state(state, key)


@pytest.mark.parametrize("compression", ["gzip", "xz"])
def test_hosted_job_checks_its_new_encrypted_backup_before_reporting_success(
    tmp_path, monkeypatch, capsys, compression
):
    import infrastructure_impact.worker as worker
    from infrastructure_impact.storage.repository import connect, evidence

    key = Fernet.generate_key()

    def collect():
        with connect() as db:
            evidence(db, b"PRIVATE SYNTHETIC JOB EVIDENCE", "https://www.arista.com/synthetic")
        return {"outcome": "partial", "failures": 1}

    monkeypatch.setattr(worker, "collect_once", collect)
    state = tmp_path / "state"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hosted_job.py",
            "--state-dir",
            str(state),
            "--output",
            str(tmp_path / "public"),
            "--encrypted-state",
            "--backup-compression",
            compression,
        ],
    )
    with patch.dict(os.environ, {"IMPACT_STATE_KEY": key.decode()}):
        hosted.main()
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["private_recovery"] == "verified" and receipt["private_backup"] == "saved"
    assert hosted.validate_encrypted_state(state, key)
    target = tmp_path / "restored.sqlite3"
    assert hosted.restore(state, target, key)
    with connect(target, read_only=True) as db:
        assert (
            db.execute("SELECT raw FROM evidence").fetchone()[0]
            == b"PRIVATE SYNTHETIC JOB EVIDENCE"
        )


def test_state_validation_cli_needs_no_public_output_or_collection(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source.sqlite3"
    vault(source)
    state = tmp_path / "state"
    key = Fernet.generate_key()
    hosted.backup(state, source, key)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hosted_job.py",
            "--state-dir",
            str(state),
            "--encrypted-state",
            "--validate-encrypted-state",
        ],
    )
    with patch.dict(os.environ, {"IMPACT_STATE_KEY": key.decode()}):
        hosted.main()
    assert json.loads(capsys.readouterr().out) == {"encrypted_state": "authenticated"}
