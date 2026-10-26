"""Scheduled writer for a private service repository; publish only its public output.

The unencrypted state directory must remain private. The public-runner mode
requires authenticated encryption and a dedicated secret key. Neither form of
state may be passed to a Pages/artifact upload action.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

MAX_VAULT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024


def restore(state, database, encryption_key=None):
    receipt = state / "current.json"
    if not receipt.exists():
        if list(state.glob("vault-*")):
            raise ValueError(
                "Backup archives exist without a current manifest; manual recovery required"
            )
        return False
    manifest = json.loads(receipt.read_text())
    name = manifest["archive"]
    if Path(name).name != name:
        raise ValueError("Invalid backup filename")
    archive = state / name
    if (
        archive.stat().st_size > MAX_ARCHIVE_BYTES
        or hashlib.sha256(archive.read_bytes()).hexdigest() != manifest["sha256"]
    ):
        raise ValueError("Private backup size or fingerprint check failed")
    compressed = archive.read_bytes()
    if manifest.get("encryption") == "fernet-v1":
        from cryptography.fernet import Fernet

        if not encryption_key:
            raise ValueError("Encrypted backup requires the dedicated recovery key")
        compressed = Fernet(encryption_key).decrypt(compressed)
    elif encryption_key:
        raise ValueError("Public-runner state must never contain a plaintext backup")
    database.parent.mkdir(parents=True, exist_ok=True)
    with (
        gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as source,
        database.open("xb") as target,
    ):
        count = 0
        while block := source.read(1024 * 1024):
            count += len(block)
            if count > MAX_VAULT_BYTES:
                raise ValueError("Restored vault exceeds supported size; manual migration required")
            target.write(block)
    with closing(sqlite3.connect(database)) as db:
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Restored vault integrity check failed")
    return True


def backup(state, database, encryption_key=None):
    state.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    name = "vault-" + stamp + ".sqlite3.gz" + (".fernet" if encryption_key else "")
    with tempfile.TemporaryDirectory() as directory:
        copy = Path(directory) / "vault.sqlite3"
        with closing(sqlite3.connect(database)) as source, closing(sqlite3.connect(copy)) as target:
            source.backup(target)
        database_bytes = copy.stat().st_size
        if database_bytes > MAX_VAULT_BYTES:
            raise ValueError("Vault size limit reached; move to persistent-host deployment")
        pending = state / ("." + name)
        with copy.open("rb") as source, gzip.open(pending, "wb") as target:
            shutil.copyfileobj(source, target)
        compressed_bytes = pending.stat().st_size
        if compressed_bytes > MAX_ARCHIVE_BYTES:
            pending.unlink()
            raise ValueError("Compressed private vault exceeds repository storage budget")
        if encryption_key:
            from cryptography.fernet import Fernet

            pending.write_bytes(Fernet(encryption_key).encrypt(pending.read_bytes()))
            if pending.stat().st_size > MAX_ARCHIVE_BYTES:
                pending.unlink()
                raise ValueError("Encrypted backup exceeds repository storage budget")
        pending.replace(state / name)
    manifest = {
        "archive": name,
        "sha256": hashlib.sha256((state / name).read_bytes()).hexdigest(),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": os.environ.get("IMPACT_SOURCE_COMMIT", "local"),
        "private": True,
        "database_bytes": database_bytes,
        "compressed_bytes": compressed_bytes,
        "archive_bytes": (state / name).stat().st_size,
        "retention": {"current_directory_copy_target": 3, "git_history_pruned": False},
        "encryption": "fernet-v1" if encryption_key else None,
    }
    temp = state / ".current.json"
    temp.write_text(json.dumps(manifest, indent=2) + "\n")
    temp.replace(state / "current.json")
    # This directory is service-owned. Git history retains previous private states.
    for previous in sorted(state.glob("vault-*"))[:-3]:
        previous.unlink()
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--base-path", default="/")
    parser.add_argument("--encrypted-state", action="store_true")
    args = parser.parse_args()
    encryption_key = os.environ.get("IMPACT_STATE_KEY") if args.encrypted_state else None
    if args.encrypted_state and not encryption_key:
        parser.error("Encrypted public-runner state requires IMPACT_STATE_KEY")
    state, output = args.state_dir.resolve(), args.output.resolve()
    if state == output or state.is_relative_to(output) or output.is_relative_to(state):
        parser.error("Private state and public output must be separate directory trees")
    with tempfile.TemporaryDirectory(prefix="impact-writer-") as directory:
        home = Path(directory)
        database = home / "data/intel.sqlite3"
        restore(state, database, encryption_key)
        os.environ.update(
            IMPACT_HOME=str(home),
            IMPACT_DATABASE=str(database),
            IMPACT_SNAPSHOT=str(output),
            IMPACT_BASE_PATH=args.base_path,
            IMPACT_DELIVERY_MODE="scheduled_static",
        )
        (home / "ops").mkdir()
        (home / "ops/schedule-status.json").write_text(
            json.dumps(
                {
                    "installed": True,
                    "kind": "github_actions",
                    "local_time": "08:37",
                    "timezone": "UTC",
                    "cron_utc": "37 8 * * *",
                }
            )
        )
        from infrastructure_impact.storage.audit import audit
        from infrastructure_impact.worker import collect_once

        try:
            result = collect_once()
            if result["outcome"] not in ("ok", "partial"):
                raise RuntimeError(
                    "No successful collection; existing public deployment is retained"
                )
            audit()
        finally:
            if database.exists():
                backup(state, database, encryption_key)
        print(
            json.dumps(
                {
                    "outcome": result["outcome"],
                    "failures": result["failures"],
                    "public_output": str(output),
                    "private_backup": "saved",
                }
            )
        )


if __name__ == "__main__":
    main()
