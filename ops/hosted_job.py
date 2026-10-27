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
import lzma
import os
import re
import shutil
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

MAX_VAULT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_DECODER_MEMORY = 64 * 1024 * 1024
BLOCK_BYTES = 1024 * 1024


def expanded_chunks(compressed, compression):
    """Bound decoder memory and each output block before writing private state."""
    if compression == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as source:
            while block := source.read(BLOCK_BYTES):
                yield block
        return
    if compression != "xz":
        raise ValueError("Unsupported private backup compression")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_DECODER_MEMORY)
    offset = 0
    try:
        while not decoder.eof:
            chunk = b""
            if decoder.needs_input:
                chunk = compressed[offset : offset + BLOCK_BYTES]
                offset += len(chunk)
                if not chunk:
                    raise ValueError("Truncated private XZ backup")
            block = decoder.decompress(chunk, max_length=BLOCK_BYTES)
            if block:
                yield block
        if decoder.unused_data or offset != len(compressed):
            raise ValueError("Unexpected trailing data in private XZ backup")
    except lzma.LZMAError as error:
        raise ValueError("Private XZ backup is corrupt or exceeds decoder memory limit") from error


def validate_encrypted_state(state, encryption_key):
    """Authenticate every tracked recovery copy before the workflow commits it."""
    from cryptography.fernet import Fernet

    if not encryption_key:
        raise ValueError("Encrypted state validation requires the dedicated recovery key")
    if state.is_symlink() or (state / "current.json").is_symlink():
        raise ValueError("Encrypted state must use regular recovery files")
    manifest = json.loads((state / "current.json").read_text())
    if not isinstance(manifest, dict) or manifest.get("encryption") != "fernet-v1":
        raise ValueError("Public-runner state must contain only encrypted backups")
    pattern = r"vault-\d{8}T\d{12}Z\.sqlite3\.(?:gz|xz)\.fernet"
    if (
        not isinstance(manifest.get("archive"), str)
        or not re.fullmatch(pattern, manifest["archive"])
        or not isinstance(manifest.get("sha256"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", manifest["sha256"])
        or manifest.get("compression", "gzip") not in ("gzip", "xz")
    ):
        raise ValueError("Invalid encrypted recovery manifest")
    archives = {}
    cipher = Fernet(encryption_key)
    for path in state.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("Unexpected entry in encrypted state directory")
        if path.name == "current.json":
            continue
        if not re.fullmatch(pattern, path.name):
            raise ValueError("Unexpected file in encrypted state directory")
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("Encrypted state archive exceeds supported size")
        raw = path.read_bytes()
        cipher.decrypt(raw)  # Authentication only; no decompression or plaintext file.
        archives[path.name] = hashlib.sha256(raw).hexdigest()
    if archives.get(manifest.get("archive")) != manifest.get("sha256"):
        raise ValueError("Encrypted state manifest does not match a recovery copy")
    return True


def restore(state, database, encryption_key=None):
    receipt = state / "current.json"
    if not receipt.exists():
        if list(state.glob("vault-*")):
            raise ValueError(
                "Backup archives exist without a current manifest; manual recovery required"
            )
        return False
    manifest = json.loads(receipt.read_text())
    compression = manifest.get("compression", "gzip")  # Legacy manifests used gzip.
    if compression not in ("gzip", "xz"):
        raise ValueError("Unsupported private backup compression")
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
    if database.exists() or database.is_symlink():
        raise FileExistsError(database)
    # Validate a private staging file first. Failed decoding or integrity checks
    # must not leave a partial database at the requested recovery path.
    pending = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".restore-", dir=database.parent, delete=False
        ) as target:
            pending = Path(target.name)
            count = 0
            for block in expanded_chunks(compressed, compression):
                count += len(block)
                if count > MAX_VAULT_BYTES:
                    raise ValueError(
                        "Restored vault exceeds supported size; manual migration required"
                    )
                target.write(block)
        with pending.open("rb") as restored:
            if restored.read(16) != b"SQLite format 3\x00":
                raise ValueError("Restored vault is not a SQLite database")
        with closing(sqlite3.connect(pending.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("Restored vault integrity check failed")
        # Same-filesystem hard linking is atomic and refuses an existing target.
        os.link(pending, database)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    return True


def backup(state, database, encryption_key=None, *, compression="xz"):
    if compression not in ("gzip", "xz"):
        raise ValueError("Unsupported private backup compression")
    state.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    suffix = ".xz" if compression == "xz" else ".gz"
    name = "vault-" + stamp + ".sqlite3" + suffix + (".fernet" if encryption_key else "")
    with tempfile.TemporaryDirectory() as directory:
        copy = Path(directory) / "vault.sqlite3"
        with (
            closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as source,
            closing(sqlite3.connect(copy)) as target,
        ):
            source.backup(target)
        database_bytes = copy.stat().st_size
        if database_bytes > MAX_VAULT_BYTES:
            raise ValueError("Vault size limit reached; move to persistent-host deployment")
        # Compression and encryption happen outside the tracked state tree.
        # Abrupt termination must never leave a plaintext file named *.fernet
        # where an always-run workflow step could accidentally commit it.
        private_pending = Path(directory) / ("compressed" + suffix)
        pending = state / ("." + name)
        try:
            compressor = (
                lzma.open(private_pending, "wb", format=lzma.FORMAT_XZ, preset=6)
                if compression == "xz"
                else gzip.open(private_pending, "wb", compresslevel=9)
            )
            with copy.open("rb") as source, compressor as target:
                shutil.copyfileobj(source, target)
            compressed_bytes = private_pending.stat().st_size
            if compressed_bytes > MAX_ARCHIVE_BYTES:
                raise ValueError("Compressed private vault exceeds repository storage budget")
            if encryption_key:
                from cryptography.fernet import Fernet

                private_pending.write_bytes(
                    Fernet(encryption_key).encrypt(private_pending.read_bytes())
                )
                if private_pending.stat().st_size > MAX_ARCHIVE_BYTES:
                    raise ValueError("Encrypted backup exceeds repository storage budget")
            shutil.copyfile(private_pending, pending)
            pending.replace(state / name)
        finally:
            pending.unlink(missing_ok=True)
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
        "compression": compression,
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
    parser.add_argument("--output", type=Path)
    parser.add_argument("--base-path", default="/")
    parser.add_argument("--encrypted-state", action="store_true")
    parser.add_argument("--backup-compression", choices=("xz", "gzip"), default="xz")
    parser.add_argument("--validate-encrypted-state", action="store_true")
    args = parser.parse_args()
    encryption_key = os.environ.get("IMPACT_STATE_KEY") if args.encrypted_state else None
    if args.encrypted_state and not encryption_key:
        parser.error("Encrypted public-runner state requires IMPACT_STATE_KEY")
    if args.validate_encrypted_state:
        if not args.encrypted_state:
            parser.error("State validation requires --encrypted-state")
        validate_encrypted_state(args.state_dir.resolve(), encryption_key)
        print(json.dumps({"encrypted_state": "authenticated"}))
        return
    if args.output is None:
        parser.error("Collection requires --output")
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
                backup(state, database, encryption_key, compression=args.backup_compression)
                # Exercise the just-written format on this runner, including
                # authentication, bounded decoding and SQLite integrity.
                restore(state, home / "recovery-check.sqlite3", encryption_key)
        print(
            json.dumps(
                {
                    "outcome": result["outcome"],
                    "failures": result["failures"],
                    "public_output": str(output),
                    "private_backup": "saved",
                    "private_recovery": "verified",
                }
            )
        )


if __name__ == "__main__":
    main()
