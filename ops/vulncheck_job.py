"""Private scheduled VulnCheck collection with isolated encrypted recovery."""

import argparse
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet

from infrastructure_impact.collection import vulncheck_kev
from infrastructure_impact.storage.remote_recovery import BACKEND, GitHubDraftStore
from ops import hosted_job

STATE_PATH = "vulncheck-state/current.json"
LIMIT = 512 * 1024 * 1024
ERRORS = {"credentials_missing", "rate_limited", "access_denied", "http_error", "source_rejected"}


def _git(checkout, *args, checked=True):
    return subprocess.run(
        ["git", "-C", str(checkout), *args],
        check=checked,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def commit_pointer(checkout, *, push=None):
    """Commit exactly one metadata file, never unrelated collector state."""
    checkout = Path(checkout)
    if _git(checkout, "diff", "--quiet", "HEAD", "--", STATE_PATH, checked=False).returncode == 0:
        if _git(checkout, "ls-files", "--error-unmatch", STATE_PATH, checked=False).returncode == 0:
            return False
    _git(checkout, "add", "--", STATE_PATH)
    _git(
        checkout,
        "-c",
        "user.name=Infrastructure Impact collector",
        "-c",
        "user.email=collector@users.noreply.github.com",
        "commit",
        "--only",
        "-m",
        "Retain encrypted VulnCheck collection checkpoint",
        "--",
        STATE_PATH,
    )
    if push is not None:
        push(checkout)
    else:
        _git(checkout, "push", "origin", "HEAD:publication-state")
    return True


def execute(checkout, *, environ=None, store=None, collector=None, commit=None):
    """Return only fixed status fields, including on recovery and provider errors."""
    env = os.environ if environ is None else environ
    result = dict(
        schema_version=1,
        source_id="vulncheck-kev",
        enabled=True,
        checked_at=datetime.now(timezone.utc).isoformat(),
        collection_outcome="not_run",
        error_code=None,
        retry_at=None,
        revision_id=None,
        private_recovery_verified=False,
        checkpoint_updated=False,
        checkpoint_persisted=False,
    )
    stage = "configuration_invalid"
    try:
        checkout = Path(checkout)
        state = checkout / "vulncheck-state"
        if checkout.is_symlink() or not checkout.is_dir() or state.is_symlink():
            raise ValueError("Invalid dedicated state path")
        if state.exists() and (
            not state.is_dir()
            or any(
                p.name != "current.json" or p.is_symlink() or not p.is_file()
                for p in state.iterdir()
            )
        ):
            raise ValueError("Unexpected dedicated state files")
        if not re.fullmatch(r"[a-f0-9]{40}", env.get("IMPACT_SOURCE_COMMIT", "")):
            raise ValueError("Pinned source required")
        key = env.get("IMPACT_STATE_KEY", "")
        Fernet(key)
        if store is None:
            store = GitHubDraftStore(env.get("GITHUB_REPOSITORY"), token=env.get("GH_TOKEN"))
        if collector is None:

            def collector(path, *, force):
                return vulncheck_kev.collect(
                    path, token=env.get("VULNCHECK_API_TOKEN", ""), force=force
                )

        pointer = state / "current.json"
        if pointer.exists():
            if pointer.stat().st_size > 2_000_000:
                raise ValueError("Oversized recovery metadata")
            metadata = json.loads(pointer.read_bytes())
            if (
                metadata.get("storage_backend") != BACKEND
                or metadata.get("encryption") != "fernet-v1"
            ):
                raise ValueError("Encrypted remote recovery required")
        with tempfile.TemporaryDirectory(prefix="impact-vulncheck-") as temporary:
            database = Path(temporary) / "private.sqlite"
            stage = "restore_failed"
            restored = hosted_job.restore_current(
                state, database, key, store=store, vault_limit_bytes=LIMIT
            )
            stage = "collection_failed"
            # Verify daily despite jitter; unchanged hashes still reuse the ZIP.
            collected = collector(database, force=True)
            outcome = collected.get("outcome")
            if outcome not in {"ok", "cached", "failed", "deferred"}:
                raise ValueError("Unexpected collection outcome")
            result["collection_outcome"] = outcome
            code = collected.get("error_code")
            result["error_code"] = (
                code if code in ERRORS else "collection_failed" if outcome == "failed" else None
            )
            retry = collected.get("retry_at")
            if retry is not None:
                vulncheck_kev._date(retry)
            result["retry_at"] = retry
            revision = collected.get("revision_id")
            if type(revision) is int and revision > 0:
                result["revision_id"] = revision
            if restored and outcome in {"cached", "deferred"}:
                result.update(private_recovery_verified=True, checkpoint_persisted=True)
                return result
            stage = "recovery_failed"
            hosted_job.backup_remote(
                state, database, key, store=store, compression="gzip", vault_limit_bytes=LIMIT
            )
            result.update(private_recovery_verified=True, checkpoint_updated=True)
            stage = "pointer_commit_failed"
            (commit or commit_pointer)(checkout)
            result["checkpoint_persisted"] = True
    except Exception:
        result["error_code"] = stage  # Never format remote errors, tokens or data.
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.receipt.resolve().is_relative_to(args.checkout.resolve()) or args.receipt.is_symlink():
        parser.error("Status receipt must be outside the service checkout")
    result = execute(args.checkout)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.receipt, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream)
        stream.write("\n")
    print(json.dumps(result))
    success = (
        result["collection_outcome"] in {"ok", "cached"}
        and result["checkpoint_persisted"]
        and result["error_code"] is None
    )
    if not success and os.environ.get("GITHUB_ACTIONS") == "true":
        print(
            "::warning title=VulnCheck collection::Private collection did not complete; inspect the status receipt."
        )
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
