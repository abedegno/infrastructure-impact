"""Read-only backup retention accounting. Never downloads ciphertext or a key."""

import argparse
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

BUDGET = 512 * 1024 * 1024
ARCHIVE_LIMIT = 50 * 1024 * 1024
VAULT_LIMIT = 512 * 1024 * 1024


def summarize(
    trees, repository_size_kib, manifest, history_limit=100, checked_at=None, repository=None
):
    if not trees:
        raise ValueError("No backup branch history available")
    unique = {
        p["sha"]: p["size"]
        for tree in trees
        for p in tree
        if p.get("path", "").startswith("state/vault-")
        and p["path"].endswith(".fernet")
        and p.get("type") == "blob"
    }
    current = [
        p
        for p in trees[0]
        if p.get("path", "").startswith("state/vault-") and p["path"].endswith(".fernet")
    ]
    latest = next((p for p in current if p["path"] == "state/" + manifest["archive"]), None)
    backend = manifest.get("storage_backend", "git")
    remote = backend == "github-draft-release-v1"
    if remote:
        pointer = manifest.get("remote", {})
        if (
            not isinstance(pointer, dict)
            or not isinstance(pointer.get("repository"), str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pointer["repository"])
            or (repository is not None and pointer["repository"] != repository)
            or any(
                type(pointer.get(k)) is not int or pointer[k] < 1
                for k in ("release_id", "asset_id")
            )
            or not isinstance(manifest.get("remote_readback_verified_at"), str)
            or not isinstance(manifest.get("archive"), str)
            or not re.fullmatch(
                r"vault-\d{8}T\d{12}Z\.sqlite3\.(?:gz|xz)\.fernet", manifest["archive"]
            )
            or type(manifest.get("archive_bytes")) is not int
            or manifest["archive_bytes"] < 1
        ):
            raise ValueError("Remote recovery metadata or writer readback receipt is invalid")
        verified_at = datetime.fromisoformat(
            manifest["remote_readback_verified_at"].replace("Z", "+00:00")
        )
        if verified_at.tzinfo is None:
            raise ValueError("Remote recovery verification time requires a timezone")
        latest = {"size": manifest["archive_bytes"]}
    if (
        backend not in ("git", "github-draft-release-v1")
        or latest is None
        or latest.get("size", 0) < 1
        or manifest.get("encryption") != "fernet-v1"
    ):
        raise ValueError(
            "Current encrypted backup is missing or manifest encryption is unsupported"
        )
    reported = repository_size_kib * 1024
    compression = manifest.get("compression", "gzip")
    if compression not in ("gzip", "xz"):
        raise ValueError("Unsupported private backup compression in manifest")
    database_bytes = manifest.get("database_bytes")
    if database_bytes is not None and (type(database_bytes) is not int or database_bytes < 0):
        raise ValueError("Invalid uncompressed vault size in manifest")
    findings = []
    if not remote and len(current) != 3:
        findings.append("Current tree does not yet contain exactly three encrypted recovery copies")
    if len(trees) >= history_limit:
        findings.append("History is bounded; older logical backup data may be omitted")
    if reported >= BUDGET * 0.8:
        findings.append("Reported repository storage has reached 80 percent of the review budget")
    if sum(unique.values()) >= BUDGET:
        findings.append(
            "Retained logical encrypted backup bytes have reached the review budget; packed storage is a separate measurement"
        )
    if latest["size"] >= ARCHIVE_LIMIT * 0.8:
        findings.append("Latest encrypted archive has reached 80 percent of its per-file limit")
    if database_bytes is not None and database_bytes >= VAULT_LIMIT * 0.8:
        findings.append("Uncompressed vault has reached 80 percent of its supported size")
    required = (
        reported >= BUDGET
        or latest["size"] >= ARCHIVE_LIMIT
        or (database_bytes is not None and database_bytes >= VAULT_LIMIT)
    )
    if required:
        findings.append(
            "Storage limits require operator review; no history or recovery data was deleted"
        )
    if remote:
        findings.append(
            "New encrypted recovery assets are append-only unpublished drafts outside Git history; legacy Git copies remain retained"
        )
    return dict(
        schema_version=1,
        checked_at=checked_at or datetime.now(timezone.utc).isoformat(),
        retention=dict(
            current_tree_target_copies=None if remote else 3,
            current_tree_copies=len(current),
            current_tree_bytes=sum(p["size"] for p in current),
            historical_copies_retained_in_git=True,
            automatic_history_deletion=False,
            current_tree_copies_are_legacy=remote,
            remote_assets="append_only" if remote else None,
        ),
        history=dict(
            commits_inspected=len(trees),
            history_limit=history_limit,
            may_be_truncated=len(trees) >= history_limit,
            unique_backup_blobs=len(unique),
            logical_backup_blob_bytes=sum(unique.values()),
        ),
        latest_archive_bytes=latest["size"],
        storage_backend=backend,
        recovery_verification_source="writer_remote_readback_receipt"
        if remote
        else "tracked_archive_metadata",
        remote_readback_verified_at=manifest.get("remote_readback_verified_at") if remote else None,
        compression=compression,
        latest_database_bytes=database_bytes,
        uncompressed_vault_limit_bytes=VAULT_LIMIT,
        reported_repository_bytes=reported,
        repository_review_budget_bytes=BUDGET,
        per_archive_limit_bytes=ARCHIVE_LIMIT,
        remaining_runs_scenario=None if remote else max(0, (BUDGET - reported) // latest["size"]),
        storage_review_required=required,
        findings=findings,
        limitations=[
            "GitHub repository size can lag changes. Logical blob sizes are not measured packed Git storage.",
            "The remaining-runs scenario assumes one new backup per run at the latest archive size, no compression savings and no other growth. It is not a time-to-exhaustion prediction.",
            "Removing old files from the current tree does not remove their history. No history or recovery copy is automatically deleted.",
            "For draft-asset storage, the read-only monitor inspects pointer metadata and the writer's readback receipt. It cannot independently authenticate encrypted content or attest draft visibility; the writer validates both before committing the pointer.",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("Expected owner/repository")

    def get(path, raw=False):
        command = ["gh", "api", ("repos/" + args.repository + "/" + path).rstrip("/")]
        if raw:
            command += ["-H", "Accept: application/vnd.github.raw+json"]
        return json.loads(subprocess.check_output(command, text=True))

    meta = get("")
    commits = get("commits?sha=publication-state&per_page=100")
    if not commits:
        raise ValueError("Backup branch history unavailable")

    def tree(commit):
        value = get("git/trees/" + commit["commit"]["tree"]["sha"] + "?recursive=1")
        if value.get("truncated"):
            raise ValueError("Backup tree metadata was truncated")
        return value["tree"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        trees = list(pool.map(tree, commits))
    # Bind the manifest to the inspected head commit, avoiding a moving-branch race.
    manifest = get("contents/state/current.json?ref=" + commits[0]["sha"], True)
    report = summarize(trees, meta["size"], manifest, repository=args.repository)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.summary:
        with args.summary.open("a") as stream:
            stream.write(
                "\n## Encrypted backup storage\n\n```json\n"
                + json.dumps(report, indent=2)
                + "\n```\n"
            )
    print(
        json.dumps(
            {
                k: report[k]
                for k in [
                    "latest_archive_bytes",
                    "reported_repository_bytes",
                    "storage_review_required",
                ]
            }
        )
    )
    if report["storage_review_required"]:
        raise SystemExit("Backup storage requires operator review; no data deleted")


if __name__ == "__main__":
    main()
