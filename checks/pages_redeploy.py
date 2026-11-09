"""Verify one reviewed, accepted public Pages artifact before deployment.

Standard library only. This does not collect, rebuild, decrypt or promote state.
The receipt is trusted reviewed configuration; API metadata and archives are not.
"""

import argparse
import hashlib
import json
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

MAX_ARCHIVE_BYTES = 1_073_741_824
MAX_MEMBERS = 100_000
MAX_JSON_BYTES = 2_000_000
BLOCK_BYTES = 1024 * 1024
FIELDS = {
    "schema_version": int,
    "repository": str,
    "run_id": int,
    "run_attempt": int,
    "workflow_path": str,
    "head_sha": str,
    "source_commit": str,
    "artifact_id": int,
    "artifact_name": str,
    "artifact_zip_bytes": int,
    "artifact_zip_sha256": str,
    "tar_bytes": int,
    "tar_sha256": str,
    "generation": str,
    "accepted_manifest_sha256": str,
}
GATES = (
    "Restore, collect, audit and back up privately",
    "Check hosted helper effects",
    "Retain only encrypted recovery copies",
    "Run actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def read_json(path):
    require(not path.is_symlink() and path.is_file(), "JSON input must be a regular file")
    require(path.stat().st_size <= MAX_JSON_BYTES, "JSON input exceeds limit")
    return json.loads(path.read_bytes(), object_pairs_hook=closed_pairs)


def receipt_value(path):
    value = read_json(path)
    require(type(value) is dict and set(value) == set(FIELDS), "Unexpected receipt fields")
    require(all(type(value[key]) is kind for key, kind in FIELDS.items()), "Invalid receipt type")
    require(value["schema_version"] == 1, "Unsupported receipt version")
    require(
        re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", value["repository"]), "Invalid repository"
    )
    require(value["workflow_path"] == ".github/workflows/collect.yaml", "Unexpected workflow")
    require(value["artifact_name"] == "github-pages", "Unexpected artifact name")
    for field in ("run_id", "run_attempt", "artifact_id"):
        require(0 < value[field] < 2**63, "Invalid receipt identity")
    for field in ("artifact_zip_bytes", "tar_bytes"):
        require(0 < value[field] <= MAX_ARCHIVE_BYTES, "Invalid archive size bound")
    for field in ("head_sha", "source_commit"):
        require(re.fullmatch(r"[a-f0-9]{40}", value[field]), "Invalid commit pin")
    for field in ("artifact_zip_sha256", "tar_sha256", "accepted_manifest_sha256"):
        require(re.fullmatch(r"[a-f0-9]{64}", value[field]), "Invalid digest pin")
    require(re.fullmatch(r"[a-f0-9]{32}", value["generation"]), "Invalid generation pin")
    return value


def match(value, expected, message):
    require(type(value) is type(expected) and value == expected, message)


def verify_metadata(receipt, artifact, run, jobs):
    require(all(type(v) is dict for v in (artifact, run, jobs)), "Invalid API metadata")
    for key, expected in (
        ("id", receipt["artifact_id"]),
        ("name", receipt["artifact_name"]),
        ("size_in_bytes", receipt["artifact_zip_bytes"]),
        ("digest", "sha256:" + receipt["artifact_zip_sha256"]),
        ("expired", False),
    ):
        match(artifact.get(key), expected, "Artifact metadata differs from receipt")
    producer = artifact.get("workflow_run")
    require(type(producer) is dict, "Artifact has no producing run")
    for key, expected in (("id", receipt["run_id"]), ("head_sha", receipt["head_sha"])):
        match(producer.get(key), expected, "Artifact producing run differs")
    for key, expected in (
        ("id", receipt["run_id"]),
        ("run_attempt", receipt["run_attempt"]),
        ("head_sha", receipt["head_sha"]),
        ("path", receipt["workflow_path"]),
    ):
        match(run.get(key), expected, "Producing workflow differs from receipt")
    for key, producer_key in (
        ("repository", "repository_id"),
        ("head_repository", "head_repository_id"),
    ):
        repository = run.get(key)
        require(type(repository) is dict, "Missing producing repository")
        match(repository.get("full_name"), receipt["repository"], "Producing repository differs")
        require(
            type(repository.get("id")) is int and repository["id"] > 0,
            "Invalid producing repository ID",
        )
        match(producer.get(producer_key), repository["id"], "Artifact repository ID differs")
    entries = jobs.get("jobs")
    require(
        type(entries) is list
        and type(jobs.get("total_count")) is int
        and jobs["total_count"] == len(entries),
        "Incomplete producer jobs metadata",
    )
    publish = [job for job in entries if type(job) is dict and job.get("name") == "publish"]
    require(len(publish) == 1, "Expected one producer publication job")
    job = publish[0]
    for key, expected in (
        ("run_id", receipt["run_id"]),
        ("run_attempt", receipt["run_attempt"]),
        ("head_sha", receipt["head_sha"]),
        ("status", "completed"),
    ):
        match(job.get(key), expected, "Producer job differs from receipt")
    steps = job.get("steps")
    require(
        type(steps) is list and all(type(step) is dict for step in steps), "Missing producer steps"
    )
    for name in GATES:
        found = [step for step in steps if step.get("name") == name]
        require(
            len(found) == 1
            and found[0].get("conclusion") == "success"
            and found[0].get("status") == "completed",
            "Producer acceptance gate failed",
        )


def file_digest(path, *, expected_bytes=None):
    require(not path.is_symlink() and path.is_file(), "Input must be a regular file")
    size = path.stat().st_size
    require(
        size <= MAX_ARCHIVE_BYTES and (expected_bytes is None or size == expected_bytes),
        "Input byte length differs from receipt",
    )
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(BLOCK_BYTES), b""):
            result.update(block)
    return result.hexdigest()


def public_path(name, *, tar=False, directory=False):
    require(
        type(name) is str
        and name
        and "\\" not in name
        and ":" not in name
        and all(ord(c) >= 32 and ord(c) != 127 for c in name),
        "Unsafe public path",
    )
    if tar and name.startswith("./"):
        name = name[2:]
    if directory and name.endswith("/"):
        name = name[:-1]
    if tar and directory and name == ".":
        return ""
    require(
        not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/")),
        "Escaping or noncanonical public path",
    )
    return name


def unpack(receipt, archive_path, stage):
    tar_path = stage.parent / "artifact.tar"
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        require(len(entries) == 1, "Expected exactly one ZIP member")
        member = entries[0]
        mode = member.external_attr >> 16
        require(
            member.filename == "artifact.tar"
            and not member.is_dir()
            and stat.S_IFMT(mode) in (0, stat.S_IFREG)
            and not member.flag_bits & 1
            and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
            "Unexpected ZIP member type",
        )
        match(member.file_size, receipt["tar_bytes"], "Tar size differs from receipt")
        size = 0
        result = hashlib.sha256()
        with archive.open(member) as source, tar_path.open("xb") as output:
            while block := source.read(BLOCK_BYTES):
                size += len(block)
                require(size <= receipt["tar_bytes"], "Tar exceeds byte bound")
                result.update(block)
                output.write(block)
        match(size, receipt["tar_bytes"], "Truncated tar")
        match(result.hexdigest(), receipt["tar_sha256"], "Tar digest differs from receipt")
    with tarfile.open(tar_path, mode="r:") as archive:
        entries = {}
        total = 0
        for member in archive:
            require(len(entries) < MAX_MEMBERS, "Too many tar members")
            require(
                member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                and not member.issparse()
                and not member.pax_headers,
                "Unexpected tar member type",
            )
            name = public_path(member.name, tar=True, directory=member.isdir())
            require(name not in entries, "Duplicate tar path")
            require(type(member.size) is int and member.size >= 0, "Invalid tar member size")
            require(not member.isdir() or member.size == 0, "Directory has file data")
            total += member.size
            require(total <= receipt["tar_bytes"], "Tar contents exceed byte bound")
            entries[name] = member
        for name, member in entries.items():
            for parent in Path(name).parents:
                ancestor = entries.get(parent.as_posix())
                require(ancestor is None or ancestor.isdir(), "Tar file used as directory")
            if member.isdir():
                (stage / name).mkdir(parents=True, exist_ok=True)
            else:
                destination = stage / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                require(source is not None, "Missing tar file contents")
                with source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output, BLOCK_BYTES)
                match(destination.stat().st_size, member.size, "Truncated tar member")
    manifest = read_json(stage / "manifest.json")
    require(
        type(manifest) is dict and set(manifest) == {"generation", "sha256"},
        "Invalid public manifest",
    )
    match(manifest["generation"], receipt["generation"], "Public generation differs from receipt")
    inventory = manifest["sha256"]
    require(type(inventory) is dict, "Invalid manifest inventory")
    files = {name for name, member in entries.items() if member.isfile()}
    require(set(inventory) == files - {"manifest.json"}, "Public manifest inventory differs")
    for name, expected in inventory.items():
        public_path(name)
        require(
            type(expected) is str and re.fullmatch(r"[a-f0-9]{64}", expected),
            "Invalid public file digest",
        )
        match(file_digest(stage / name), expected, "Public file digest differs")
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in (
        "receipt",
        "artifact-metadata",
        "run-metadata",
        "job-metadata",
        "accepted-manifest",
        "artifact-zip",
        "output",
    ):
        parser.add_argument("--" + flag, type=Path, required=True)
    args = parser.parse_args()
    receipt = receipt_value(args.receipt)
    require(not args.output.exists() and not args.output.is_symlink(), "Output already exists")
    verify_metadata(
        receipt,
        read_json(args.artifact_metadata),
        read_json(args.run_metadata),
        read_json(args.job_metadata),
    )
    match(
        file_digest(args.accepted_manifest),
        receipt["accepted_manifest_sha256"],
        "Accepted recovery pointer changed",
    )
    accepted = read_json(args.accepted_manifest)
    require(type(accepted) is dict, "Invalid accepted recovery pointer")
    match(
        accepted.get("source_commit"),
        receipt["source_commit"],
        "Accepted recovery source differs from receipt",
    )
    match(
        file_digest(args.artifact_zip, expected_bytes=receipt["artifact_zip_bytes"]),
        receipt["artifact_zip_sha256"],
        "ZIP digest differs from receipt",
    )
    with tempfile.TemporaryDirectory(
        prefix=".pages-redeploy-", dir=args.output.parent
    ) as temporary:
        stage = Path(temporary) / "public"
        stage.mkdir()
        count = unpack(receipt, args.artifact_zip, stage)
        require(not args.output.exists() and not args.output.is_symlink(), "Output already exists")
        stage.rename(args.output)
    print(json.dumps({"generation": receipt["generation"], "files": count, "status": "verified"}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, RuntimeError):
        sys.exit("Pages retry verification failed; no deployment is authorized")
