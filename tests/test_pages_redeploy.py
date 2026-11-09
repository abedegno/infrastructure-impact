"""Authored public ZIP/tar fixtures; no downloaded artifacts or private state."""

import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def candidate(tmp_path):
    files = {"index.html": b"synthetic public page", ".nojekyll": b"", "assets/app.js": b"ok"}
    generation = "1" * 32
    manifest = {"generation": generation, "sha256": {k: digest(v) for k, v in files.items()}}
    files["manifest.json"] = json.dumps(manifest).encode()
    accepted = b'{"synthetic":"accepted recovery pointer","source_commit":"' + b"3" * 40 + b'"}\n'
    receipt = {
        "schema_version": 1,
        "repository": "example/public-service",
        "run_id": 123,
        "run_attempt": 1,
        "workflow_path": ".github/workflows/collect.yaml",
        "head_sha": "2" * 40,
        "source_commit": "3" * 40,
        "artifact_id": 456,
        "artifact_name": "github-pages",
        "artifact_zip_bytes": 1,
        "artifact_zip_sha256": "4" * 64,
        "tar_bytes": 1,
        "tar_sha256": "5" * 64,
        "generation": generation,
        "accepted_manifest_sha256": digest(accepted),
    }
    metadata = {
        "id": 456,
        "name": "github-pages",
        "size_in_bytes": 1,
        "digest": "sha256:" + "4" * 64,
        "expired": False,
        "workflow_run": {
            "id": 123,
            "head_sha": "2" * 40,
            "repository_id": 789,
            "head_repository_id": 789,
        },
    }
    run = {
        "id": 123,
        "run_attempt": 1,
        "path": ".github/workflows/collect.yaml",
        "head_sha": "2" * 40,
        "repository": {"id": 789, "full_name": "example/public-service"},
        "head_repository": {"id": 789, "full_name": "example/public-service"},
    }
    return {
        "root": tmp_path,
        "files": files,
        "receipt": receipt,
        "metadata": metadata,
        "run": run,
        "jobs": {
            "total_count": 1,
            "jobs": [
                {
                    "name": "publish",
                    "run_id": 123,
                    "run_attempt": 1,
                    "head_sha": "2" * 40,
                    "status": "completed",
                    "steps": [
                        {"name": name, "conclusion": "success", "status": "completed"}
                        for name in (
                            "Restore, collect, audit and back up privately",
                            "Check hosted helper effects",
                            "Retain only encrypted recovery copies",
                            "Run actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9",
                        )
                    ],
                }
            ],
        },
        "accepted": accepted,
    }


def archive(candidate, *, members=None, zip_members=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as tar:
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        directory = tarfile.TarInfo("./assets")
        directory.type = tarfile.DIRTYPE
        tar.addfile(directory)
        for name, content in candidate["files"].items():
            member = tarfile.TarInfo("./" + name)
            member.size = len(content)
            tar.addfile(member, io.BytesIO(content))
        for member, content in members or []:
            tar.addfile(member, io.BytesIO(content))
    raw_tar = stream.getvalue()
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("artifact.tar", raw_tar)
        for info, content in zip_members or []:
            zipped.writestr(info, content)
    raw_zip = packed.getvalue()
    candidate["receipt"].update(
        tar_bytes=len(raw_tar),
        tar_sha256=digest(raw_tar),
        artifact_zip_bytes=len(raw_zip),
        artifact_zip_sha256=digest(raw_zip),
    )
    candidate["metadata"].update(size_in_bytes=len(raw_zip), digest="sha256:" + digest(raw_zip))
    candidate["zip"] = raw_zip


def invoke(candidate):
    root = candidate["root"]
    for name in ("receipt", "metadata", "run", "jobs"):
        (root / (name + ".json")).write_text(json.dumps(candidate[name]))
    (root / "accepted.json").write_bytes(candidate["accepted"])
    (root / "artifact.zip").write_bytes(candidate["zip"])
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "checks/pages_redeploy.py"),
            "--receipt",
            str(root / "receipt.json"),
            "--artifact-metadata",
            str(root / "metadata.json"),
            "--run-metadata",
            str(root / "run.json"),
            "--job-metadata",
            str(root / "jobs.json"),
            "--accepted-manifest",
            str(root / "accepted.json"),
            "--artifact-zip",
            str(root / "artifact.zip"),
            "--output",
            str(root / "public"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def reject(candidate):
    result = invoke(candidate)
    assert result.returncode != 0
    assert not (candidate["root"] / "public").exists()


def test_verified_public_files_are_extracted_and_generation_reported(candidate):
    archive(candidate)
    result = invoke(candidate)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["generation"] == "1" * 32
    output = candidate["root"] / "public"
    assert {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()} == set(
        candidate["files"]
    )
    assert (output / "index.html").read_bytes() == b"synthetic public page"


@pytest.mark.parametrize(
    "field,value",
    [
        ("extra", "unexpected"),
        ("schema_version", True),
        ("schema_version", 2),
        ("run_id", True),
        ("run_id", "123"),
        ("run_id", 0),
        ("repository", "https://example.invalid/repo"),
        ("repository", "../repo"),
        ("head_sha", "not-a-commit"),
        ("source_commit", "3" * 7),
        ("workflow_path", ".github/workflows/other.yaml"),
        ("artifact_name", "other"),
        ("artifact_zip_bytes", 0),
        ("tar_bytes", 2**40),
        ("generation", "../escape"),
        ("accepted_manifest_sha256", "A" * 64),
    ],
)
def test_receipt_is_closed_and_strictly_typed(candidate, field, value):
    archive(candidate)
    candidate["receipt"][field] = value
    reject(candidate)


@pytest.mark.parametrize("field", ["artifact_zip_sha256", "tar_sha256", "accepted_manifest_sha256"])
def test_changed_pinned_digest_is_rejected(candidate, field):
    archive(candidate)
    candidate["receipt"][field] = "0" * 64
    reject(candidate)


@pytest.mark.parametrize("field", ["artifact_zip_bytes", "tar_bytes"])
def test_changed_pinned_size_is_rejected(candidate, field):
    archive(candidate)
    candidate["receipt"][field] += 1
    reject(candidate)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 457),
        ("name", "other"),
        ("size_in_bytes", True),
        ("expired", True),
        ("expired", 0),
        ("digest", "sha256:" + "0" * 64),
        ("workflow_run", {"id": 124, "head_sha": "2" * 40}),
        ("workflow_run", {"id": 123, "head_sha": "9" * 40}),
    ],
)
def test_artifact_metadata_must_match_pins(candidate, field, value):
    archive(candidate)
    candidate["metadata"][field] = value
    reject(candidate)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 124),
        ("run_attempt", 2),
        ("head_sha", "9" * 40),
        ("path", ".github/workflows/other.yaml"),
        ("repository", {"full_name": "other/repo"}),
        ("head_repository", {"full_name": "other/fork"}),
    ],
)
def test_producing_workflow_and_repository_are_bound(candidate, field, value):
    archive(candidate)
    candidate["run"][field] = value
    reject(candidate)


def test_advanced_accepted_pointer_is_rejected(candidate):
    archive(candidate)
    candidate["accepted"] += b" "
    reject(candidate)


def test_zip_extra_member_is_rejected_even_with_updated_zip_pins(candidate):
    archive(candidate, zip_members=[("unexpected", b"public")])
    reject(candidate)


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "assets/../escape",
        "./index.html",
        "assets//escape",
        "assets\\escape",
        "C:/escape",
    ],
)
def test_escaping_noncanonical_and_duplicate_tar_paths_are_rejected(candidate, name):
    member = tarfile.TarInfo(name)
    member.size = 1
    archive(candidate, members=[(member, b"x")])
    reject(candidate)


@pytest.mark.parametrize(
    "kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE]
)
def test_tar_links_and_special_files_are_rejected(candidate, kind):
    member = tarfile.TarInfo("./unexpected")
    member.type = kind
    member.linkname = "index.html"
    archive(candidate, members=[(member, b"")])
    reject(candidate)


@pytest.mark.parametrize("change", ["extra", "missing", "hash", "generation", "type", "self"])
def test_manifest_covers_every_public_file_and_pinned_generation(candidate, change):
    manifest = json.loads(candidate["files"]["manifest.json"])
    if change == "extra":
        candidate["files"]["extra.html"] = b"unexpected"
    elif change == "missing":
        del candidate["files"]["index.html"]
    elif change == "hash":
        candidate["files"]["index.html"] = b"changed"
    elif change == "generation":
        manifest["generation"] = "9" * 32
    elif change == "type":
        manifest["sha256"] = []
    elif change == "self":
        manifest["sha256"]["manifest.json"] = "0" * 64
    candidate["files"]["manifest.json"] = json.dumps(manifest).encode()
    archive(candidate)
    reject(candidate)


def test_existing_output_is_never_modified(candidate):
    archive(candidate)
    output = candidate["root"] / "public"
    output.mkdir()
    (output / "marker").write_text("keep")
    assert invoke(candidate).returncode != 0
    assert (output / "marker").read_text() == "keep"


def test_zip_unix_symlink_is_not_read_as_tar(candidate):
    archive(candidate)
    raw_zip = io.BytesIO()
    member = zipfile.ZipInfo("artifact.tar")
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(raw_zip, "w") as zipped:
        zipped.writestr(member, b"elsewhere")
    candidate["zip"] = raw_zip.getvalue()
    candidate["receipt"].update(
        artifact_zip_bytes=len(candidate["zip"]), artifact_zip_sha256=digest(candidate["zip"])
    )
    candidate["metadata"].update(
        size_in_bytes=len(candidate["zip"]), digest="sha256:" + digest(candidate["zip"])
    )
    reject(candidate)


@pytest.mark.parametrize("index", range(4))
def test_candidate_backup_and_artifact_gates_must_have_succeeded(candidate, index):
    archive(candidate)
    candidate["jobs"]["jobs"][0]["steps"][index]["conclusion"] = "failure"
    reject(candidate)


def test_fork_repository_identity_is_rejected(candidate):
    archive(candidate)
    candidate["metadata"]["workflow_run"]["head_repository_id"] = 790
    reject(candidate)


def test_duplicate_json_keys_are_rejected(candidate):
    archive(candidate)
    candidate["files"]["manifest.json"] = (
        b'{"generation":"' + b"1" * 32 + b'","sha256":{},"sha256":{}}'
    )
    archive(candidate)
    reject(candidate)


def test_source_commit_must_match_accepted_pointer(candidate):
    archive(candidate)
    candidate["receipt"]["source_commit"] = "9" * 40
    reject(candidate)
