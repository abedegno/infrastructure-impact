"""Create a reviewed public source tree without copying the private workspace.

Uses an explicit source allowlist. Refuses an existing destination and checks the
result for private artifacts, local identity strings, credential patterns and
synthetic-fixture integrity. This is a release check, not a general secret scanner.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = (
    "README.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "uv.lock",
    "requirements.lock",
    "requirements-build.lock",
    "package.json",
    "package-lock.json",
    ".gitignore",
    ".dockerignore",
    ".editorconfig",
    ".gitattributes",
    ".prettierrc.json",
    "Dockerfile",
    "compose.yaml",
    "sources.json",
    "adapters.py",
    "collect_cohort.py",
    "collector_job.py",
    "comparison.py",
    "cohort.py",
    "build_pilot.py",
    "impact.py",
    "intel.py",
    "report_benchmark.py",
    "research.py",
    "review.py",
    "server.py",
    "sync.py",
    "verify_pilot.py",
    "ops/manage_schedule.py",
    "ops/hosted_job.py",
    "ops/target_import_job.py",
    "ops/switching_fix_preview.py",
    "ops/retained_preview_progress.py",
)
DIRECTORIES = ("infrastructure_impact", "docs", ".github", "checks", "tests", "examples", "deploy")
IGNORED_PARTS = {"__pycache__", ".pytest_cache", ".ruff_cache", ".venv", "dist", "node_modules"}
# Match concrete leak forms; do not print matched contents.
LEAKS = re.compile(
    r"/Users/|/home/jonw/|jon@jonwilliams|appgprj_[a-z0-9]+|"
    r"cometsquid13\.chatgpt\.site|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bghp_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{30,}|\bAKIA[0-9A-Z]{16}"
)


def check_tracked_sources(root):
    """Reject checkout inventory that the public export would silently omit."""
    if not (root / ".git").exists():
        return  # Source archives have no Git inventory.
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--stage", "-z"],
            capture_output=True,
            check=False,
        )
    except OSError:
        raise ValueError("Unable to inspect tracked source inventory") from None
    if result.returncode:
        raise ValueError("Unable to inspect tracked source inventory")
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, _, stage = metadata.split()
        relative = Path(os.fsdecode(name))
        path = root / relative
        if (
            name == b"web"
            and mode == b"120000"
            and stage == b"0"
            and path.is_symlink()
            and path.readlink() == Path("infrastructure_impact/web")
        ):
            continue
        if (
            stage != b"0"
            or mode not in (b"100644", b"100755")
            or not (relative.as_posix() in FILES or relative.parts[0] in DIRECTORIES)
            or set(relative.parts) & IGNORED_PARTS
            or relative.suffix == ".pyc"
            or any(p.is_symlink() for p in (path, *path.parents) if p != root and root in p.parents)
        ):
            raise ValueError("Tracked source inventory contains unexpected entries")


def fixture_check(root):
    fixtures = root / "tests/fixtures"
    entries = json.loads((fixtures / "manifest.json").read_text())
    expected = {"README.md", "manifest.json"}
    for entry in entries:
        assert entry["kind"] == "synthetic", "Non-synthetic fixture in public manifest"
        name = entry["file"]
        assert Path(name).name == name, "Unsafe fixture name"
        expected.add(name)
        assert hashlib.sha256((fixtures / name).read_bytes()).hexdigest() == entry["sha256"], name
    assert {p.name for p in fixtures.iterdir()} == expected, "Unlisted public fixture"


def validate(root):
    fixture_check(root)
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.relative_to(root).parts:
            continue
        relative = path.relative_to(root)
        assert not (
            set(relative.parts) & {"data", "publications", "site", "node_modules", ".venv"}
        ), relative
        assert path.suffix not in (".sqlite3", ".plist", ".tar", ".gz", ".png"), relative
        if relative != Path("checks/release.py"):
            assert not LEAKS.search(path.read_bytes().decode("utf-8", errors="replace")), (
                f"Private content pattern: {relative}"
            )
        files.append(
            {"path": relative.as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        )
    assert (root / "LICENSE").read_text().lstrip().startswith("Apache License")
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "release/infrastructure-impact")
    args = parser.parse_args()
    destination = args.output.resolve()
    if destination.exists():
        parser.error("Output already exists; choose a new empty destination")
    if destination == ROOT or ROOT.is_relative_to(destination):
        parser.error("Output cannot contain the source checkout")
    check_tracked_sources(ROOT)
    destination.mkdir(parents=True)
    for name in FILES:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    for name in DIRECTORIES:
        for path in (ROOT / name).rglob("*"):
            relative = path.relative_to(ROOT)
            if not path.is_file() or set(relative.parts) & IGNORED_PARTS or path.suffix == ".pyc":
                continue
            if path.is_symlink():
                raise ValueError(f"Unexpected source symlink: {relative}")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    (destination / "web").symlink_to("infrastructure_impact/web", target_is_directory=True)
    files = validate(destination)
    print(
        json.dumps(
            {
                "destination": str(destination),
                "files": len(files),
                "synthetic_fixtures": "verified",
                "private_artifact_checks": "passed",
                "source_manifest": files,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError) as error:
        sys.exit(str(error))
