"""Create a reviewed public source tree without copying the private workspace.

Uses an explicit source allowlist. Refuses an existing destination and checks the
result for private artifacts, local identity strings, credential patterns and
synthetic-fixture integrity. This is a release check, not a general secret scanner.
"""

import argparse
import hashlib
import json
import re
import shutil
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
)
DIRECTORIES = ("infrastructure_impact", "docs", ".github", "checks", "tests", "examples", "deploy")
IGNORED_PARTS = {"__pycache__", ".pytest_cache", ".ruff_cache", ".venv", "dist", "node_modules"}
# Match concrete leak forms; do not print matched contents.
LEAKS = re.compile(
    r"/Users/|/home/jonw/|jon@jonwilliams|appgprj_[a-z0-9]+|"
    r"cometsquid13\.chatgpt\.site|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bghp_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{30,}|\bAKIA[0-9A-Z]{16}"
)


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
