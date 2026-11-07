"""Prove that a wheel plus an external plugin works without checkout imports."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


def release_wheel(root):
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    wheels = sorted((root / "dist").glob("infrastructure_impact-" + version + "-*.whl"))
    if len(wheels) != 1:
        raise ValueError(
            "Build exactly one wheel for the declared package version before distribution checks"
        )
    return wheels[0]


def public_resource_fingerprints(root):
    names = [
        "schemas/comparison-eligibility-summary-v1.json",
        "schemas/coverage-gaps-v1.json",
        "schemas/cve-reconciliation-v1.json",
        "resources/cve-reconciliation-selectors.json",
        "web/kev.js",
        "schemas/kev-v1.json",
        "schemas/current-evidence-v1.json",
        "schemas/static-index-v1.json",
        "resources/openapi.json",
        "web/lossless-json.js",
        "web/current-evidence.js",
        "resources/sources.json",
        "web/switching-contracts.js",
        "web/switching.js",
        "web/switching-view.js",
        "resources/switching-study.json",
        "resources/switching-source-bindings.json",
        "resources/switching-extraction-review.json",
        "migrations/011_switching_collection.sql",
        "resources/target-imports/campus-switching-public-gap-2026-11-07-v1.json",
        "schemas/target-import-manifest-v1.json",
        "schemas/target-import-preview-v1.json",
        "schemas/target-import-result-v1.json",
    ]
    names += [
        "schemas/switching-" + name + "-v1.json"
        for name in ("study", "evidence", "comparison", "summary", "inputs")
    ]
    resources = {
        name: hashlib.sha256((root / "infrastructure_impact" / name).read_bytes()).hexdigest()
        for name in names
    }
    resources.update(
        {
            "_standalone/" + name: hashlib.sha256((root / "checks" / name).read_bytes()).hexdigest()
            for name in ("public_health.py", "switching_health.py")
        }
    )
    return resources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline", action="store_true", help="Use already cached dependencies only"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    wheel = release_wheel(root)
    from infrastructure_impact.plugins.builtin import builtin_plugins
    from infrastructure_impact.plugins.registry import default_registry

    expected = {p.id: default_registry().fingerprint(p.id) for p in builtin_plugins()}
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["IMPACT_DISTRIBUTION_SOURCE_ROOT"] = str(root)
    environment["IMPACT_EXPECTED_PACKAGE_VERSION"] = tomllib.loads(
        (root / "pyproject.toml").read_text()
    )["project"]["version"]
    environment["IMPACT_EXPECTED_NORMALIZER_FINGERPRINTS"] = json.dumps(expected)
    environment["IMPACT_EXPECTED_PUBLIC_RESOURCES"] = json.dumps(public_resource_fingerprints(root))
    environment["IMPACT_TARGET_IMPORT_PROBE"] = (
        root / "tests/fixtures/target-import-candidate.json"
    ).read_text()
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(
            [
                "uv",
                "run",
                *(["--offline"] if args.offline else []),
                "--no-project",
                "--isolated",
                "--python",
                sys.executable,
                "--with-requirements",
                str(root / "requirements.lock"),
                "--with",
                str(wheel),
                "--with",
                str(root / "examples/vendor-plugin"),
                "python",
                "-I",
                str(root / "checks/package_probe.py"),
            ],
            cwd=directory,
            env=environment,
            check=True,
        )


if __name__ == "__main__":
    main()
