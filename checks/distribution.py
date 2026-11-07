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
from zipfile import ZipFile


def release_wheel(root):
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    wheels = sorted((root / "dist").glob("infrastructure_impact-" + version + "-*.whl"))
    if len(wheels) != 1:
        raise ValueError(
            "Build exactly one wheel for the declared package version before distribution checks"
        )
    return wheels[0]


def public_resource_fingerprints(root):
    # Derive the required set from source, independently of wheel contents.
    # Checking only files that happened to ship cannot detect omitted modules.
    package = root / "infrastructure_impact"
    names = [
        path.relative_to(package).as_posix()
        for path in package.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
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
    resources["_standalone/publication_codec.py"] = hashlib.sha256(
        (root / "infrastructure_impact/publication_codec.py").read_bytes()
    ).hexdigest()
    return resources


def verify_wheel_inventory(root, wheel):
    expected = public_resource_fingerprints(root)
    prefix = "infrastructure_impact/"
    with ZipFile(wheel) as archive:
        names = [n for n in archive.namelist() if n.startswith(prefix) and not n.endswith("/")]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate wheel package member")
        actual = {n.removeprefix(prefix) for n in names}
        if actual != set(expected):
            raise ValueError(
                "Wheel package inventory mismatch: missing="
                + repr(sorted(set(expected) - actual))
                + "; unexpected="
                + repr(sorted(actual - set(expected)))
            )
        for name, digest in expected.items():
            if hashlib.sha256(archive.read(prefix + name)).hexdigest() != digest:
                raise ValueError("Wheel package bytes mismatch: " + name)
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline", action="store_true", help="Use already cached dependencies only"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    wheel = release_wheel(root)
    verify_wheel_inventory(root, wheel)
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
