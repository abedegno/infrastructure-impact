"""Prove that a wheel plus an external plugin works without checkout imports."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline", action="store_true", help="Use already cached dependencies only"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    wheel = next((root / "dist").glob("infrastructure_impact-*.whl"))
    from infrastructure_impact.plugins.builtin import builtin_plugins
    from infrastructure_impact.plugins.registry import default_registry

    expected = {p.id: default_registry().fingerprint(p.id) for p in builtin_plugins()}
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["IMPACT_DISTRIBUTION_SOURCE_ROOT"] = str(root)
    environment["IMPACT_EXPECTED_NORMALIZER_FINGERPRINTS"] = json.dumps(expected)
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
                str(root / "checks/package_probe.py"),
            ],
            cwd=directory,
            env=environment,
            check=True,
        )


if __name__ == "__main__":
    main()
