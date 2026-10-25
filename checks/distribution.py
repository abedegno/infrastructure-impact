"""Prove that a wheel plus an external plugin works without checkout imports."""

import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    wheel = next((root / "dist").glob("infrastructure_impact-*.whl"))
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(
            [
                "uv",
                "run",
                "--offline",
                "--no-project",
                "--isolated",
                "--python",
                sys.executable,
                "--with",
                str(wheel),
                "--with",
                str(root / "examples/vendor-plugin"),
                "python",
                str(root / "checks/package_probe.py"),
            ],
            cwd=directory,
            check=True,
        )


if __name__ == "__main__":
    main()
