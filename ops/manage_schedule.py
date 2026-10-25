"""Install, inspect or remove the user-owned daily collector LaunchAgent."""

import argparse
import json
import os
import plistlib
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABEL = "com.jonw.infrastructure-impact.collector"
SOURCE = ROOT / "ops" / f"{LABEL}.plist"
TARGET = Path.home() / "Library/LaunchAgents" / SOURCE.name
DOMAIN = f"gui/{os.getuid()}"
SERVICE = DOMAIN + "/" + LABEL


def command(*args):
    return subprocess.run(["launchctl", *args], capture_output=True, text=True)


def inspect():
    result = command("print", SERVICE)
    loaded = result.returncode == 0 and str(ROOT / "collector_job.py") in result.stdout
    tz = str(Path("/etc/localtime").resolve()).split("zoneinfo/")[-1]
    status = {
        "installed": loaded and TARGET.exists(),
        "kind": "user LaunchAgent",
        "label": LABEL,
        "local_time": "08:15",
        "timezone": tz if "/" in tz else "system local time",
        "hosted_auto_publication": False,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
    (ROOT / "ops/schedule-status.json").write_text(json.dumps(status, indent=2) + "\n")
    return status


def render_source():
    """Generate checkout-local configuration instead of shipping personal paths."""
    interpreter = ROOT / ".venv/bin/python"
    if not interpreter.is_file():
        raise ValueError("Run uv sync before installing the native schedule")
    config = {
        "Label": LABEL,
        "ProcessType": "Background",
        "ProgramArguments": [str(interpreter), str(ROOT / "collector_job.py")],
        "WorkingDirectory": str(ROOT),
        "RunAtLoad": False,
        "StartCalendarInterval": {"Hour": 8, "Minute": 15},
        "StandardOutPath": str(ROOT / "data/collector-scheduled.log"),
        "StandardErrorPath": str(ROOT / "data/collector-scheduled-error.log"),
    }
    (ROOT / "data").mkdir(exist_ok=True)
    SOURCE.write_bytes(plistlib.dumps(config, sort_keys=False))


def install():
    if not SOURCE.exists():
        render_source()
    desired = plistlib.loads(SOURCE.read_bytes())
    if desired.get("Label") != LABEL or desired["ProgramArguments"][1] != str(
        ROOT / "collector_job.py"
    ):
        raise ValueError("Unexpected collector LaunchAgent configuration")
    if TARGET.exists() and TARGET.read_bytes() != SOURCE.read_bytes():
        raise ValueError("Existing agent differs; inspect before replacing it")
    existing = command("print", SERVICE)
    if existing.returncode == 0:
        if str(ROOT / "collector_job.py") not in existing.stdout:
            raise ValueError("Loaded job does not match this collector")
        return inspect()
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    created = not TARGET.exists()
    with tempfile.NamedTemporaryFile(dir=TARGET.parent, delete=False) as f:
        temp = Path(f.name)
        f.write(SOURCE.read_bytes())
    temp.chmod(0o644)
    temp.replace(TARGET)
    result = command("bootstrap", DOMAIN, str(TARGET))
    if result.returncode:
        if created:
            TARGET.unlink()
        inspect()
        raise RuntimeError(result.stderr.strip() or "LaunchAgent registration failed")
    status = inspect()
    if not status["installed"]:
        raise RuntimeError("Agent registration could not be verified")
    return status


def remove():
    if TARGET.exists() and TARGET.read_bytes() != SOURCE.read_bytes():
        raise ValueError("Refusing to remove a different job")
    existing = command("print", SERVICE)
    if existing.returncode == 0:
        if str(ROOT / "collector_job.py") not in existing.stdout:
            raise ValueError("Refusing to stop a different job")
        stopped = command("bootout", SERVICE)
        if stopped.returncode:
            raise RuntimeError(stopped.stderr.strip())
    if TARGET.exists():
        TARGET.unlink()
    return inspect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["install", "status", "remove"])
    args = parser.parse_args()
    print(
        json.dumps(
            {"install": install, "status": inspect, "remove": remove}[args.action](), indent=2
        )
    )
