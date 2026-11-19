"""Exact public receipt pins for the deployment-only retry workflow."""

import hashlib
import re
from pathlib import Path

from checks.pages_redeploy import receipt_value

ROOT = Path(__file__).resolve().parents[1]


def test_retry_workflow_uses_only_the_reviewed_reader_artifact():
    receipt_path = "docs/operations/pages-redeploy-reader-2026-11-19.json"
    receipt = receipt_value(ROOT / receipt_path)
    assert receipt["repository"] == "abedegno/infrastructure-impact"
    assert receipt["run_id"] == 44616329992
    assert receipt["run_attempt"] == 1
    assert receipt["artifact_id"] == 14575364963
    assert receipt["source_commit"] == "cc84ad64fa7704020228f47ea7e433dde0acb0ee"
    assert receipt["generation"] == "f227eadfa17340ac92135c55cf56d0ae"

    workflow = (ROOT / ".github/workflows/pages-redeploy.yaml").read_text()
    api_root = f"repos/{receipt['repository']}/actions"
    artifact = f"{api_root}/artifacts/{receipt['artifact_id']}"
    run = f"{api_root}/runs/{receipt['run_id']}"
    assert re.findall(r"gh api --hostname github.com '?([^'\s]+)'? >", workflow) == [
        artifact,
        run,
        f"{run}/attempts/{receipt['run_attempt']}/jobs?per_page=100",
        f"{artifact}/zip",
    ]
    assert re.findall(r"--receipt (\S+)", workflow) == [receipt_path]
    # The ZIP-preservation comment mentions gh run download; commands must not use it.
    commands = "\n".join(
        line for line in workflow.splitlines() if not line.lstrip().startswith("#")
    )
    for selector in ("gh run download", "--name", "--pattern", "/latest", "workflow_run:"):
        assert selector not in commands

    previous = ROOT / "docs/operations/pages-redeploy-2026-11-09.json"
    assert hashlib.sha256(previous.read_bytes()).hexdigest() == (
        "9f915565b0f6d79c6d94fce4e121807bb7785e94fe6028d8b057d193bda5da0c"
    )


def test_previous_cisco_retry_receipt_is_preserved():
    previous = ROOT / "docs/operations/pages-redeploy-cisco-2026-11-10.json"
    assert hashlib.sha256(previous.read_bytes()).hexdigest() == (
        "d79e3fd29ddad74174ca9395fd3551d48acfc01e4a0e39860e3b6493f84fcb6a"
    )
