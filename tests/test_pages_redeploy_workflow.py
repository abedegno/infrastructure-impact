"""Exact public receipt pins for the deployment-only retry workflow."""

import hashlib
import re
from pathlib import Path

from checks.pages_redeploy import receipt_value

ROOT = Path(__file__).resolve().parents[1]


def test_retry_workflow_uses_only_the_reviewed_cisco_artifact():
    receipt_path = "docs/operations/pages-redeploy-cisco-2026-11-10.json"
    receipt = receipt_value(ROOT / receipt_path)
    assert receipt["repository"] == "abedegno/infrastructure-impact"
    assert receipt["run_id"] == 42807404632
    assert receipt["run_attempt"] == 1
    assert receipt["artifact_id"] == 13761577124
    assert receipt["source_commit"] == "26dbdc745b7e8f3ae949d43198b202b040bdeae8"
    assert receipt["generation"] == "0d1e99eaab8e41ab9f8e8afd7f448991"

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
