"""Retain an honest public-health receipt and summary without application dependencies."""

import json
import os
from pathlib import Path


def main():
    receipt = Path(os.environ["RUNNER_TEMP"]) / "public-health.json"
    outcome = os.environ["CHECK_OUTCOME"]
    try:
        report = json.loads(receipt.read_text())
    except (OSError, ValueError):
        report = None
    verified = isinstance(report, dict) and report.get("status") == "fresh"
    if outcome != "success":
        report = {"status": "failed"}
    elif not verified:
        report = {"status": "unavailable"}
    report["check_outcome"] = outcome
    receipt.write_text(json.dumps(report, indent=2) + "\n")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
        stream.write(
            "\n## Public service health\n\n"
            f"Check outcome: **{outcome}**; receipt status: **{report['status']}**.\n\n"
            + "```json\n"
            + json.dumps(report, indent=2)
            + "\n```\n"
        )
    if outcome == "success" and not verified:
        raise SystemExit("Public-health receipt unavailable; successful health is unverified")


if __name__ == "__main__":
    main()
