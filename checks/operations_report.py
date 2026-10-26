"""Summarize observed hosted runs; never manufacture a week of uptime."""

import argparse
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path


def summarize(collections, monitors, now=None, repository_size_kib=None):
    now = now or datetime.now(timezone.utc)
    all_runs = collections + monitors
    start = min(
        (datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00")) for r in all_runs),
        default=now,
    )
    elapsed = max(0, (now - start).total_seconds() / 86400)

    def counts(runs):
        recent = [
            r
            for r in runs
            if datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00"))
            >= now - timedelta(days=7)
        ]
        return {
            "observed": len(recent),
            "successful": sum(r.get("conclusion") == "success" for r in recent),
            "failed": sum(
                r.get("conclusion") in ("failure", "timed_out", "cancelled") for r in recent
            ),
            "scheduled": sum(r.get("event") == "schedule" for r in recent),
            "manual": sum(r.get("event") == "workflow_dispatch" for r in recent),
        }

    return {
        "schema_version": 1,
        "checked_at": now.isoformat(),
        "first_observed_run": start.isoformat(),
        "elapsed_days": round(elapsed, 3),
        "seven_day_window_complete": elapsed >= 7,
        "review_after": (start + timedelta(days=7)).isoformat(),
        "collections": counts(collections),
        "monitors": counts(monitors),
        "history_may_be_truncated": len(collections) >= 100 or len(monitors) >= 100,
        "repository_size_kib": repository_size_kib,
        "repository_budget_kib": 524288,
        "storage_review_required": repository_size_kib is not None
        and repository_size_kib >= 524288,
        "limitations": [
            "Workflow success is not continuous service uptime.",
            "Successful collection may have partial source failures; inspect the publication health.",
            "Seven days must actually elapse before the initial reliability review can be completed.",
        ],
    }


def run_json(command):
    return json.loads(subprocess.check_output(command, text=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()

    def runs(workflow):
        return run_json(
            [
                "gh",
                "run",
                "list",
                "--repo",
                args.repository,
                "--workflow",
                workflow,
                "--limit",
                "100",
                "--json",
                "createdAt,status,conclusion,event,url",
            ]
        )

    metadata = run_json(["gh", "api", "repos/" + args.repository])
    report = summarize(
        runs("collect.yaml"), runs("monitor.yaml"), repository_size_kib=metadata["size"]
    )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.summary:
        args.summary.write_text(
            "# Hosted reliability observation\n\n"
            + f"Observed {report['elapsed_days']} days. Seven-day review complete: {report['seven_day_window_complete']}.\n\n"
            + "```json\n"
            + json.dumps(report, indent=2)
            + "\n```\n"
        )
    print(
        json.dumps(
            {
                "elapsed_days": report["elapsed_days"],
                "seven_day_window_complete": report["seven_day_window_complete"],
                "storage_review_required": report["storage_review_required"],
            }
        )
    )
    if report["storage_review_required"]:
        raise SystemExit("Repository storage budget requires operator review; no data deleted")


if __name__ == "__main__":
    main()
