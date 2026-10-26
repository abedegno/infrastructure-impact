"""Summarize observed hosted runs; never manufacture a week of uptime."""

import argparse
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path


def summarize(
    collections,
    monitors,
    now=None,
    repository_size_kib=None,
    observation_start=None,
    history_limit=100,
    public_health=None,
):
    now = now or datetime.now(timezone.utc)
    all_runs = collections + monitors
    start = min(
        (datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00")) for r in all_runs),
        default=now,
    )
    if observation_start:
        start = datetime.fromisoformat(observation_start.replace("Z", "+00:00"))
        if start.tzinfo is None or start > now:
            raise ValueError("Observation start requires a past timezone-aware timestamp")
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
            "scheduled_successful": sum(
                r.get("event") == "schedule" and r.get("conclusion") == "success" for r in recent
            ),
            "scheduled_failed": sum(
                r.get("event") == "schedule"
                and r.get("conclusion") in ("failure", "timed_out", "cancelled")
                for r in recent
            ),
        }

    collection_counts, monitor_counts = counts(collections), counts(monitors)
    truncated = len(collections) >= history_limit or len(monitors) >= history_limit
    findings = []
    if collection_counts["failed"] or monitor_counts["failed"]:
        findings.append("Failed, cancelled or timed-out workflows occurred in the window")
    if collection_counts["scheduled_successful"] < 7:
        findings.append("Fewer than seven successful scheduled collections observed")
    if monitor_counts["scheduled_successful"] < 24:
        findings.append("Fewer than 24 successful scheduled monitors observed")
    if public_health is None or public_health.get("status") != "fresh":
        findings.append("No successful current public-health receipt")
    elif public_health.get("source_failures") is None:
        findings.append("Source-failure count is unavailable")
    elif public_health.get("source_failures"):
        findings.append("Public publication retains unresolved source failures")
    if repository_size_kib is not None and repository_size_kib > 512 * 1024:
        findings.append("Repository storage budget requires operator review")
    review_ready = elapsed >= 7 and not truncated and public_health is not None
    return {
        "schema_version": 1,
        "checked_at": now.isoformat(),
        "first_observed_run": start.isoformat(),
        "elapsed_days": round(elapsed, 3),
        "seven_day_window_complete": elapsed >= 7,
        "review_after": (start + timedelta(days=7)).isoformat(),
        "collections": collection_counts,
        "monitors": monitor_counts,
        "anchor_basis": "configured_verified_start"
        if observation_start
        else "earliest_retrieved_run",
        "history_limit": history_limit,
        "history_may_be_truncated": truncated,
        "public_health": public_health,
        "findings": findings,
        "automated_review_completed": review_ready,
        "review_status": "waiting_for_window"
        if elapsed < 7
        else "incomplete_history"
        if truncated
        else "missing_health_receipt"
        if public_health is None
        else "review_with_findings"
        if findings
        else "review_without_detected_operational_findings",
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
    parser.add_argument("--observation-start")
    parser.add_argument("--health-report", type=Path)
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
                "1000",
                "--json",
                "createdAt,status,conclusion,event,url",
            ]
        )

    metadata = run_json(["gh", "api", "repos/" + args.repository])
    receipt = None
    if args.health_report:
        try:
            receipt = json.loads(args.health_report.read_text())
        except (OSError, ValueError):
            receipt = {"status": "unavailable", "reason": "No successful public-health receipt"}
    report = summarize(
        runs("collect.yaml"),
        runs("monitor.yaml"),
        repository_size_kib=metadata["size"],
        observation_start=args.observation_start or None,
        history_limit=1000,
        public_health=receipt,
    )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.summary:
        args.summary.write_text(
            "# Hosted reliability observation\n\n"
            + f"Observed {report['elapsed_days']} days. Seven-day review complete: {report['seven_day_window_complete']}.\n\n"
            + f"Automated review: {report['review_status']}. This is not a continuous uptime measurement.\n\n"
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
