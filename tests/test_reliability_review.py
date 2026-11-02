"""Elapsed observation windows, stable anchors and actual scheduled-run evidence."""

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from checks.operations_report import summarize

START = datetime(2026, 10, 26, 11, 53, 57, tzinfo=timezone.utc)


def run(at, event="schedule"):
    return dict(createdAt=at.isoformat(), event=event, conclusion="success")


def test_stable_anchor_does_not_move_when_old_runs_leave_retrieved_history():
    report = summarize(
        [run(START + timedelta(days=7))],
        [],
        START + timedelta(days=8),
        3000,
        observation_start=START.isoformat(),
        public_health={"status": "fresh", "source_failures": 5},
    )
    assert report["elapsed_days"] == 8
    assert report["review_after"] == (START + timedelta(days=7)).isoformat()
    assert report["review_status"] == "review_with_findings"
    assert report["automated_review_completed"]
    assert any("source failures" in finding for finding in report["findings"])


def test_successful_manual_runs_do_not_substitute_for_a_week_of_scheduled_service():
    report = summarize(
        [run(START, "workflow_dispatch")] * 20,
        [],
        START + timedelta(hours=3),
        3000,
        observation_start=START.isoformat(),
        public_health={"status": "fresh", "source_failures": 0},
    )
    assert report["review_status"] == "waiting_for_window"
    assert report["collections"]["scheduled"] == 0
    assert not report["automated_review_completed"]


def test_due_review_records_real_schedules_and_no_automatic_uptime_claim():
    collections = [run(START + timedelta(hours=12, days=i)) for i in range(7)]
    monitors = [run(START + timedelta(hours=1 + 6 * i)) for i in range(28)]
    report = summarize(
        collections,
        monitors,
        START + timedelta(days=7, minutes=1),
        3000,
        observation_start=START.isoformat(),
        public_health={"status": "fresh", "source_failures": 0},
    )
    assert report["review_status"] == "review_without_detected_operational_findings"
    assert report["automated_review_completed"]
    assert report["collections"]["scheduled"] == 7
    assert any("uptime" in limitation for limitation in report["limitations"])
    report = summarize(
        collections,
        monitors,
        START + timedelta(days=7, minutes=1),
        3000,
        observation_start=START.isoformat(),
        history_limit=7,
        public_health={"status": "fresh", "source_failures": 0},
    )
    assert report["review_status"] == "incomplete_history"
    assert report["review_status"] != "review_without_detected_operational_findings"
    assert not report["automated_review_completed"]


@pytest.mark.parametrize("anchor", ["2026-10-26T11:53:57", "2026-11-10T00:00:00Z"])
def test_invalid_or_future_anchor_cannot_manufacture_elapsed_history(anchor):
    with pytest.raises(ValueError):
        summarize([], [], START, observation_start=anchor)


def test_fresh_manual_publications_cannot_hide_a_missing_scheduled_run():
    current = START + timedelta(days=1, hours=5)
    manual = [run(current - timedelta(minutes=1), "workflow_dispatch")]
    report = summarize(
        manual,
        manual,
        current,
        observation_start=START.isoformat(),
        public_health={"status": "fresh", "source_failures": 0},
    )
    assert report["schedule_cadence"]["collection"]["overdue"]
    assert report["schedule_cadence"]["monitor"]["overdue"]
    assert report["review_status"] == "waiting_for_window"
    assert not report["automated_review_completed"]


def test_new_cadence_anchor_is_separate_from_the_seven_day_service_anchor():
    current = START + timedelta(days=1)
    activation = current - timedelta(minutes=1)
    report = summarize(
        [],
        [],
        current,
        observation_start=START.isoformat(),
        schedule_observation_start=activation.isoformat(),
    )
    assert report["first_observed_run"] == START.isoformat()
    assert report["review_after"] == (START + timedelta(days=7)).isoformat()
    assert all(
        c["status"] == "no_trigger_due_in_observation_window"
        for c in report["schedule_cadence"].values()
    )
    assert not report["seven_day_window_complete"]


def test_current_scheduled_success_is_distinct_from_grace_and_overdue():
    from checks.operations_report import schedule_observation

    activation = START.replace(hour=12, minute=0)
    trigger = activation.replace(minute=43)
    within = schedule_observation([], activation, trigger + timedelta(hours=1), (12,), 43)
    overdue = schedule_observation([], activation, trigger + timedelta(hours=3), (12,), 43)
    success = schedule_observation(
        [run(trigger + timedelta(minutes=15))], activation, trigger + timedelta(hours=3), (12,), 43
    )
    assert within["status"] == "within_trigger_grace_period" and not within["overdue"]
    assert overdue["overdue"]
    assert success["status"] == "recent_scheduled_success_observed" and not success["overdue"]


def test_future_and_preanchor_runs_do_not_count_as_observed_service():
    current = START + timedelta(hours=1)
    report = summarize(
        [run(START - timedelta(minutes=1)), run(current + timedelta(days=1))],
        [],
        current,
        observation_start=START.isoformat(),
    )
    assert report["collections"]["observed"] == 0
    assert report["collections"]["scheduled_successful"] == 0


@pytest.mark.parametrize(
    "anchor", ["2026-10-26T11:53:57", "2026-10-25T00:00:00Z", "2026-11-10T00:00:00Z"]
)
def test_invalid_cadence_anchor_cannot_reset_or_advance_service_history(anchor):
    with pytest.raises(ValueError):
        summarize(
            [],
            [],
            START + timedelta(days=1),
            observation_start=START.isoformat(),
            schedule_observation_start=anchor,
        )


def test_operational_failures_identify_each_overdue_workflow():
    current = datetime(2026, 11, 2, 17, tzinfo=timezone.utc)
    manual = [run(current - timedelta(minutes=1), "workflow_dispatch")]
    report = summarize(
        manual,
        manual,
        current,
        observation_start=START.isoformat(),
        public_health={"status": "fresh", "source_failures": 0},
    )
    assert report["public_health"]["status"] == "fresh"
    failures = report["operational_failures"]
    assert [failure["code"] for failure in failures] == [
        "collection_schedule_overdue",
        "monitor_schedule_overdue",
    ]
    for failure, workflow, expected, deadline in zip(
        failures,
        ["collect.yaml", "monitor.yaml"],
        ["2026-11-02T12:43:00+00:00", "2026-11-02T12:23:00+00:00"],
        ["2026-11-02T14:43:00+00:00", "2026-11-02T14:23:00+00:00"],
        strict=True,
    ):
        assert failure["workflow"] == workflow
        assert failure["expected_trigger_at"] == expected
        assert failure["latest_successful_scheduled_run_created_at"] is None
        assert failure["grace_deadline_at"] == deadline
        assert all(value in failure["message"] for value in [workflow, expected, deadline])


def test_operational_failures_retain_storage_with_cadence():
    report = summarize(
        [],
        [],
        datetime(2026, 11, 2, 17, tzinfo=timezone.utc),
        repository_size_kib=524288,
        observation_start=START.isoformat(),
    )
    assert [failure["code"] for failure in report["operational_failures"]] == [
        "collection_schedule_overdue",
        "monitor_schedule_overdue",
        "repository_storage_budget_exceeded",
    ]
    failure = report["operational_failures"][-1]
    for field in (
        "workflow",
        "expected_trigger_at",
        "latest_successful_scheduled_run_created_at",
        "grace_deadline_at",
    ):
        assert failure[field] is None
    assert "524288 KiB" in failure["message"]
    assert "budget" in failure["message"]
    assert report["storage_review_required"]
    assert "Repository storage budget requires operator review" in report["findings"]


@pytest.mark.parametrize(
    "current,collections,monitors",
    [
        (datetime(2026, 10, 26, 12, tzinfo=timezone.utc), [], []),
        (datetime(2026, 10, 26, 14, 23, tzinfo=timezone.utc), [], []),
        (
            datetime(2026, 11, 2, 17, tzinfo=timezone.utc),
            [run(datetime(2026, 11, 2, 12, 58, tzinfo=timezone.utc))],
            [run(datetime(2026, 11, 2, 12, 38, tzinfo=timezone.utc))],
        ),
    ],
    ids=["no-trigger-due", "grace-deadline-inclusive", "current-scheduled-success"],
)
def test_no_operational_failures_before_overdue_cadence(current, collections, monitors):
    report = summarize(collections, monitors, current, observation_start=START.isoformat())
    assert report["repository_size_kib"] is None
    assert not report["storage_review_required"]
    assert report["operational_failures"] == []


def test_overdue_diagnostic_keeps_latest_observation_and_old_failures():
    report = summarize(
        [run(datetime(2026, 11, 1, 18, 5, 45, tzinfo=timezone.utc))],
        [dict(run(START + timedelta(days=1)), conclusion="failure")],
        datetime(2026, 11, 2, 17, tzinfo=timezone.utc),
        observation_start=START.isoformat(),
    )
    failure = report["operational_failures"][0]
    assert failure["latest_successful_scheduled_run_created_at"] == "2026-11-01T18:05:45+00:00"
    assert "2026-11-01T18:05:45+00:00" in failure["message"]
    assert report["monitors"]["scheduled_failed"] == 1
    assert "Failed, cancelled or timed-out workflows occurred in the window" in report["findings"]


def operations_cli(
    tmp_path, *, current, repository_size=3000, health='{"status": "fresh", "source_failures": 0}'
):
    """Replace only the external gh boundary; run the real CLI in a child process."""
    gh = tmp_path / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "with Path(__file__).with_name('gh-calls.jsonl').open('a') as stream:\n"
        "    stream.write(json.dumps(args) + '\\n')\n"
        "if args == ['api', 'repos/example/service']:\n"
        f"    print(json.dumps({{'size': {repository_size!r}}}))\n"
        "elif args[:2] == ['run', 'list'] and args[args.index('--workflow') + 1] in "
        "['collect.yaml', 'monitor.yaml']:\n"
        "    print('[]')\n"
        "else:\n"
        "    raise SystemExit('Unexpected gh invocation: ' + repr(args))\n"
    )
    gh.chmod(0o755)
    receipt = tmp_path / "health.json"
    if health is not None:
        receipt.write_text(health)
    output, summary = tmp_path / "operations.json", tmp_path / "summary.md"
    # The fixed clock changes only datetime.now; parsing and cadence arithmetic stay real.
    runner = (
        "from datetime import datetime\n"
        "from checks import operations_report\n"
        "class Clock(datetime):\n"
        "    @classmethod\n"
        "    def now(cls, tz=None):\n"
        f"        return datetime.fromisoformat({current!r})\n"
        "operations_report.datetime = Clock\n"
        "operations_report.main()\n"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            runner,
            "--repository",
            "example/service",
            "--output",
            str(output),
            "--summary",
            str(summary),
            "--observation-start",
            START.isoformat(),
            "--health-report",
            str(receipt),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        text=True,
    )
    report = json.loads(output.read_text())
    summary_text = summary.read_text()
    assert json.loads(summary_text.split("```json\n")[1].split("\n```")[0]) == report
    calls = [json.loads(line) for line in (tmp_path / "gh-calls.jsonl").read_text().splitlines()]
    assert calls == [["api", "repos/example/service"]] + [
        [
            "run",
            "list",
            "--repo",
            "example/service",
            "--workflow",
            workflow,
            "--limit",
            "1000",
            "--json",
            "createdAt,status,conclusion,event,url",
        ]
        for workflow in ("collect.yaml", "monitor.yaml")
    ]
    return result, report


@pytest.mark.parametrize("repository_size", [524287, 524288, 600000])
def test_cli_retains_complete_receipts_and_explains_all_operational_failures(
    tmp_path, repository_size
):
    result, report = operations_cli(
        tmp_path, current="2026-11-02T17:00:00+00:00", repository_size=repository_size
    )
    assert result.returncode != 0
    assert report["public_health"]["status"] == "fresh"
    for value in (
        "collection_schedule_overdue",
        "collect.yaml",
        "2026-11-02T14:43:00+00:00",
        "monitor_schedule_overdue",
        "monitor.yaml",
        "2026-11-02T14:23:00+00:00",
    ):
        assert value in result.stderr
    assert json.loads(result.stdout)["storage_review_required"] == (repository_size >= 524288)
    if repository_size >= 524288:
        assert "repository_storage_budget_exceeded" in result.stderr
        assert f"{repository_size} KiB" in result.stderr
        assert "524288 KiB" in result.stderr
    else:
        assert "repository_storage_budget_exceeded" not in result.stderr


def test_cli_without_operational_failures_keeps_successful_command_behavior(tmp_path):
    result, report = operations_cli(tmp_path, current="2026-10-26T12:00:00+00:00")
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert report["operational_failures"] == []
    assert json.loads(result.stdout) == {
        "elapsed_days": 0.004,
        "seven_day_window_complete": False,
        "storage_review_required": False,
    }


@pytest.mark.parametrize("health", [None, "{invalid", "[]", "null", '"fresh"', "42", "true"])
def test_cli_keeps_missing_or_malformed_health_unavailable(tmp_path, health):
    result, report = operations_cli(tmp_path, current="2026-10-26T12:00:00+00:00", health=health)
    assert result.returncode == 0, result.stderr
    assert report["public_health"]["status"] == "unavailable"
    assert "No successful current public-health receipt" in report["findings"]
