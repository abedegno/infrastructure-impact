"""Elapsed observation windows, stable anchors and actual scheduled-run evidence."""

import json
import os
import re
import subprocess
import sys
import textwrap
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


WORKFLOW_ROOT = Path(__file__).resolve().parents[1] / ".github/workflows"
HEALTH_STEP = "Check public HTML, dataset age and fingerprints"
OPERATIONS_STEP = "Summarize the seven-day observation window and storage budget"
STORAGE_STEP = "Assess encrypted backup growth without downloading evidence"


def workflow_step(workflow, name):
    """Read named step fields from this repo's YAML subset without adding a dependency."""
    source = (WORKFLOW_ROOT / workflow).read_text()
    steps = re.split(r"(?=^      - (?:name|uses):)", source, flags=re.MULTILINE)
    block = next((step for step in steps if step.startswith(f"      - name: {name}\n")), None)
    assert block is not None, f"Missing workflow step {workflow}: {name}"
    fields = {}
    lines = block.splitlines()
    for index, line in enumerate(lines[1:], 1):
        match = re.fullmatch(r"        ([\w-]+): (.*)", line)
        if match:
            key, value = match.groups()
            if value == "|":
                following = []
                for nested in lines[index + 1 :]:
                    if nested and not nested.startswith("          "):
                        break
                    following.append(nested)
                value = textwrap.dedent("\n".join(following)) + "\n"
            fields[key] = value
    return block, fields


def workflow_environment(
    tmp_path, *, health_exit=0, health='{"status":"fresh","source_failures":0}'
):
    """Replace external public HTTP/gh boundaries; keep Bash, summaries and check CLIs real."""
    python = tmp_path / "python3"
    python.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "args = sys.argv[1:]\n"
        "if args and args[0] == 'checks/public_health.py':\n"
        "    assert args == ['checks/public_health.py', 'https://example.invalid/']\n"
        f"    print({health!r})\n"
        f"    raise SystemExit({health_exit})\n"
        "if args and args[0] == 'checks/operations_report.py':\n"
        f"    sys.path.insert(0, {str(WORKFLOW_ROOT.parents[1])!r})\n"
        "    from datetime import datetime\n"
        "    from checks import operations_report\n"
        "    class Clock(datetime):\n"
        "        @classmethod\n"
        "        def now(cls, tz=None):\n"
        "            return datetime.fromisoformat('2026-11-02T17:00:00+00:00')\n"
        "    operations_report.datetime = Clock\n"
        "    sys.argv = args\n"
        "    operations_report.main()\n"
        "    raise SystemExit(0)\n"
        f"os.execv({sys.executable!r}, [{sys.executable!r}, *args])\n"
    )
    python.chmod(0o755)
    gh = tmp_path / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['api', 'repos/example/service']:\n"
        "    value = {'size': 3000}\n"
        "elif args[:2] == ['run', 'list']:\n"
        "    assert args == ['run', 'list', '--repo', 'example/service', '--workflow',\n"
        "                    args[5], '--limit', '1000', '--json',\n"
        "                    'createdAt,status,conclusion,event,url']\n"
        "    assert args[5] in ['collect.yaml', 'monitor.yaml']\n"
        "    value = []\n"
        "elif args == ['api', 'repos/example/service/commits?sha=publication-state&per_page=100']:\n"
        "    value = [{'sha': 'head', 'commit': {'tree': {'sha': 'tree'}}}]\n"
        "elif args == ['api', 'repos/example/service/git/trees/tree?recursive=1']:\n"
        "    value = {'truncated': False, 'tree': [\n"
        "        {'path': 'state/vault-synthetic.fernet', 'sha': 'blob', 'size': 100, 'type': 'blob'}]}\n"
        "elif args == ['api', 'repos/example/service/contents/state/current.json?ref=head',\n"
        "              '-H', 'Accept: application/vnd.github.raw+json']:\n"
        "    value = {'archive': 'vault-synthetic.fernet', 'encryption': 'fernet-v1'}\n"
        "else:\n"
        "    raise SystemExit('Unexpected gh invocation: ' + repr(args))\n"
        "print(json.dumps(value))\n"
    )
    gh.chmod(0o755)
    return {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "PUBLIC_URL": "https://example.invalid/",
        "REPOSITORY": "example/service",
        "OBSERVATION_START": START.isoformat(),
        "SCHEDULE_START": START.isoformat(),
        "VAULT_PROFILE": "standard",
    }


def execute_workflow_step(workflow, name, env):
    _, fields = workflow_step(workflow, name)
    return subprocess.run(
        ["bash", "-c", fields["run"]],
        cwd=WORKFLOW_ROOT.parents[1],
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("workflow", ["monitor.yaml", "operations.yaml"])
@pytest.mark.parametrize("exit_code", [0, 13])
def test_health_workflow_pipeline_preserves_upstream_exit_and_receipt(
    tmp_path, workflow, exit_code
):
    env = workflow_environment(tmp_path, health_exit=exit_code)
    result = execute_workflow_step(workflow, HEALTH_STEP, env)
    assert result.returncode == exit_code, result.stderr
    assert json.loads((tmp_path / "public-health.json").read_text()) == {
        "status": "fresh",
        "source_failures": 0,
    }


@pytest.mark.parametrize("workflow", ["monitor.yaml", "operations.yaml"])
@pytest.mark.parametrize("outcome", ["success", "failure"])
@pytest.mark.parametrize(
    "receipt,success_status",
    [
        ('{"status":"fresh","source_failures":0}', "fresh"),
        (None, "unavailable"),
        ("{bad", "unavailable"),
        ("[]", "unavailable"),
        ("{}", "unavailable"),
        ('{"status":"failed"}', "unavailable"),
    ],
)
def test_health_summary_retains_actual_outcome_without_inventing_freshness(
    tmp_path, workflow, outcome, receipt, success_status
):
    env = workflow_environment(tmp_path)
    env["CHECK_OUTCOME"] = outcome
    if receipt is not None:
        (tmp_path / "public-health.json").write_text(receipt)
    block, fields = workflow_step(workflow, "Summarize public health")
    assert fields["if"] == "always()"
    assert "CHECK_OUTCOME: ${{ steps.public-health.outcome }}" in block
    result = execute_workflow_step(workflow, "Summarize public health", env)
    assert (result.returncode != 0) == (outcome == "success" and success_status == "unavailable"), (
        result.stderr
    )
    retained = json.loads((tmp_path / "public-health.json").read_text())
    assert retained["check_outcome"] == outcome
    expected = "failed" if outcome == "failure" else success_status
    assert retained["status"] == expected
    summary = (tmp_path / "summary.md").read_text()
    assert outcome in summary and expected in summary
    if expected == "fresh":
        assert retained["source_failures"] == 0


def test_workflow_split_keeps_trusted_source_read_only_boundaries():
    monitor = (WORKFLOW_ROOT / "monitor.yaml").read_text()
    operations = WORKFLOW_ROOT / "operations.yaml"
    assert operations.exists(), "Operations checks still share the public-health conclusion"
    operations = operations.read_text()
    assert "name: Public service health" in monitor
    assert "cron: '23 */6 * * *'" in monitor
    assert "ref: ${{ vars.IMPACT_SOURCE_COMMIT }}" in monitor
    assert "operations_report.py" not in monitor and "backup_storage.py" not in monitor
    assert "name: Service operations" in operations
    assert "cron: '53 */6 * * *'" in operations
    assert "ref: ${{ github.sha }}" in operations
    assert (
        "    if: ${{ github.ref == format('refs/heads/{0}', github.event.repository.default_branch) }}"
        in operations
    )
    for source in (monitor, operations):
        assert "  workflow_dispatch:" in source
        assert source.split("permissions:\n")[1].split("jobs:\n")[0] == (
            "  contents: read\n  actions: read\n"
        )
        triggers = source.split("on:\n", 1)[1].split("permissions:\n", 1)[0]
        assert set(re.findall(r"^  (\w+):", triggers, re.MULTILINE)) == {
            "workflow_dispatch",
            "schedule",
        }
        assert len(re.findall(r"^permissions:", source, re.MULTILINE)) == 1
        assert "timeout-minutes: 5" in source
        assert "persist-credentials: false" in source
        assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in source
        assert "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" in source
        for forbidden in (
            "secrets.",
            ": write",
            "workflow_run:",
            "pull_request",
            "workflow dispatch",
            "continue-on-error",
            "gh workflow run",
            "IMPACT_EVIDENCE_KEY",
            "download-artifact",
            "hosted_job.py",
            "git push",
            "gh api --method",
            "restore",
            "--method POST",
        ):
            assert forbidden not in source


@pytest.mark.parametrize("event", ["schedule", "workflow_dispatch"])
@pytest.mark.parametrize(
    "default_branch,branch,allowed",
    [
        ("main", "main", True),
        ("main", "feature", False),
        ("release", "main", False),
        ("release", "release", True),
    ],
)
def test_operations_event_sha_is_only_used_on_the_default_branch(
    event, default_branch, branch, allowed
):
    source = (WORKFLOW_ROOT / "operations.yaml").read_text()
    condition = re.search(r"^    if: \$\{\{ (.+) \}\}$", source, re.MULTILINE)
    assert condition, "Both operations event types require a default-branch job guard"
    # Evaluate the actual equality condition over realistic event/ref contexts.
    operands = condition[1].split(" == ")
    context = {
        "github.ref": f"refs/heads/{branch}",
        "format('refs/heads/{0}', github.event.repository.default_branch)": f"refs/heads/{default_branch}",
    }
    assert len(operands) == 2
    assert (context[operands[0]] == context[operands[1]]) is allowed, event


@pytest.mark.parametrize("health_exit", [0, 13])
def test_operations_failure_keeps_health_independent_and_retains_all_receipts(
    tmp_path, health_exit
):
    env = workflow_environment(tmp_path, health_exit=health_exit)
    health = execute_workflow_step("operations.yaml", HEALTH_STEP, env)
    assert health.returncode == health_exit
    env["CHECK_OUTCOME"] = "success" if health_exit == 0 else "failure"
    summary = execute_workflow_step("operations.yaml", "Summarize public health", env)
    assert summary.returncode == 0, summary.stderr
    for step in (OPERATIONS_STEP, STORAGE_STEP):
        assert workflow_step("operations.yaml", step)[1]["if"] == "always()"
    report = execute_workflow_step("operations.yaml", OPERATIONS_STEP, env)
    assert report.returncode != 0
    assert "collection_schedule_overdue" in report.stderr
    assert "monitor_schedule_overdue" in report.stderr
    stored = json.loads((tmp_path / "operations.json").read_text())
    assert stored["public_health"]["status"] == ("fresh" if health_exit == 0 else "failed")
    storage = execute_workflow_step("operations.yaml", STORAGE_STEP, env)
    assert storage.returncode == 0, storage.stderr
    artifact, fields = workflow_step("operations.yaml", "Retain operational review evidence")
    assert fields["if"] == "always()"
    assert "name: reliability-review-${{ github.run_id }}" in artifact
    assert "if-no-files-found: warn" in artifact and "retention-days: 30" in artifact
    for filename in ("operations.json", "backup-storage.json", "public-health.json"):
        assert f"${{{{ runner.temp }}}}/{filename}" in artifact
        assert json.loads((tmp_path / filename).read_text())


def test_monitor_retains_public_health_receipt_even_after_failure():
    artifact, fields = workflow_step("monitor.yaml", "Retain public health evidence")
    assert fields["if"] == "always()"
    assert "name: public-health-${{ github.run_id }}" in artifact
    assert "${{ runner.temp }}/public-health.json" in artifact
    assert "if-no-files-found: warn" in artifact and "retention-days: 30" in artifact


@pytest.mark.parametrize("workflow", ["monitor.yaml", "operations.yaml"])
def test_real_public_checker_failure_propagates_through_workflow_tee(tmp_path, workflow):
    env = {
        **os.environ,
        "PUBLIC_URL": (tmp_path / "missing-publication").as_uri() + "/",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }
    result = execute_workflow_step(workflow, HEALTH_STEP, env)
    assert result.returncode != 0
    assert "URLError" in result.stderr
    assert (tmp_path / "public-health.json").read_text() == ""
    env["CHECK_OUTCOME"] = "failure"
    summary = execute_workflow_step(workflow, "Summarize public health", env)
    assert summary.returncode == 0, summary.stderr
    assert json.loads((tmp_path / "public-health.json").read_text()) == {
        "status": "failed",
        "check_outcome": "failure",
    }


def test_successful_public_monitor_is_independent_of_overdue_operations(tmp_path):
    monitor_dir, operations_dir = tmp_path / "monitor", tmp_path / "operations"
    monitor_dir.mkdir()
    operations_dir.mkdir()
    monitor_env = workflow_environment(monitor_dir)
    assert execute_workflow_step("monitor.yaml", HEALTH_STEP, monitor_env).returncode == 0
    monitor_env["CHECK_OUTCOME"] = "success"
    assert (
        execute_workflow_step("monitor.yaml", "Summarize public health", monitor_env).returncode
        == 0
    )
    operations_env = workflow_environment(operations_dir)
    assert execute_workflow_step("operations.yaml", HEALTH_STEP, operations_env).returncode == 0
    operations_env["CHECK_OUTCOME"] = "success"
    assert (
        execute_workflow_step(
            "operations.yaml", "Summarize public health", operations_env
        ).returncode
        == 0
    )
    operations = execute_workflow_step("operations.yaml", OPERATIONS_STEP, operations_env)
    assert operations.returncode != 0
    assert "monitor_schedule_overdue" in operations.stderr
    assert json.loads((monitor_dir / "public-health.json").read_text())["status"] == "fresh"
