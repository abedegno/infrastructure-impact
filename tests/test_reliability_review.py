"""Elapsed observation windows, stable anchors and actual scheduled-run evidence."""

from datetime import datetime, timedelta, timezone

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
