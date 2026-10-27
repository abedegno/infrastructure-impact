"""Evidence denominators, revision chronology and API/static cohort parity."""

import copy
import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from infrastructure_impact.adapters.common import assessment, base
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.application.scorecards import scorecards
from infrastructure_impact.application.timeline import evidence_timeline
from infrastructure_impact.exports import select
from infrastructure_impact.http import Application
from infrastructure_impact.storage.repository import connect, ingest, semantic_diff

CID = "CVE-2025-12345"
OTHER = "CVE-2025-54321"
URL = "https://www.arista.com/example-advisory"


def record():
    r = base("arista", URL, "SYNTHETIC-1", "Example", "2020-01-01")
    r["document_status"] = "final"
    r["cves"] = [CID]
    r["notes"] = [{"text": "PRIVATE_TIMELINE_NOTE"}]
    r["assessments"] = [
        assessment(CID, "Example router", "affected", "synthetic", versions=[{"version": "1.x"}]),
        assessment(CID, "Example router", "fixed", "synthetic", versions=[{"version": "2.x"}]),
    ]
    r["assessments"][1]["product_id"] += ":2.x"
    return r


def test_missing_vendor_statement_cannot_become_unaffected_or_better_coverage():
    at = datetime(2026, 10, 26, tzinfo=timezone.utc)
    r = record()
    r["assessments"].append(assessment(OTHER, "Other product", "unknown", "synthetic"))
    profiles = {
        "vendors": [
            dict(vendor="arista", sources=[dict(url=URL, role="pinned")], stale_after_hours=36)
        ]
    }
    checks = [
        dict(
            vendor="arista",
            source_url=URL,
            outcome="error",
            checked_at=(at - timedelta(hours=40)).isoformat(),
            error_code="access_denied",
        )
    ]
    checks.append({**checks[0], "source_url": URL + "/discovered"})
    cards = scorecards(
        [r],
        [],
        profiles,
        checks,
        [CID, OTHER],
        {"arista": "Arista", "missing": "Missing Vendor"},
        at.isoformat(),
    )["vendors"]
    assert cards[0]["status_counts"]["affected"] == 1
    assert cards[0]["status_counts"]["fixed"] == 1
    assert cards[0]["explicit_unknown"] == 1
    assert cards[0]["source_outcomes"] == {"error": 1}
    assert len(cards[0]["additional_source_errors"]) == 1
    assert cards[0]["stale_sources"] == 1
    assert cards[1]["without_statement"] == 2
    assert cards[1]["explicit_unknown"] == 0
    assert cards[1]["status_counts"]["unaffected"] == 0
    assert all(c["cohort_size"] == 2 for c in cards)
    r["document_status"] = "draft"
    assert (
        scorecards([r], [], profiles, checks, [CID], {"arista": "Arista"}, at.isoformat())[
            "vendors"
        ][0]["without_statement"]
        == 1
    )


def test_revision_timeline_separates_publisher_dates_parser_changes_and_removals():
    r = record()
    with connect(":memory:") as db:
        ingest(db, b"first", URL, lambda *_: r, "arista")
        r["cves"].append(OTHER)
        r["assessments"].append(assessment(OTHER, "Example other", "investigating", "synthetic"))
        ingest(db, b"second", URL, lambda *_: r, "arista")
        r["adapter_version"] = "b" * 16
        r["assessments"][-1]["status"] = "unaffected"
        ingest(db, b"second", URL, lambda *_: r, "arista")
        r["cves"].remove(OTHER)
        r["assessments"] = [a for a in r["assessments"] if a["cve_id"] != OTHER]
        ingest(db, b"third", URL, lambda *_: r, "arista")
        timeline = evidence_timeline(db)
        events = timeline["events"]
        assert any(
            e["kind"] == "first_observed"
            and e["publisher_published_at"] == "2020-01-01"
            and e["observed_at"] > "2020"
            for e in events
        )
        assert any(e["cve_reference_added"] and e["cve_id"] == OTHER for e in events)
        assert any(
            e["kind"] == "parser_reinterpretation" and not e["cve_reference_added"] for e in events
        )
        removed = next(e for e in events if e["cve_id"] == OTHER and not e["reference_present"])
        assert removed["statuses"] == []
        assert "PRIVATE_TIMELINE_NOTE" not in json.dumps(timeline)
        bounded = evidence_timeline(db, max_revisions=1, max_events=1)
        assert bounded["history_truncated"]
        assert all(e["kind"] != "first_observed" for e in bounded["events"])
        event_bounded = evidence_timeline(db, max_events=1)
        assert event_bounded["events_truncated"]
        assert len(event_bounded["events"]) == 1


def test_api_scorecard_timeline_filter_and_static_artifacts(tmp_path):
    with connect(":memory:") as db:
        ingest(db, b"synthetic", URL, lambda *_: record(), "arista")
        data = state(db)
    generation = publish(data, root=tmp_path)
    app = Application(tmp_path)
    for endpoint, key in [("scorecards", "vendors"), ("timeline", "events")]:
        status, _, body = app.route(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/v1/" + endpoint,
                "QUERY_STRING": f"cves={CID}&vendor=arista",
            }
        )
        payload = json.loads(body)
        assert status == 200
        assert payload[key]
        assert all(row["vendor"] == "arista" for row in payload[key])
        assert (generation / (endpoint + ".json")).exists()
    for path in ("/api/v1/scorecards", "/api/v1/timeline"):
        responses = []
        app(
            {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": "vendor=does-not-exist"},
            lambda status, headers: responses.append(status),
        )
        assert responses == ["400 Bad Request"]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node required for static reader parity")
def test_static_and_python_selection_have_identical_scorecards_and_timelines():
    with connect(":memory:") as db:
        ingest(db, b"synthetic", URL, lambda *_: record(), "arista")
        data = state(db)
    ids = [CID, "CVE-1999-999999"]
    expected = select(copy.deepcopy(data), ids)
    script = """const fs=require('fs'),vm=require('vm');const c={window:{},Set,URL,Response,Blob};vm.createContext(c);vm.runInContext(fs.readFileSync('infrastructure_impact/web/research-dossiers.js','utf8'),c);vm.runInContext(fs.readFileSync('infrastructure_impact/web/snapshot.js','utf8'),c);const input=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(c.selectSnapshot(input.data,input.ids)));"""
    result = subprocess.run(
        ["node", "-e", script],
        input=json.dumps(dict(data=data, ids=ids)),
        text=True,
        capture_output=True,
        check=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    actual = json.loads(result.stdout)
    for key in ("scorecards", "timeline", "coverage"):
        assert actual[key] == expected[key]
    assert (
        actual["scorecards"]["vendors"][0]["cases"][1]["cve_id"] == CID
    )  # IDs are sorted, never position-matched.


def test_reported_fix_date_changes_are_visible_without_an_affectedness_claim():
    before = record()
    after = {**before, "reported_fix_date": "2024-01-01"}
    assert semantic_diff(before, after) == [
        {"field": "reported_fix_date", "before": None, "after": "2024-01-01"}
    ]
