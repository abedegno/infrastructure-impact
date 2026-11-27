"""Research findings cannot silently become dates, incidents or approved evidence."""

import json
from pathlib import Path

from infrastructure_impact.application import release_reliability as rr

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "docs/research"


def read(name):
    return json.loads((RESEARCH / ("2026-11-27-round6-" + name + ".json")).read_text())


def test_preview_replays_unique_pairs_and_pending_reason_reviews():
    preview = read("preview")
    assert (
        rr.build_report(
            preview["catalogue"],
            preview["config"],
            publication=None,
            generated_at=preview["generated_at"],
            staircase_join_version=1,
        )
        == preview
    )
    pairs = preview["respins"]
    assert (
        len(pairs)
        == len(
            {(p["vendor"], p["train"], p["previous_release"], p["followup_release"]) for p in pairs}
        )
        == 4
    )
    assert not any(p["previous_release"] is None and p["vendor"] == "cisco" for p in pairs)
    assert all(p["build_reason"] == "unknown" for p in pairs)
    reviews = read("review")
    assert reviews["items"] == preview["review_packet"]
    reasons = [i for i in reviews["items"] if i["type"] == "build_reason"]
    assert {i["fact"]["version"] for i in reasons} == {"10.13.1031", "10.13.1161"}
    assert all(i["build_reason"] == "security_fix" and i["platforms_stated"] == [] for i in reasons)
    assert all(i["review_status"] == "independent_human_review_pending" for i in reviews["items"])
    assert "unique_respin_identity" in preview["validation"]["checks"]
    assert all(m["rate"] is None for r in preview["annual"] for m in r["metrics"].values())


def test_unestablished_cisco_references_and_control_remain_outside_catalogue():
    findings = {r["version"]: r for r in read("build-sources")["findings"]}
    for version in ("17.12.5a", "17.12.5b", "17.12.7a"):
        assert findings[version]["build_reason"] == "unknown"
    versions = {r["version"] for r in read("preview")["catalogue"]["releases"]}
    assert not {"17.12.5a", "17.12.5b", "17.9.6"} & versions
    control = read("dates-control")["control_17_9_6"]
    assert control["outside_cohort"] and control["result"] == "not_established"
    assert control["notice_date"] is control["action_date"] is control["release_date"] is None
    assert control["fresh_evidence_ids"] and control["tried_receipts"]


def test_build_reasons_retain_original_advisory_provenance_without_dates():
    report = read("preview")
    sources = {s["source_id"]: s for s in report["catalogue"]["sources"]}
    facts = [r for r in report["catalogue"]["releases"] if r.get("build_reason") == "security_fix"]
    assert len(facts) == 2
    for fact in facts:
        assert fact["release_date"] is None and fact["date_status"] == "unknown"
        assert fact["platforms_stated"] == []
        for proof in fact["build_reason_evidence"]:
            assert proof["advisory_id"].startswith("HPESBNW")
            for ref in proof["evidence"]:
                source = sources[ref["source_id"]]
                assert source["capture_kind"] == "original_document" and source["original_sha256"]
                assert ref["locator"] and fact["version"] in ref["quote"]
