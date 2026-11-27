"""Unique respin pairs retain scoped timing and independently evidenced reasons."""

from copy import deepcopy

import pytest
from test_reliability_corrections import configured

from infrastructure_impact.application import release_catalogue as cat
from infrastructure_impact.application import release_reliability as rr


def unique(d):
    d["respin_identity"] = "vendor_train_previous_followup"
    return d


def test_respin_pair_unions_models_and_source_locators():
    d, c = configured("aruba", [("10.13.1000", "2024-01-01"), ("10.13.1005", "2024-02-01")])
    c["trains"][0]["platforms"] = ["6200", "6300"]
    d["releases"][0]["platforms_stated"] = ["6200", "6300"]
    d["releases"][1]["platforms_stated"] = ["6200"]
    other = deepcopy(d["releases"][1])
    other["platforms_stated"] = ["6300"]
    other["evidence"][0]["locator"] = "6300 release history"
    d["releases"].append(other)
    pairs = cat.find_respins(unique(d), c)
    assert len(pairs) == 1
    row = pairs[0]
    assert row["platforms_stated"] == ["6200", "6300"]
    assert len(row["observations"]) == 2
    assert {e["locator"] for e in row["evidence"]} == {
        "Release history / row",
        "6300 release history",
    }
    assert row["days"] == 31


def test_resolved_predecessor_replaces_null_without_inventing_model_binding():
    d, c = configured("cisco", [("17.12.7", None), ("17.12.7a", None)])
    c["trains"][0]["platforms"] = ["9200", "9300"]
    d["releases"][0]["platforms_stated"] = ["9300"]
    d["releases"][1]["platforms_stated"] = ["9200", "9300"]
    (row,) = cat.find_respins(unique(d), c)
    assert row["previous_release"] == "17.12.7"
    assert row["platforms_stated"] == ["9200", "9300"]
    assert {(o["previous_release"], tuple(o["platforms_stated"])) for o in row["observations"]} == {
        (None, ("9200",)),
        ("17.12.7", ("9300",)),
    }
    assert row["days"] is None and row["production_eligible"] is False


def test_conflicting_scoped_timings_stay_in_observations_and_annual_counts():
    d, c = configured("cisco", [("17.12.7", "2025-01-01"), ("17.12.7a", "2025-01-10")])
    c["trains"][0]["platforms"] = ["9200", "9300"]
    for r in d["releases"]:
        r["platforms_stated"] = ["9200"]
    others = deepcopy(d["releases"])
    for r, day in zip(others, ["2025-01-02", "2025-02-15"]):
        r["platforms_stated"] = ["9300"]
        r["release_date"] = day
    d["releases"].extend(others)
    report = rr.build_report(unique(d), c, publication=None, generated_at=d["generated_at"])
    (row,) = report["respins"]
    assert row["days"] is None and row["within_30_days"] is None
    assert {o["days"] for o in row["observations"]} == {9, 44}
    assert report["annual"][1]["metrics"]["possible_respin_30"]["numerator"] == 1
    bad = deepcopy(report)
    bad["respins"].append(deepcopy(row))
    with pytest.raises(ValueError, match="Duplicate respin identity"):
        rr.validate_report(bad)


def reason(kind="security_fix"):
    return {
        "reason": kind,
        "advisory_id": "TEST-SA-1" if kind == "security_fix" else None,
        "predecessor": None if kind == "security_fix" else "10.13.1000",
        "platforms_stated": [],
        "evidence": [
            {
                "source_id": "s1",
                "locator": "Fixed Software / row",
                "quote": "10.13.1005 fixes the issue in 10.13.1000",
            }
        ],
    }


def test_build_reason_is_separate_from_timing_and_requires_proof():
    d, c = configured("aruba", [("10.13.1000", "2024-01-01"), ("10.13.1005", "2024-02-01")])
    r = d["releases"][1]
    r.update(build_reason="security_fix", build_reason_evidence=[reason()])
    report = rr.build_report(unique(d), c, publication=None, generated_at=d["generated_at"])
    (pair,) = report["respins"]
    assert pair["classification"] == "possible_respin"
    assert pair["build_reason"] == "security_fix" and pair["build_reason_evidence"] == [reason()]
    assert report["review_packet"][0]["build_reason"] == "security_fix"
    r["build_reason"] = "both"
    with pytest.raises(ValueError, match="reason"):
        cat.validate_catalogue(d)


def test_build_reason_does_not_come_from_timing_or_unrelated_source():
    d, c = configured("aruba", [("10.13.1000", "2024-01-01"), ("10.13.1005", "2024-01-02")])
    (pair,) = cat.find_respins(unique(d), c)
    assert pair["build_reason"] == "unknown" and pair["build_reason_evidence"] == []
    r = d["releases"][1]
    r.update(build_reason="security_fix", build_reason_evidence=[reason()])
    r["build_reason_evidence"][0]["evidence"][0]["source_id"] = "missing"
    with pytest.raises(ValueError, match="reason"):
        cat.validate_catalogue(d)


def test_defect_fix_requires_predecessor_and_both_requires_two_kinds():
    d, _ = configured("aruba", [("10.13.1005", None)])
    r = d["releases"][0]
    r.update(build_reason="both", build_reason_evidence=[reason(), reason("defect_fix")])
    cat.validate_catalogue(d)
    r["build_reason_evidence"][1]["predecessor"] = None
    with pytest.raises(ValueError, match="reason"):
        cat.validate_catalogue(d)


def test_resolved_pair_does_not_transfer_predecessor_to_another_model_marker():
    from test_release_reliability import selected

    d, c = configured("cisco", [("17.12.7", None), ("17.12.7a", None)])
    c["trains"][0]["platforms"] = ["9200", "9300"]
    d["releases"][0]["platforms_stated"] = ["9300"]
    d["releases"][1]["platforms_stated"] = ["9200", "9300"]
    upgrades = selected(["9200"])
    report = rr.build_report(
        unique(d),
        c,
        publication=upgrades["publication"],
        generated_at=upgrades["generated_at"],
        staircase_join_version=1,
    )
    assert rr.with_upgrades(report, upgrades)["upgrade_annotations"][0]["matches"] == []


def test_untagged_historical_catalogue_keeps_scoped_rows():
    d, c = configured("cisco", [("17.12.7", None), ("17.12.7a", None)])
    c["trains"][0]["platforms"] = ["9200", "9300"]
    for row in d["releases"]:
        row["platforms_stated"] = ["9200", "9300"]
    assert len(cat.find_respins(d, c)) == 2
    assert len(cat.find_respins(unique(d), c)) == 1


def test_defect_predecessor_must_be_a_literal_not_a_version_prefix():
    d, _ = configured("aruba", [("10.13.1005", None)])
    proof = reason("defect_fix")
    proof["evidence"][0]["quote"] = "10.13.1005 fixes an issue in 10.13.10000"
    d["releases"][0].update(build_reason="defect_fix", build_reason_evidence=[proof])
    with pytest.raises(ValueError, match="reason"):
        cat.validate_catalogue(d)


def test_reason_literal_can_end_a_sentence():
    d, _ = configured("aruba", [("10.13.1005", None)])
    proof = reason()
    proof["evidence"][0]["quote"] = "Fixed release: 10.13.1005."
    d["releases"][0].update(build_reason="security_fix", build_reason_evidence=[proof])
    cat.validate_catalogue(d)
