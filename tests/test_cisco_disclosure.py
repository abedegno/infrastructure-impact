"""Authored bounded source fixture; table order intentionally differs from CVE order."""

import copy
import json
from pathlib import Path

import pytest

from infrastructure_impact.adapters import cisco_disclosure as disclosure
from infrastructure_impact.adapters.standards import csaf
from infrastructure_impact.domain import NormalizationError, validate_advisory

FIXTURE = Path(__file__).parent / "fixtures/cisco-disclosure-hardening.json"


def source():
    return json.loads(FIXTURE.read_text())


def test_owned_seven_classes_and_worst_bug_wording():
    data = source()
    result = disclosure.extract_cisco_disclosure(data)
    meta = result["disclosure_metadata"]
    assert not result["issues"]
    assert {v["cve_id"]: v["cwe_id"] for v in meta["umbrella_cves"]} == {
        "CVE-2026-20267": "CWE-284",
        "CVE-2026-20268": "CWE-119",
        "CVE-2026-20269": "CWE-664",
        "CVE-2026-20270": "CWE-682",
        "CVE-2026-20271": "CWE-691",
        "CVE-2026-20272": "CWE-74",
        "CVE-2026-20273": "CWE-20",
    }
    assert meta["highest_cvss_wording"] == data["document"]["notes"][1]["text"].split("\r\n")[0]
    assert meta["bug_count"] is None
    assert meta["bug_count_status"] == "not_disclosed"
    assert meta["bundle"]["advisory_ids"] == [data["document"]["tracking"]["id"]]
    assert len(meta["bundle"]["cve_ids"]) == 7
    assert meta["method"]["basis"] == "date_and_type_rule"


@pytest.mark.parametrize(
    "control", ["mere_cwe", "title", "multiple", "changed_mapping", "mixed_scope"]
)
def test_negative_controls_cannot_claim_umbrella(control):
    data = source()
    if control == "mere_cwe":
        data["document"]["notes"][0]["text"] = "CWE-284 affects this product."
    elif control == "title":
        data["document"]["notes"] = []
    elif control == "multiple":
        data["document"]["notes"][0]["text"] = "Multiple CVEs were fixed."
    elif control == "changed_mapping":
        data["document"]["notes"][1]["text"] = data["document"]["notes"][1]["text"].replace(
            "CWE-119", "CWE-284"
        )
    else:
        data["document"]["notes"][1]["text"] = data["document"]["notes"][1]["text"].replace(
            "CVE-2026-20268", "CVE-2026-99999"
        )
    assert disclosure.extract_cisco_disclosure(data)["disclosure_metadata"]["umbrella_cves"] == []


def test_metadata_normalization_closed_schema_and_owner_binding():
    record = csaf(FIXTURE.read_text(), "https://sec.cloudapps.cisco.com/example.json", "cisco")
    validate_advisory(record)
    assert record["disclosure_metadata"]["bundle"]["cve_ids"] == sorted(record["cves"])
    broken = copy.deepcopy(record)
    broken["disclosure_metadata"]["umbrella_cves"][0]["cve_id"] = "CVE-2026-99999"
    with pytest.raises(NormalizationError):
        validate_advisory(broken)
    broken = copy.deepcopy(record)
    broken["disclosure_metadata"]["bug_count"] = 7
    with pytest.raises(NormalizationError):
        validate_advisory(broken)


def test_method_boundary_unknown_and_explicit_third_party():
    data = source()
    data["document"]["notes"] = []
    data["document"]["title"] = "Ordinary advisory"
    data["document"]["tracking"]["initial_release_date"] = "2026-06-30"
    assert (
        disclosure.extract_cisco_disclosure(data)["disclosure_metadata"]["method"]["classification"]
        == "pre_risk_based"
    )
    data["document"]["tracking"]["initial_release_date"] = "2026-07-01"
    assert (
        disclosure.extract_cisco_disclosure(data)["disclosure_metadata"]["method"]["classification"]
        is None
    )
    data["document"]["notes"] = [
        {
            "title": "Summary",
            "category": "summary",
            "text": "These vulnerabilities are in third-party open-source software.",
        }
    ]
    assert (
        disclosure.extract_cisco_disclosure(data)["disclosure_metadata"]["method"]["basis"]
        == "third_party_exception"
    )
    data["document"]["tracking"]["initial_release_date"] = None
    data["document"]["notes"] = []
    assert (
        disclosure.extract_cisco_disclosure(data)["disclosure_metadata"]["method"]["basis"]
        == "unknown"
    )


def test_actual_case_checker_checks_values_and_never_accepts_human_review():
    from infrastructure_impact.application.cisco_disclosure_replay import validate_cases

    record = csaf(FIXTURE.read_text(), "https://sec.cloudapps.cisco.com/example.json", "cisco")
    record["sha256"] = "0f51863687793ec84cfa51289e3028b712ec0695061eafa576e6ea5f62fe8149"
    assert validate_cases([record])[0] == dict(
        advisory_id=record["advisory_id"], automated_validation="passed", human_review="pending"
    )
    record["disclosure_metadata"]["umbrella_cves"][0]["cwe_id"] = "CWE-999"
    assert validate_cases([record])[0]["automated_validation"] == "failed"
    record["sha256"] = "b" * 64
    assert validate_cases([record])[0]["automated_validation"] == "different_capture"
    assert validate_cases([])[0]["automated_validation"] == "not_replayed"


def test_disclosure_metadata_survives_storage_and_public_projection():
    from infrastructure_impact.application.publication import public_projection
    from infrastructure_impact.application.query import state
    from infrastructure_impact.storage.repository import connect, ingest, latest

    with connect(":memory:") as db:
        ingest(
            db, FIXTURE.read_bytes(), "https://sec.cloudapps.cisco.com/example.json", csaf, "cisco"
        )
        stored = latest(db)[0]
        data = state(db, stored["cves"])
        projected = public_projection(data, publication_format="v2")
    assert projected["records"][0]["disclosure_metadata"] == stored["disclosure_metadata"]


def test_method_and_precision_must_match_owned_initial_date():
    record = csaf(FIXTURE.read_text(), "https://sec.cloudapps.cisco.com/example.json", "cisco")
    record["disclosure_metadata"]["method"]["classification"] = "pre_risk_based"
    with pytest.raises(NormalizationError, match="method"):
        validate_advisory(record)
    record = csaf(FIXTURE.read_text(), "https://sec.cloudapps.cisco.com/example.json", "cisco")
    record["disclosure_metadata"]["date_precision"] = "day"
    with pytest.raises(NormalizationError, match="precision"):
        validate_advisory(record)
