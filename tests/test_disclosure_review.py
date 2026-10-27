"""A review task is never a verified disclosure or concealment finding."""

from copy import deepcopy

from infrastructure_impact.application.disclosure_review import disclosure_review
from infrastructure_impact.application.research_reports import validator

URL = "https://docs.fortinet.com/document/fortiproxy/7.2.8/release-notes/4/change-log"
CID = "CVE-2023-38545"


def inputs():
    evidence = dict(
        source_url=URL,
        source_sha256="a" * 64,
        observed_at="2026-10-27T00:00:00Z",
        publisher_date_claim=None,
    )
    lead = dict(
        id="synthetic",
        vendor="fortinet",
        product="FortiProxy 7.2.8",
        kind="publisher_reported_chronology",
        cve_ids=[CID],
        evidence=[evidence],
        alternative_explanations=["Earlier advisory may exist."],
    )
    case = dict(
        id="counter",
        vendor="fortinet",
        selected_cve_ids=[CID],
        advisory_urls=[],
        release_source_leads=[URL],
        earlier_dated_vendor_documents=[
            dict(
                source_url="https://www.fortiguard.com/psirt/test",
                source_sha256="b" * 64,
                publisher_published_at="2023-10-01",
                cve_ids=[CID],
                PRIVATE_SENTINEL="private",
            )
        ],
    )
    return dict(fix_leads={"leads": [lead], "leads_truncated": False}, casefiles={"cases": [case]})


def test_matching_counter_evidence_is_prioritized_and_all_review_gates_stay_pending():
    report = disclosure_review(inputs())
    validator("disclosure_review").validate(report)
    row = report["cases"][0]
    assert row["next_action"] == "review_counter_evidence"
    assert (
        row["related_case_ids"] == ["counter"]
        and len(row["earlier_document_counter_evidence"]) == 1
    )
    assert "PRIVATE_SENTINEL" not in str(report)
    assert len(row["checklist"]) == 5 and all(
        c["state"] == "not_established" for c in row["checklist"]
    )
    assert (
        row["concealment"] == "not_established"
        and report["independent_human_review_completed"] is False
    )


def test_vendor_source_and_cve_must_all_match_for_counter_evidence():
    for key, value in [
        ("vendor", "cisco"),
        ("selected_cve_ids", ["CVE-2024-6387"]),
        ("release_source_leads", ["https://www.fortinet.com/other"]),
    ]:
        d = inputs()
        d["casefiles"]["cases"][0][key] = value
        row = disclosure_review(d)["cases"][0]
        assert row["earlier_document_counter_evidence"] == [] and row["related_case_ids"] == []


def test_component_change_does_not_create_cve_linkage_or_prior_exposure():
    d = inputs()
    lead = d["fix_leads"]["leads"][0]
    lead.update(kind="component_version_changed", cve_ids=[])
    before = deepcopy(d)
    report = disclosure_review(d)
    assert d == before
    row = report["cases"][0]
    assert row["cve_ids"] == [] and row["next_action"] == "verify_change_and_scope"
    assert row["earlier_document_counter_evidence"] == []
    assert disclosure_review({})["cases"] == []


def test_related_multicve_case_cannot_supply_counter_evidence_for_a_different_cve():
    d = inputs()
    d["casefiles"]["cases"][0]["earlier_dated_vendor_documents"][0]["cve_ids"] = ["CVE-2023-38546"]
    row = disclosure_review(d)["cases"][0]
    assert row["related_case_ids"] == ["counter"]
    assert row["earlier_document_counter_evidence"] == []
