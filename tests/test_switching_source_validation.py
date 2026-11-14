"""Typed facts cannot become passes when their exact source is unavailable."""

import json
from importlib.resources import files

from infrastructure_impact.application.switching_source_validation import report


def test_missing_facts_are_unavailable_and_human_review_pending():
    result = report([])
    assert len(result["cases"]) == 7
    assert all(c["outcome"] == "unavailable" for c in result["cases"])
    assert all(v["evaluated"] == 0 for v in result["vendor_results"])
    assert result["independent_human_review_completed"] is False
    assert result["vendor_results"][1]["coverage"] == "no_pinned_source_cases"


def test_pinned_typed_dates_reject_disagreement_and_changed_receipt():
    expected = json.loads(
        files("infrastructure_impact")
        .joinpath("resources/arista-chronology-validation.json")
        .read_text()
    )
    rows = [
        dict(
            number=c["number"],
            source_hashes=c["source_hashes"],
            status="corrected",
            effective_initial=c["html_initial"],
            csaf_initial=c["csaf_initial"],
            rss_publication=c["rss_publication"],
            claim_initials=[c["html_initial"]],
            claim_scope_and_fixes_unchanged=True,
            finalized_claim_initials=[c["html_initial"]],
        )
        for c in expected["cases"]
    ]
    assert [c["outcome"] for c in report([], chronology_rows=rows)["cases"][-3:]] == ["pass"] * 3
    rows[0]["effective_initial"] = "2000-01-01"
    rows[1]["source_hashes"] = {}
    result = report([], chronology_rows=rows)
    assert [c["outcome"] for c in result["cases"][-3:]] == ["fail", "unavailable", "pass"]
    assert result["vendor_results"][-1]["evaluated"] == 2


def test_hardening_checks_use_metadata_and_stated_rows_not_claim_counts():
    expected = json.loads(
        files("infrastructure_impact")
        .joinpath("resources/cisco-disclosure-validation.json")
        .read_text()
    )["cases"][0]
    metadata = dict(
        initial_published_at=expected["initial_published_at"],
        umbrella_cves=[dict(cve_id=c, cwe_id=w) for c, w in expected["cwe_by_cve"].items()],
        highest_cvss_wording=expected["highest_cvss_wording"],
        bug_count=None,
        bug_count_status="not_disclosed",
    )
    fixed = [
        dict(method="stated_table", fixed_versions=[v], disposition="fixed", train_expression=v)
        for v in ["17.9.10", "17.12.8", "17.15.6", "17.18.4", "17.18.4a", "26.1.2"]
    ]
    fixed.append(
        dict(
            method="stated_table",
            fixed_versions=[],
            disposition="migrate",
            train_expression="17.8 and earlier",
        )
    )
    record = dict(
        vendor="cisco",
        advisory_id=expected["advisory_id"],
        sha256=expected["sha256"],
        source_url="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
        + expected["advisory_id"],
        source_observed_at="2026-11-13T00:00:00Z",
        disclosure_metadata=metadata,
        first_fixed=fixed,
    )
    assert [c["outcome"] for c in report([record])["cases"][:2]] == ["pass", "pass"]
    metadata["bug_count"] = 7
    assert report([record])["cases"][0]["outcome"] == "fail"
    record["sha256"] = "0" * 64
    assert [c["outcome"] for c in report([record])["cases"][:2]] == ["unavailable", "unavailable"]
