"""Typed facts cannot become passes when their exact source is unavailable."""

import json
from importlib.resources import files

import pytest

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


@pytest.mark.parametrize("field", ["disclosure_metadata", "first_fixed"])
def test_dropped_cisco_fact_with_exact_record_stays_in_denominator(field):
    expected = json.loads(
        files("infrastructure_impact")
        .joinpath("resources/cisco-disclosure-validation.json")
        .read_text()
    )["cases"][0]
    record = dict(
        vendor="cisco",
        advisory_id=expected["advisory_id"],
        sha256=expected["sha256"],
        source_url="https://sec.cloudapps.cisco.com/example.json",
        source_observed_at="2026-11-13T00:00:00Z",
    )
    record[field] = None if field == "disclosure_metadata" else []
    result = report([record])
    assert [c["outcome"] for c in result["cases"][:2]] == ["fail", "fail"]
    assert result["vendor_results"][0]["evaluated"] == 2
    assert result["vendor_results"][0]["failed"] == 2


@pytest.fixture
def sa137(monkeypatch):
    from copy import deepcopy

    from test_switching_kev_reconciliation import inputs

    from infrastructure_impact.adapters import arista_sa0137
    from infrastructure_impact.application import switching_analysis

    feed, _, _, _ = inputs()
    record = dict(
        vendor="arista",
        advisory_id=arista_sa0137.ID,
        source_url=arista_sa0137.URL,
        sha256="21540eabc1c78ff4d0a6122ff5b03e103017b4e9ef38551712936f26f64d5c7d",
        source_observed_at="2026-11-13T00:00:00Z",
    )
    claims = [
        dict(
            vendor="arista",
            advisory_id=arista_sa0137.ID,
            source=dict(source_url=record["source_url"], source_sha256=record["sha256"]),
            status="affected",
            scope="cve_specific",
            scope_level="os_family",
            cve_id=cid,
        )
        for cid in arista_sa0137.CVES
    ]
    # Isolate this helper's denominator logic; real KEV DTO validation is retained.
    monkeypatch.setattr(switching_analysis, "validate_report", lambda value: None)
    monkeypatch.setattr(switching_analysis, "claim_facets", lambda value: claims)
    entry = dict(
        mapping=dict(vendor="arista"),
        cve_id=arista_sa0137.CVES[0],
        historically_listed=True,
        membership="unknown",
        claim_state="documented_affected",
    )
    compiled = dict(
        kev_reconciliation=dict(
            availability="missing",
            entries=[entry],
            catalogue=deepcopy(feed["catalogue"]),
            source=deepcopy(feed["source"]),
        )
    )
    return record, claims, compiled, feed


def test_sa137_historical_membership_does_not_invent_current_health(sa137):
    record, claims, compiled, feed = sa137
    feed["source"].update(checked_at=None, latest_attempt=None, availability="missing")
    feed["selection"]["membership"] = {cid: "unknown" for cid in feed["listed_cve_ids"]}
    case = report([record], compiled=compiled, retained_kev=feed)["cases"][3]
    assert case["outcome"] == "pass"
    assert case["observed"] == dict(
        historically_listed=True,
        current_membership="unknown",
        current_availability="missing",
        claim_state="documented_affected",
    )
    entry = compiled["kev_reconciliation"]["entries"][0]
    entry["historically_listed"] = False
    assert report([record], compiled=compiled, retained_kev=feed)["cases"][3]["outcome"] == "fail"
    entry["historically_listed"] = True
    entry["claim_state"] = "unknown"
    assert report([record], compiled=compiled, retained_kev=feed)["cases"][3]["outcome"] == "fail"


@pytest.mark.parametrize("drop", ["claims", "entries"])
def test_sa137_missing_derived_output_fails_with_independent_prerequisites(sa137, drop):
    record, claims, compiled, feed = sa137
    if drop == "claims":
        claims.clear()
    else:
        compiled["kev_reconciliation"]["entries"].clear()
    result = report([record], compiled=compiled, retained_kev=feed)
    assert result["cases"][2 if drop == "claims" else 3]["outcome"] == "fail"
    assert result["vendor_results"][-1]["evaluated"] == 2


@pytest.mark.parametrize(
    "missing",
    [
        "record",
        "changed_record",
        "duplicate_record",
        "compiled",
        "feed",
        "changed_feed",
        "partial_feed",
    ],
)
def test_sa137_absent_or_unusable_prerequisites_stay_unavailable(sa137, missing):
    record, claims, compiled, feed = sa137
    records = [record]
    if missing == "record":
        records = []
    elif missing == "changed_record":
        record["sha256"] = "0" * 64
    elif missing == "duplicate_record":
        records.append(record.copy())
    elif missing == "compiled":
        compiled = None
    elif missing == "feed":
        feed = None
    elif missing == "changed_feed":
        feed["catalogue"]["sha256"] = "b" * 64
    else:
        feed["entries"] = {}
    result = report(records, compiled=compiled, retained_kev=feed)
    assert result["cases"][3]["outcome"] == "unavailable"
    if missing in {"record", "changed_record", "duplicate_record", "compiled"}:
        assert result["cases"][2]["outcome"] == "unavailable"


@pytest.mark.parametrize("field", ["version", "source_observed_at", "parsed_at", "revision_id"])
def test_kev_receipt_identity_includes_capture_and_version(sa137, field):
    record, _, compiled, feed = sa137
    feed["catalogue"][field] = "2026-11-12T12:00:00Z" if field.endswith("_at") else "different"
    assert (
        report([record], compiled=compiled, retained_kev=feed)["cases"][3]["outcome"]
        == "unavailable"
    )


def test_adequate_partial_feed_independently_proves_expected_output(sa137):
    record, _, compiled, feed = sa137
    # Complete retained index, partial detail set including the pinned CVE.
    feed["listed_cve_ids"].append("CVE-2026-99999")
    feed["catalogue"]["count"] = 2
    compiled["kev_reconciliation"]["catalogue"]["count"] = 2
    assert report([record], compiled=compiled, retained_kev=feed)["cases"][3]["outcome"] == "pass"
    compiled["kev_reconciliation"]["entries"].clear()
    result = report([record], compiled=compiled, retained_kev=feed)
    assert result["cases"][3]["outcome"] == "fail"
    assert result["vendor_results"][-1]["evaluated"] == 2


def test_missing_retained_catalogue_remains_unavailable(sa137):
    from infrastructure_impact.application import kev

    record, _, compiled, _ = sa137
    feed = kev.build_report({}, [], publication=None, generated_at="2026-11-13T12:00:00Z")
    assert (
        report([record], compiled=compiled, retained_kev=feed)["cases"][3]["outcome"]
        == "unavailable"
    )


def test_cli_records_independent_kev_input_receipt(tmp_path, monkeypatch, sa137):
    from hashlib import sha256

    from infrastructure_impact.application.switching_source_validation import main

    _, _, _, feed = sa137
    records = tmp_path / "records.json"
    records.write_text(json.dumps(dict(records=[])))
    source = tmp_path / "kev.json"
    source.write_text(json.dumps(feed))
    output = tmp_path / "result.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "source-validation",
            "--records-input",
            str(records),
            "--kev-input",
            str(source),
            "--output",
            str(output),
        ],
    )
    main()
    result = json.loads(output.read_text())
    assert (
        dict(path=str(source), sha256=sha256(source.read_bytes()).hexdigest())
        in result["input_receipts"]
    )
    assert result["cases"][3]["outcome"] == "unavailable"  # No SA137 record or compiled input.
