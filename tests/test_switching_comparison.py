"""Synthetic parity cases exercise descriptive semantics, never real applicability."""

import copy
import json
from pathlib import Path

import pytest

from infrastructure_impact.application import kev
from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as evidence

AT = "2026-11-04T10:00:00Z"
FIXTURE = json.loads((Path(__file__).parent / "fixtures/switching-cases.json").read_text())


def claim(identity="A", cid="CVE-2025-12345", date="2025-01-01", **changes):
    c = copy.deepcopy(FIXTURE["evidence"]["claims"][0])
    c.update(advisory_id=identity, cve_id=cid, initial_published_at=date, scores=[], bundle=None)
    c["publisher"]["id"] = identity
    c["remediations"][0]["availability"] = "vendor_reports_fixed"
    c.update(changes)
    return c


def report(claims, coverage=None):
    data = evidence.project(
        dict(claims=claims, coverage=coverage or [], issues=[]), publication=None, generated_at=AT
    )
    k = kev.build_report({}, [], publication=None, generated_at=AT)
    return comparison.build_report(
        data,
        k,
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-04",
    )


def row(r, **select):
    return comparison.select_report(r, vendor="arista", evaluated_at=AT, **select)["rows"][0]


@pytest.mark.parametrize(
    "date,window",
    [
        ("2026-04-06", "pre"),
        ("2026-04-07", "post"),
        ("2026-04-07T00:30:00+02:00", "pre"),
        (None, "undated"),
    ],
)
def test_dates_and_updates(date, window):
    r = report([claim(date=date)])
    assert row(r, window=window)["counts"]["advisories"] == 1
    assert row(r, window="2026")["counts"]["advisories"] == (0 if date is None else 1)
    assert row(report([claim()]), window="post")["counts"]["advisories"] == 0


def test_distinct_sets_selection_and_empty_scope():
    r = report([claim("A", date="2024-01-01"), claim("B", date="2025-01-01")])
    assert row(r)["counts"]["affected_cves"] == 1
    assert row(r, window="2024")["counts"]["affected_cves"] == 1
    assert row(r, window="2025")["counts"]["affected_cves"] == 1
    assert comparison.select_report(r, cve_ids=[])["selection"]["effective_cve_ids"] == []
    assert comparison.select_report(r)["selection"]["effective_cve_ids"] == ["CVE-2025-12345"]
    assert comparison.select_report(r, window="post")["selection"]["requested_window"] == "post"
    assert row(r, cve_ids=[])["counts"]["affected_cves"] == 0
    selected = comparison.select_report(r, scope_level="model_qualified")
    assert selected["inputs"] == r["inputs"]
    assert selected["publication"] == r["publication"]


def test_bundle_members_and_unbundled_same_day_are_not_interchangeable():
    a, b = claim("A"), claim("B")
    bundle = copy.deepcopy(FIXTURE["evidence"]["claims"][0]["bundle"])
    bundle.update(member_advisory_ids=["A", "B"], published_at="2026-04-07")
    a["bundle"] = copy.deepcopy(bundle)
    b["bundle"] = copy.deepcopy(bundle)
    r = report([a, b])
    assert row(r)["counts"]["remediation_events"] == 1
    assert row(r, window="2025")["counts"]["remediation_events"] == 0
    assert row(r, window="post")["counts"]["remediation_events"] == 1
    assert row(r, window="post")["counts"]["advisories"] == 0
    assert row(report([claim("A"), claim("B")]))["counts"]["unbundled_publications"] == 2


def test_explicit_affected_branches_conditions_and_fix_scope():
    affected = claim("A", conditions=["Only with RADIUS configured"], conditional_affected=True)
    r = report(
        [
            affected,
            claim("A", status="conflicting"),
            claim("B", scope="bulletin_shared"),
            claim("C", status="investigating"),
            claim("D", status="fixed"),
        ]
    )
    result = row(r)
    assert result["counts"]["affected_cves"] == 1
    assert result["counts"]["conditional_cves"] == 1
    assert result["counts"]["remediation_events"] == 1
    assert result["counts"]["fixed_only_claims"] == 1
    unresolved = claim(platform_bindings=[], named_platforms=[], scope_level="os_family")
    assert row(report([unresolved]), scope_level="model_qualified")["counts"]["affected_cves"] == 0
    assert row(report([unresolved]))["counts"]["model_unresolved_claims"] == 1
    unresolved["remediations"][0]["product_ids"] = []
    assert row(report([unresolved]))["counts"]["remediation_events"] == 0


def test_drafts_coverage_unknown_and_unavailable_are_distinct():
    draft = claim("draft")
    draft["publisher"]["status"] = "draft"
    result = row(report([draft]))
    assert result["counts"]["draft_advisories"] == 1
    assert result["counts"]["affected_cves"] == 0
    assert result["coverage"]["expected_advisories"] is None
    assert result["coverage"]["state"] == "unknown"
    old = comparison.select_report(
        None,
        publication={"id": "a" * 32, "advisory_schema_version": 2},
        generated_at=AT,
        evaluated_at=AT,
    )
    assert (
        old["availability"] == "unavailable"
        and old["rows"] == []
        and old["publication"]["id"] == "a" * 32
    )


@pytest.mark.parametrize(
    "version,value,expected",
    [
        ("2.0", 0, "Low"),
        ("2.0", 9.8, "High"),
        ("3.1", 0, "None"),
        ("3.1", 3.9, "Low"),
        ("4.0", 4, "Medium"),
        ("3.1", 7, "High"),
        ("4.0", 9, "Critical"),
        ("3.1", None, "Unknown"),
    ],
)
def test_version_specific_bands(version, value, expected):
    assert comparison.severity_band(version, value) == expected


def test_score_provider_conflicts_and_unknown_are_preserved():
    c = claim()
    base = copy.deepcopy(FIXTURE["evidence"]["claims"][0]["scores"][0])
    c["scores"] = [
        dict(base, value=0, provider="vendor", preferred=True),
        dict(base, value=9.8, provider="other", preferred=False),
    ]
    r = row(report([c, claim("B", cid="CVE-2026-98765")]))
    assert {(f["provider"], f["band"]) for f in r["severity"]} == {
        ("vendor", "None"),
        ("other", "Critical"),
        (None, "Unknown"),
    }
    assert r["counts"]["affected_cves"] == 2
    assert r["kev"]["unknown_count"] == 2


@pytest.mark.parametrize(
    "options",
    [
        {"vendor": "juniper"},
        {"scope_level": "all"},
        {"window": "2020"},
        {"window": "2027"},
        {"window": "nonsense"},
        {"cve_ids": ["bad"]},
    ],
)
def test_invalid_selectors_rejected(options):
    with pytest.raises(ValueError):
        comparison.select_report(report([]), **options)


def test_strict_rows_and_generation_are_validated():
    r = report([claim()])
    evidence.validate_comparison(r)
    bad = copy.deepcopy(r)
    bad["rows"][0]["private"] = "no"
    with pytest.raises(Exception):
        evidence.validate_comparison(bad)
    bad = copy.deepcopy(r)
    bad["rows"][0]["counts"]["affected_cves"] = 999
    with pytest.raises(ValueError):
        evidence.validate_comparison(bad)


def test_kevs_complete_index_outside_old_cohort_is_rechecked_at_selection():
    k = json.loads((Path(__file__).parent / "fixtures/kev-selection-cases.json").read_text())[
        "base_report"
    ]
    k.update(publication=None, generated_at=AT, evaluated_at=AT)
    k["source"]["checked_at"] = AT
    k["source"]["latest_attempt"]["checked_at"] = AT
    r = report([claim(cid="CVE-2099-99999")])
    r = comparison.build_report(
        r["inputs"]["evidence"],
        k,
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-04",
    )
    assert row(r)["kev"]["listed_count"] == 1
    stale = comparison.select_report(r, vendor="arista", evaluated_at="2026-11-07T10:00:00Z")
    assert stale["rows"][0]["kev"]["listed_count"] == 0
    assert stale["rows"][0]["kev"]["unknown_count"] == 1
    assert stale["inputs"] == r["inputs"]


def test_conditionality_unknown_is_not_false_or_any_context():
    for c in [
        claim(conditions=["General vulnerability description"]),
        claim(conditional_affected=None),
        claim(conditional_affected=False),
    ]:
        result = row(report([c]))
        assert result["counts"]["conditional_cves"] == 0
        assert result["counts"]["conditionality_unclassified_cves"] == int(
            c.get("conditional_affected") is None
        )
    assert row(report([claim(conditional_affected=True)]))["counts"]["conditional_cves"] == 1


def test_planned_workaround_fixed_only_and_same_row_available_are_separate():
    c = claim()
    c["product_id"] = None
    c["remediations"][0]["product_ids"] = []
    c["remediations"][0]["scope_binding"] = dict(
        basis="same_source_row", cve_id=c["cve_id"], source=copy.deepcopy(c["source"])
    )
    assert row(report([c]))["counts"]["remediation_events"] == 1
    c["remediations"][0]["availability"] = "planned"
    result = row(report([c]))
    assert (
        result["counts"]["remediation_events"] == 0 and result["counts"]["planned_fix_claims"] == 1
    )
    c["remediations"][0]["category"] = "workaround"
    assert row(report([c]))["counts"]["workaround_claims"] == 1
    c["status"] = "fixed"
    c["remediations"][0]["availability"] = "vendor_reports_fixed"
    assert row(report([c]))["counts"]["remediation_events"] == 0


def test_period_boundaries_missing_bundle_date_and_duplicate_revisions():
    old = claim(date="2020-12-16")
    assert row(report([old]))["counts"]["advisories"] == 0
    a = claim()
    b = copy.deepcopy(a)
    b["revision"] = "2"
    assert row(report([a, b]))["counts"]["remediation_events"] == 1
    assert row(report([a, b]))["counts"]["advisories"] == 1
    a["bundle"] = copy.deepcopy(FIXTURE["evidence"]["claims"][0]["bundle"])
    a["bundle"]["member_advisory_ids"] = ["A"]
    assert row(report([a]), window="undated")["counts"]["remediation_events"] == 1
    assert row(report([a]), window="2025")["counts"]["remediation_events"] == 0


def test_source_window_enumeration_is_not_copied_into_year_denominators():
    coverage = copy.deepcopy(FIXTURE["evidence"]["coverage"])
    enumeration = dict(
        definition_sha256=evidence.definition_sha256(evidence.definition()),
        source_kind="listing",
        window=dict(start_date="2021-01-01", end_date="2026-11-04"),
        coverage_state="blocked",
        portfolio_completeness="not_established",
        gaps=["authentication_unavailable"],
    )
    for key in [
        "expected_total",
        "discovered_unique_identities",
        "duplicate_entries",
        "withdrawn_entries",
        "retrieved",
        "parsed",
        "parse_failed",
        "retrieval_failed",
        "classified",
        "classification_pending",
        "unknown_dates",
        "unknown_models",
        "exhausted_errors",
    ]:
        enumeration[key] = None
    enumeration.update(unknown_dates=5, retrieved=10, parse_failed=2)
    coverage[0]["enumeration"] = enumeration
    r = report([claim()], coverage)
    selected = row(r, window="2025")
    assert selected["coverage"]["sources"][0]["enumeration"] == enumeration
    assert selected["coverage"]["expected_advisories"] is None
    assert selected["denominators"]["expected_advisories"] is None


@pytest.mark.parametrize("case", FIXTURE["comparison_cases"], ids=lambda c: c["name"])
def test_shared_python_javascript_selection_contract(case):
    base = FIXTURE["comparison_base_report"]
    before = copy.deepcopy(base)
    selected = comparison.select_report(base, **case["options"])
    assert {k: v for k, v in selected.items() if k not in ("inputs", "definition")} == case[
        "expected"
    ]
    assert base == before and selected["inputs"] == base["inputs"]


def test_shared_fixture_has_independently_pinned_boundary_results():
    base = FIXTURE["comparison_base_report"]
    assert row(base)["counts"]["affected_cves"] == 5
    assert row(base)["counts"]["remediation_events"] == 6
    assert row(base, window="post")["counts"]["remediation_events"] == 3
    assert row(base, window="pre")["counts"]["remediation_events"] == 2
    assert row(base, window="undated")["counts"]["remediation_events"] == 1
    assert row(base, scope_level="model_qualified")["counts"]["affected_cves"] == 4
    assert row(base)["counts"]["draft_advisories"] == 1
    assert comparison.select_report(base, cve_ids=[])["selection"]["effective_cve_ids"] == []
    for case in FIXTURE["severity_band_cases"]:
        assert comparison.severity_band(case["version"], case["value"]) == case["band"]
