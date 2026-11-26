"""Coverage inventories expose gaps without inventing release denominators."""

import copy
import csv
import io

import pytest
from test_release_catalogue import config, release, specimen

from infrastructure_impact.application import release_reliability as rr
from infrastructure_impact.application import reliability_coverage as coverage


def report(catalogue=None):
    return rr.build_report(
        catalogue or specimen(),
        config(),
        publication={"id": "coverage-test", "advisory_schema_version": 2},
        generated_at="2026-11-26T01:00:00Z",
    )


def test_dates_are_scoped_per_model_and_inventory_is_not_a_denominator():
    cat = specimen()
    cat["releases"] = [
        release("17.12.7", "2025-01-01", platforms=["Catalyst 9200"]),
        release("17.12.7", None, platforms=["Catalyst 9300"]),
        release("17.12.8", None, platforms=["Catalyst 9500"]),
    ]
    value = coverage.build_coverage(report(cat))
    train = value["trains"][0]
    first, second = train["models"]
    assert first["dated_original_versions"] == ["17.12.7"]
    assert first["undated_versions"] == []
    assert second["undated_versions"] == ["17.12.7"]
    assert train["outside_cohort_versions"] == ["17.12.8"]
    assert train["unbound_versions"] == []
    assert all(p["metrics"]["releases_shipped"]["denominator"] is None for p in train["periods"])
    assert value["publication"]["id"] == "coverage-test"
    assert value["review_status"] == "independent_human_review_pending"
    assert train["release_evidence"][0]["evidence"][0]["locator"]
    assert value["sources"][0]["original_sha256"]


def test_original_dated_observation_resolves_older_research_and_undated_observations():
    cat = specimen()
    research = copy.deepcopy(cat["sources"][0])
    research.update(
        source_id="research",
        capture_kind="tool_excerpt",
        original_sha256=None,
        excerpt_sha256="b" * 64,
    )
    cat["sources"].append(research)
    old = release("17.12.7", "2025-01-01")
    old["evidence"][0]["source_id"] = "research"
    cat["releases"] = [old, release("17.12.7", None), release("17.12.7", "2025-01-01")]
    model = coverage.build_coverage(report(cat))["trains"][0]["models"][0]
    assert model["observed_versions"] == ["17.12.7"]
    assert model["dated_original_versions"] == ["17.12.7"]
    assert model["dated_research_only_versions"] == []
    assert model["undated_versions"] == []


def test_announcement_and_missing_model_are_distinct_gaps():
    cat = specimen()
    item = release("17.12.7", None)
    item.update(platforms_stated=[], announcement_date="2025-01-01")
    cat["releases"] = [item]
    value = coverage.build_coverage(report(cat))
    assert value["trains"][0]["unbound_versions"] == ["17.12.7"]
    assert all(m["observed_versions"] == [] for m in value["trains"][0]["models"])
    assert value["trains"][0]["release_evidence"][0]["release_date"] is None
    assert value["trains"][0]["release_evidence"][0]["announcement_date"] == "2025-01-01"


def test_unavailable_and_invalid_reports_do_not_become_empty_complete_coverage():
    r = rr.unavailable_report(publication=None, generated_at="2026-11-26T01:00:00Z")
    value = coverage.build_coverage(r)
    assert value["availability"] == "unavailable" and value["trains"] == []
    assert value["sources"] == []
    r = report()
    r["annual"][0]["metrics"]["releases_shipped"]["denominator"] = 100
    with pytest.raises(ValueError):
        coverage.build_coverage(r)


def test_csv_is_spreadsheet_safe_and_budgeted():
    value = coverage.build_coverage(report())
    value["limitations"].append("=SUM(A1)")
    rows = list(csv.DictReader(io.StringIO(coverage.csv_export(value))))
    assert any(row["row_type"] == "model_inventory" for row in rows)
    assert any(row["row_type"] == "period_metric" for row in rows)
    assert any(row["payload"] == "'=SUM(A1)" for row in rows)
    assert all(row["publication_id"] == "coverage-test" for row in rows)
    with pytest.raises(ValueError):
        coverage.csv_export(value, max_bytes=10)


def test_cli_exports_and_refuses_input_aliases(tmp_path):
    import json

    from infrastructure_impact.reliability_coverage_cli import main

    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()))
    output = tmp_path / "coverage.json"
    assert main(["--input", str(source), "--output", str(output)]) == 0
    assert json.loads(output.read_text()) == coverage.build_coverage(report())
    csv_path = tmp_path / "coverage.csv"
    assert main(["--input", str(source), "--output", str(csv_path), "--format", "csv"]) == 0
    assert csv_path.read_bytes().decode() == coverage.csv_export(coverage.build_coverage(report()))
    before = source.read_bytes()
    for target in (source, tmp_path / "alias.json"):
        if target != source:
            target.hardlink_to(source)
        with pytest.raises(SystemExit):
            main(["--input", str(source), "--output", str(target)])
    assert source.read_bytes() == before


def test_coverage_exports_retain_statement_judgement_and_respin_evidence():
    from test_release_reliability import action, complete_coverage

    cat = specimen()
    cat["releases"] = [release("17.12.7", "2024-12-25"), release("17.12.7a", "2025-01-10")]
    cat["statements"] = [action()]
    cat["coverage"] = [complete_coverage()]
    accepted = report(cat)
    value = coverage.build_coverage(accepted)
    train = value["trains"][0]
    assert train["statement_evidence"] == cat["statements"]
    assert train["statement_evidence"][0]["evidence"][0]["locator"]
    assert train["coverage_judgements"] == cat["coverage"]
    assert train["coverage_judgements"][0]["source_ids"] == ["s1"]
    assert train["respin_evidence"] == accepted["respins"]
    assert value["config"] == accepted["config"] and value["method"] == accepted["method"]
    rows = list(csv.DictReader(io.StringIO(coverage.csv_export(value))))
    assert {"statement_evidence", "coverage_judgement", "respin_evidence"} <= {
        r["row_type"] for r in rows
    }
    train["statement_evidence"][0]["evidence"][0]["locator"] = "edited"
    assert cat["statements"][0]["evidence"][0]["locator"] != "edited"
