"""Elapsed collection time cannot promote a publisher's planned remediation."""

import json
from datetime import datetime

import pytest

from infrastructure_impact.adapters import common
from infrastructure_impact.adapters.standards import csaf


@pytest.mark.parametrize(
    "details,date,as_of,expected",
    [
        ("Fixed in 2.0", None, None, "vendor_reports_fixed"),
        ("Upgrade to 2.0", "2024-10-15", "2024-06-01", "planned"),
        ("Upgrade to 2.0", "2024-10-15", "2024-10-15", "vendor_reports_fixed"),
        ("Upgrade to 2.0", "2024-10-15", "2024-11-01", "vendor_reports_fixed"),
        ("Upgrade to 2.0", "2024-10-15", None, "unknown"),
        ("Upgrade to 2.0", "invalid", "2024-11-01", "unknown"),
        ("Upgrade to 2.0", "2024-10-15", "invalid", "unknown"),
        ("Upgrade to 2.0", "2024-10-15", "20241101", "unknown"),
        ("2.0 (October 2024)", None, "2024-06-01", "planned"),
        ("2.0 (october 2024)", None, "2024-06-01", "planned"),
        ("2.0 (Oct 2024)", None, "2024-10-31", "unknown"),
        ("2.0 (Oct 2024)", None, "2024-11-01", "vendor_reports_fixed"),
        ("2.0 (Oct 2024)", None, None, "unknown"),
        ("1.0 (May 2023); 2.0 (Oct 2024)", None, "2024-06-01", "planned"),
        ("2.0 (Oct 2024)", "2024-12-01", "2024-11-01", "planned"),
        ("2.0 (Oct 2024)", "2024-09-01", "2024-10-01", "unknown"),
        ("Will be fixed in 2.0", "2024-10-15", "2026-01-01", "planned"),
        ("A fix will be included in 2.0", "2024-10-15", "2026-01-01", "planned"),
        ("2.0 (ETA: Oct 2024)", None, "2026-01-01", "planned"),
        ("2.0 scheduled for Oct 2024", None, "2026-01-01", "planned"),
        ("A partial fix is scheduled", "2099-01-01", None, "partial_mitigation"),
        ("Upgrade to 2.0", "2024-10-15T16:00:00Z", "2024-10-14T23:00:00-07:00", "planned"),
    ],
)
def test_classification_is_stable_before_and_after_the_target(
    monkeypatch, details, date, as_of, expected
):
    for year in (2023, 2026, 2099):

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(year, 1, 1, tzinfo=tz)

        monkeypatch.setattr(common, "datetime", Clock)
        assert common.availability(details, "vendor_fix", date, as_of=as_of) == expected


@pytest.mark.parametrize(
    "category,expected",
    [
        ("no_fix_planned", "no_fix_planned"),
        ("none_available", "unavailable"),
        ("workaround", "not_a_fix"),
    ],
)
def test_non_fix_categories_do_not_acquire_availability_from_dates(category, expected):
    assert common.availability("Oct 2024", category, "2024-10-01") == expected


def document(updated):
    tracking = {"id": "SYNTHETIC-1", "status": "final", "initial_release_date": "2024-06-01"}
    if updated is not None:
        tracking["current_release_date"] = updated
    return {
        "document": {"title": "Synthetic", "tracking": tracking},
        "product_tree": {"full_product_names": [{"product_id": "r", "name": "Router"}]},
        "vulnerabilities": [
            {
                "cve": "CVE-2099-12345",
                "product_status": {"known_affected": ["r"]},
                "remediations": [
                    {"category": "vendor_fix", "details": "Upgrade to 2.0", "date": "2024-10-01"}
                ],
            }
        ],
    }


@pytest.mark.parametrize(
    "updated,expected",
    [
        (None, "planned"),
        ("2024-07-01", "planned"),
        ("2024-11-01", "vendor_reports_fixed"),
        ("invalid", "unknown"),
    ],
)
def test_csaf_uses_current_publisher_date_then_initial_date(updated, expected):
    record = csaf(json.dumps(document(updated)), "https://example.invalid/test.json", "aruba")
    assert record["assessments"][0]["remediations"][0]["availability"] == expected


def test_csaf_without_publisher_dates_does_not_assume_a_dated_fix_was_released():
    value = document(None)
    del value["document"]["tracking"]["initial_release_date"]
    record = csaf(json.dumps(value), "https://example.invalid/test.json", "aruba")
    assert record["assessments"][0]["remediations"][0]["availability"] == "unknown"


def test_conflicting_publisher_chronology_does_not_turn_date_into_a_release_claim():
    value = document("2023-01-01")
    record = csaf(json.dumps(value), "https://example.invalid/test.json", "aruba")
    assert record["assessments"][0]["remediations"][0]["availability"] == "unknown"


@pytest.mark.parametrize(
    "module_name,fixture,vendor",
    [
        ("legacy_html", "cisco-php.html", "cisco"),
        ("hpe", "hpe-cray.html", "hpe"),
    ],
)
def test_html_callers_supply_source_dates(monkeypatch, module_name, fixture, vendor):
    from importlib import import_module
    from pathlib import Path

    module = import_module("infrastructure_impact.adapters." + module_name)
    calls = []

    def record_call(details, category, date=None, *, as_of=None):
        calls.append(as_of)
        return "unknown"

    monkeypatch.setattr(module, "availability", record_call)
    raw = (Path(__file__).parent / "fixtures" / fixture).read_bytes()
    parser = module.html_advisory if module_name == "legacy_html" else module.hpe_bulletin
    result = parser(raw, "https://example.invalid/test", vendor)
    assert calls and set(calls) == {result["updated_at"] or result["published_at"]}


def test_cna_solution_uses_source_timeline_without_collection_clock():
    from infrastructure_impact.adapters.standards import cna

    value = {
        "cveMetadata": {"cveId": "CVE-2099-12345"},
        "containers": {
            "cna": {
                "datePublic": "2024-06-01",
                "timeline": [{"time": "2024-07-01", "value": "Published update"}],
                "affected": [
                    {"product": "Router", "versions": [{"version": "1.0", "status": "affected"}]}
                ],
                "solutions": [{"value": "Router\nUpgrade to 2.0 (Oct 2024)"}],
            }
        },
    }
    record = cna(json.dumps(value), "https://example.invalid/test.json", "paloalto")
    assert record["assessments"][0]["remediations"][0]["availability"] == "planned"
