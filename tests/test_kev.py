"""Synthetic contract tests for generation-bound KEV membership and freshness."""

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from infrastructure_impact.application.kev import (
    KevUnavailable,
    build_report,
    select_report,
    validate_report,
)
from infrastructure_impact.references.kev import parse

FIXTURES = Path(__file__).parent / "fixtures"
SHARED = json.loads((FIXTURES / "kev-selection-cases.json").read_text())
BASE = SHARED["base_report"]


@pytest.mark.parametrize("case", SHARED["cases"], ids=lambda case: case["name"])
def test_shared_selection(case):
    before = copy.deepcopy(case)
    if case["expected"]["error"]:
        with pytest.raises(KevUnavailable) as error:
            select_report(
                case["report"],
                case["requested"],
                kev_only=case["kev_only"],
                evaluated_at=case["evaluated_at"],
            )
        assert error.value.code == case["expected"]["error"]
    else:
        result = select_report(
            case["report"],
            case["requested"],
            kev_only=case["kev_only"],
            evaluated_at=case["evaluated_at"],
        )
        expected = case["expected"]
        assert result["source"]["availability"] == expected["availability"]
        assert result["selection"]["membership"] == expected["membership"]
        assert result["selection"]["effective_cve_ids"] == expected["effective_cve_ids"]
        assert result["selection"]["requested_cve_ids"] == sorted(expected["membership"])
        assert result["evaluated_at"] == case["evaluated_at"]
        if case["report"]:
            original = case["report"]
            for key in original.keys() - {"source", "selection", "evaluated_at"}:
                assert result[key] == original[key]
            assert (
                result["source"] | {"availability": original["source"]["availability"]}
                == original["source"]
            )
        else:
            assert result["publication"] is None
            assert result["source"]["configured"] is None
            assert result["source"]["enabled"] is None
            validate_report(result)
    assert case == before


def source_input():
    return {
        "configured": True,
        "enabled": True,
        "checked_at": "2026-11-02T13:00:00+01:00",
        "latest_attempt": {
            "checked_at": "2026-11-02T13:00:00+01:00",
            "outcome": "ok",
            "error_code": None,
        },
        "retained": {
            "catalogue": parse((FIXTURES / "kev-valid.json").read_bytes()),
            "sha256": "a" * 64,
            "revision_id": "7",
            "source_observed_at": "2026-11-01T12:00:00Z",
            "parsed_at": "2026-11-01T12:01:00Z",
        },
    }


def build(source=None, scope=None, publication=BASE["publication"]):
    return build_report(
        source if source is not None else source_input(),
        scope if scope is not None else ["CVE-2024-6387"],
        publication=publication,
        generated_at=BASE["generated_at"],
    )


def test_build_retains_complete_index_and_bounds_details_to_scope_without_mutation():
    source = source_input()
    source["retained"]["catalogue"]["entries"]["CVE-2024-6387"]["forensicTriage"] = "Novel triage"
    source["retained"]["catalogue"]["entries"]["CVE-2024-6387"]["knownRansomwareCampaignUse"] = (
        "Unknown"
    )
    before = copy.deepcopy(source)
    report = build(source, ["CVE-2024-6387", "invalid", "CVE-2024-6387"])
    validate_report(report)
    assert report["listed_cve_ids"] == ["CVE-2024-6387", "CVE-2099-99999"]
    assert list(report["entries"]) == ["CVE-2024-6387"]
    assert report["source"]["checked_at"] == "2026-11-02T13:00:00+01:00"
    assert report["catalogue"]["revision_id"] == "7"
    assert report["entries"]["CVE-2024-6387"]["forensicTriage"] == "Novel triage"
    assert report["entries"]["CVE-2024-6387"]["knownRansomwareCampaignUse"] == "Unknown"
    report["entries"]["CVE-2024-6387"]["product"] = "changed"
    report["publication"]["id"] = "changed"
    assert source == before
    assert BASE["publication"]["id"] == "synthetic-generation"


def test_builder_preserves_historical_retention_and_supports_unpublished_context():
    source = source_input()
    source["enabled"] = False
    report = build(source, publication=None)
    validate_report(report)
    assert report["source"]["availability"] == "disabled"
    assert report["selection"]["membership"] == {"CVE-2024-6387": "unknown"}
    assert report["listed_cve_ids"] == ["CVE-2024-6387", "CVE-2099-99999"]
    assert report["entries"]


def test_absent_source_input_is_not_configured():
    report = build({})
    validate_report(report)
    assert report["source"]["availability"] == "not_configured"
    assert report["source"]["configured"] is False
    assert report["source"]["enabled"] is False


@pytest.mark.parametrize(
    "path,value",
    [
        (("unexpected",), True),
        (("source", "payload_path"), "private"),
        (("catalogue", "raw"), "private"),
        (("publication", "private"), "private"),
        (("policy", "fresh_for_seconds"), 1),
        (("catalogue", "revision_id"), 7),
        (("generated_at",), "2026-02-30T00:00:00Z"),
        (("source", "checked_at"), "2026-11-02T12:00:00"),
        (("entries", "CVE-2024-6387", "dateAdded"), "2026-02-30"),
        (("entries", "CVE-2024-6387", "private"), "private"),
        (("selection", "membership", "CVE-2024-6387"), "affected"),
        (("listed_cve_ids",), ["CVE-2024-6387", "CVE-2024-6387"]),
        (("catalogue", "count"), 3),
        (("source", "configured"), None),
    ],
)
def test_strict_validation_rejects_malformed_reports(path, value):
    report = copy.deepcopy(BASE)
    target = report
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        validate_report(report)


@pytest.mark.parametrize("mutation", ["count", "identity", "empty", "bad_date", "extra", "parser"])
def test_builder_rejects_invalid_normalized_catalogue_even_outside_scope(mutation):
    source = source_input()
    catalogue = source["retained"]["catalogue"]
    if mutation == "count":
        catalogue["count"] = 1
    if mutation == "identity":
        catalogue["entries"]["CVE-2099-99999"]["cveID"] = "CVE-2024-6387"
    if mutation == "empty":
        catalogue["entries"] = {}
        catalogue["count"] = 0
    if mutation == "bad_date":
        catalogue["entries"]["CVE-2099-99999"]["dateAdded"] = "bad"
    if mutation == "extra":
        catalogue["entries"]["CVE-2099-99999"]["private_path"] = "private"
    if mutation == "parser":
        catalogue["parser_version"] = 0
    with pytest.raises(ValueError):
        build(source)


def test_selection_defaults_to_current_utc_without_changing_generation_time():
    before = datetime.now(timezone.utc)
    selected = select_report(BASE, ["CVE-2024-6387"])
    after = datetime.now(timezone.utc)
    assert (
        before <= datetime.fromisoformat(selected["evaluated_at"].replace("Z", "+00:00")) <= after
    )
    assert selected["generated_at"] == BASE["generated_at"]
    with pytest.raises(ValueError):
        select_report(BASE, [], evaluated_at="invalid")


def test_explicit_freshness_boundaries():
    def evaluate_age(seconds):
        when = datetime(2026, 11, 2, 12, tzinfo=timezone.utc) + timedelta(seconds=seconds)
        return select_report(BASE, [], evaluated_at=when.isoformat())

    def evaluate_future(seconds):
        report = copy.deepcopy(BASE)
        report["source"]["checked_at"] = (
            datetime(2026, 11, 2, 12, tzinfo=timezone.utc) + timedelta(seconds=seconds)
        ).isoformat()
        return select_report(report, [], evaluated_at=BASE["generated_at"])

    assert evaluate_age(129600)["source"]["availability"] == "available"
    assert evaluate_age(129601)["source"]["availability"] == "stale"
    assert evaluate_future(300)["source"]["availability"] == "available"
    assert evaluate_future(301)["source"]["availability"] == "future"


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_membership",
        "unavailable_claim",
        "newline_cve",
        "blank_publisher",
        "missing_normalized",
    ],
)
def test_strict_reports_reject_inconsistent_or_noncanonical_claims(mutation):
    report = copy.deepcopy(BASE)
    if mutation == "wrong_membership":
        report["selection"]["membership"]["CVE-2024-6387"] = "not_listed"
    elif mutation == "unavailable_claim":
        report["source"]["availability"] = "disabled"
    elif mutation == "newline_cve":
        report["listed_cve_ids"][1] += "\n"
    elif mutation == "blank_publisher":
        report["entries"]["CVE-2024-6387"]["product"] = " "
    elif mutation == "missing_normalized":
        source = source_input()
        del source["retained"]["catalogue"]["entries"]
        with pytest.raises(ValueError):
            build(source)
        return
    with pytest.raises(ValueError):
        validate_report(report)
