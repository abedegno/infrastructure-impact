"""Pinned first-delivery facts stay reproducible and outside hosted publication."""

import json
from pathlib import Path

import pytest

from checks.build_release_catalogue import build_catalogue
from infrastructure_impact.application.release_catalogue import catalogue_summary, find_respins

ROOT = Path(__file__).resolve().parents[1]


def test_pinned_catalogue_matches_offline_mapping():
    actual = json.loads((ROOT / "docs/research/2026-11-25-release-catalogue.json").read_text())
    assert build_catalogue() == actual
    assert len(actual["releases"]) == 51
    assert all(
        row["evidence"]
        for section in ("releases", "notices", "statements")
        for row in actual[section]
    )


def test_pinned_summary_does_not_claim_denominators_or_review():
    value = build_catalogue()
    config = json.loads(
        (ROOT / "infrastructure_impact/resources/release-catalogue-trains.json").read_text()
    )
    summary = catalogue_summary(value, config)
    assert all(row["denominator"] is None for row in summary["annual"])
    assert summary["review_status"] == "independent_human_review_pending"
    assert [r["research_dated_releases"] for r in summary["annual"] if r["vendor"] == "aruba"] == [
        11,
        8,
        5,
    ]
    # The historical publication retains its explicit legacy configuration.
    for train in config["trains"]:
        train.pop("respin_rule", None)
    pairs = find_respins(value, config)
    assert len(pairs) == 21 and all(r["classification"] == "possible_respin" for r in pairs)
    assert not any(r["production_eligible"] for r in pairs)


def test_notice_scope_and_date_exclusions_are_retained():
    value = build_catalogue()
    notices = {r["notice_id"]: r for r in value["notices"]}
    assert set(notices) == {"FN0103", "FN74221", "FN74135", "FN72416"}
    assert notices["FN0103"]["action_date"] is None
    assert notices["FN0103"]["platforms_stated"] == []
    assert notices["FN72416"]["notice_date"] is None
    assert all(
        r["release_date"] is None for r in value["releases"] if r["vendor"] in {"cisco", "arista"}
    )
    assert len({r["version"] for r in value["releases"] if r["vendor"] == "cisco"}) == 8


def test_real_provenance_keeps_original_and_excerpt_distinct():
    sources = build_catalogue()["sources"]
    assert any(s["vendor"] == "cisco" and s["original_sha256"] for s in sources)
    assert all(s["original_sha256"] is None for s in sources if s["vendor"] == "aruba")
    assert all(
        (s["capture_kind"] == "original_document") == bool(s["original_sha256"]) for s in sources
    )


def test_research_packets_pass_public_release_identity_guard():
    from checks.release import LEAKS

    paths = list((ROOT / "docs/research").glob("2026-11-25-round4-*"))
    paths.append(ROOT / "docs/RELEASE_CATALOGUE.md")
    assert paths
    for path in paths:
        if LEAKS.search(path.read_text()):
            pytest.fail("Public release identity guard rejected " + path.name)
