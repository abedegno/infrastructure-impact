"""Regression controls for the reviewed release-reliability corrections."""

from copy import deepcopy

import pytest
from test_release_catalogue import config, release, specimen

from infrastructure_impact.application import release_catalogue as catalogue
from infrastructure_impact.application import release_reliability as reliability


def configured(vendor, versions):
    d = specimen()
    train = {"cisco": "17.12", "aruba": "10.13", "arista": "4.33"}[vendor]
    c = config()
    patterns = {
        "cisco": (r"^(17\.12\.\d+)[a-z]?$", r"\1", "letter_suffix"),
        "aruba": (r"^(10\.13\.\d{2})\d{2}$", r"\1xx", "non_decadal_build"),
        "arista": (r"^(4\.33\.\d+)(?:\.\d+)?([FM])$", r"\1\2", "subrelease"),
    }
    pattern, replacement, rule = patterns[vendor]
    c["trains"][0].update(
        vendor=vendor,
        train=train,
        family=vendor,
        platforms=["model"],
        base_pattern=pattern,
        base_replacement=replacement,
        respin_rule=rule,
    )
    d["sources"][0].update(
        vendor=vendor,
        source_url={
            "cisco": "https://www.cisco.com/notes",
            "aruba": "https://www.hpe.com/notes",
            "arista": "https://www.arista.com/notes",
        }[vendor],
    )
    for version, day in versions:
        row = release(version, day, vendor, train, ["model"])
        row["family"] = vendor
        d["releases"].append(row)
    return d, c


def test_aruba_regular_cadence_is_not_a_respin():
    d, c = configured(
        "aruba",
        [("10.13.1000", "2024-01-01"), ("10.13.1010", "2024-01-20"), ("10.13.1020", "2024-02-01")],
    )
    assert catalogue.find_respins(d, c) == []


def test_aruba_patch_builds_anchor_to_regular_build_not_each_other():
    d, c = configured(
        "aruba",
        [("10.13.1000", "2024-01-01"), ("10.13.1003", "2024-01-10"), ("10.13.1005", "2024-02-01")],
    )
    rows = catalogue.find_respins(d, c)
    assert [(r["previous_release"], r["followup_release"], r["days"]) for r in rows] == [
        ("10.13.1000", "10.13.1003", 9),
        ("10.13.1000", "10.13.1005", 31),
    ]
    assert all(r["expected_regular_build_absent"] is False for r in rows)


def test_missing_regular_build_keeps_candidate_but_unknown_interval():
    d, c = configured("aruba", [("10.13.1101", "2025-01-01")])
    (row,) = catalogue.find_respins(d, c)
    assert row["expected_regular_build"] == "10.13.1100"
    assert row["expected_regular_build_absent"] is True
    assert row["previous_release"] is None and row["days"] is None
    assert row["within_30_days"] is None and row["within_90_days"] is None
    assert row["evidence"] == d["releases"][0]["evidence"]
    report = reliability.build_report(d, c, publication=None, generated_at=d["generated_at"])
    metric = report["annual"][1]["metrics"]["possible_respin_90"]
    assert metric["rate"] is None and metric["observed_count"] is None
    assert any(r["type"] == "respin" for r in report["review_packet"])


@pytest.mark.parametrize(
    ("vendor", "versions", "expected"),
    [
        ("cisco", ["17.12.7", "17.12.7a", "17.12.8"], [("17.12.7", "17.12.7a")]),
        ("arista", ["4.33.11M", "4.33.11.2M", "4.33.12M"], [("4.33.11M", "4.33.11.2M")]),
    ],
)
def test_explicit_vendor_rules(vendor, versions, expected):
    d, c = configured(vendor, list(zip(versions, ["2025-01-01", "2025-01-10", "2025-01-20"])))
    assert [
        (r["previous_release"], r["followup_release"]) for r in catalogue.find_respins(d, c)
    ] == expected


def test_rule_cannot_be_used_for_a_different_vendor():
    d, c = configured("aruba", [])
    c["trains"][0]["respin_rule"] = "letter_suffix"
    with pytest.raises(ValueError, match="rule"):
        catalogue.find_respins(d, c)


def test_unique_release_keeps_scope_union_and_each_source_observation():
    d = specimen()
    a = release("17.12.7", None, platforms=["Catalyst 9200"])
    b = release("17.12.7", None, platforms=["Catalyst 9300"])
    b["evidence"][0]["locator"] = "Second model table / row"
    d["releases"] = [a, b]
    original = deepcopy(d)
    result = catalogue.deduplicate_releases(d)
    assert d == original
    (row,) = result["releases"]
    assert row["platforms_stated"] == ["Catalyst 9200", "Catalyst 9300"]
    assert row["evidence"] == a["evidence"] + b["evidence"]
    assert row["observations"] == [a, b]
    assert catalogue.deduplicate_releases(result) == result
    catalogue.validate_catalogue(result)
    result["releases"].append(deepcopy(row))
    with pytest.raises(ValueError, match="Duplicate release identity"):
        catalogue.validate_catalogue(result)


def test_merged_record_does_not_transfer_dates_or_original_eligibility_between_models():
    d = specimen()
    d["sources"].append(
        {
            **d["sources"][0],
            "source_id": "s2",
            "capture_kind": "tool_excerpt",
            "original_sha256": None,
            "excerpt_sha256": "b" * 64,
        }
    )
    for model, days, source in [
        ("Catalyst 9200", ["2025-01-01", "2025-01-10"], "s1"),
        ("Catalyst 9300", ["2025-01-02", "2025-02-15"], "s2"),
    ]:
        for version, day in zip(["17.12.7", "17.12.7a"], days):
            row = release(version, day, platforms=[model])
            row["evidence"][0]["source_id"] = source
            d["releases"].append(row)
    result = catalogue.deduplicate_releases(d)
    assert len(result["releases"]) == 2
    assert all(r["release_date"] is None for r in result["releases"])
    pairs = catalogue.find_respins(result, config())
    assert {(tuple(r["platforms_stated"]), r["days"], r["production_eligible"]) for r in pairs} == {
        (("Catalyst 9200",), 9, True),
        (("Catalyst 9300",), 44, False),
    }
    assert (
        catalogue.catalogue_summary(result, config())["annual"][1]["observed_dated_releases"] == 2
    )


def test_unique_catalogue_rejects_tampered_union_scope():
    d = specimen()
    d["releases"] = [
        release("17.12.7", None, platforms=[p]) for p in ["Catalyst 9200", "Catalyst 9300"]
    ]
    result = catalogue.deduplicate_releases(d)
    result["releases"][0]["platforms_stated"].append("unstated model")
    with pytest.raises(ValueError, match="observation union"):
        catalogue.validate_catalogue(result)


@pytest.mark.parametrize("reverse", [False, True])
def test_dated_original_is_not_hidden_by_undated_same_model_observation(reverse):
    d, c = configured(
        "cisco", [("17.12.7", None), ("17.12.7", "2025-01-01"), ("17.12.7a", "2025-01-10")]
    )
    if reverse:
        d["releases"][:2] = reversed(d["releases"][:2])
    report = reliability.build_report(d, c, publication=None, generated_at=d["generated_at"])
    (row,) = report["respins"]
    assert row["days"] == 9 and row["production_eligible"] is True
    assert report["annual"][1]["metrics"]["possible_respin_30"]["numerator"] == 1


def test_legacy_chronology_outside_period_keeps_original_acceptance_semantics():
    d = specimen()
    d["releases"] = [release("17.12.7b", "2023-01-01"), release("17.12.7a", "2023-01-02")]
    assert catalogue.find_respins(d, config()) == []
