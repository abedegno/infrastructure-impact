"""Catalogue dates, evidence eligibility and conservative same-base follow-ups."""

from copy import deepcopy

import pytest

from infrastructure_impact.application.release_catalogue import (
    catalogue_summary,
    find_respins,
    validate_catalogue,
)


def specimen():
    return {
        "schema_version": 1,
        "generated_at": "2026-11-25T12:00:00Z",
        "review_status": "independent_human_review_pending",
        "sources": [
            {
                "source_id": "s1",
                "vendor": "cisco",
                "source_url": "https://www.cisco.com/release-notes.html",
                "retrieved_at": "2026-11-25T10:00:00Z",
                "capture_kind": "original_document",
                "original_sha256": "a" * 64,
                "excerpt_sha256": None,
            }
        ],
        "releases": [],
        "notices": [],
        "statements": [],
        "coverage": [],
    }


def evidence(source="s1"):
    return [
        {
            "source_id": source,
            "locator": "Release history / row",
            "quote": "Test release date and scope",
        }
    ]


def release(version, day, vendor="cisco", train="17.12", platforms=None):
    return {
        "vendor": vendor,
        "family": {"cisco": "IOS XE", "aruba": "AOS-CX", "arista": "EOS"}[vendor],
        "train": train,
        "version": version,
        "release_date": day,
        "date_status": "stated" if day else "unknown",
        "announcement_date": None,
        "platforms_stated": platforms or ["Catalyst 9200"],
        "evidence": evidence(),
    }


def config():
    return {
        "schema_version": 1,
        "start": "2024-01-01",
        "end": "2026-12-31",
        "trains": [
            {
                "vendor": "cisco",
                "family": "IOS XE",
                "train": "17.12",
                "platforms": ["Catalyst 9200", "Catalyst 9300"],
                "base_pattern": r"^(17\.12\.\d+)[a-z]?$",
                "base_replacement": r"\1",
            }
        ],
    }


def test_unknown_dates_stay_out_of_year_counts():
    d = specimen()
    d["releases"] = [release("17.12.7a", None)]
    rows = catalogue_summary(d, config())["annual"]
    assert all(r["observed_dated_releases"] is None and r["denominator"] is None for r in rows)
    assert catalogue_summary(d, config())["undated"][0]["versions"] == ["17.12.7a"]


def test_excerpt_is_research_only_and_complete_denominator_rejected():
    d = specimen()
    d["sources"][0].update(
        capture_kind="tool_excerpt", original_sha256=None, excerpt_sha256="b" * 64
    )
    d["releases"] = [release("17.12.7", "2025-01-01")]
    row = catalogue_summary(d, config())["annual"][1]
    assert row["observed_dated_releases"] is None
    assert row["research_dated_releases"] == 1
    assert row["denominator"] is None


def test_original_hash_and_receipt_time_required():
    d = specimen()
    d["sources"][0]["original_sha256"] = None
    with pytest.raises(ValueError):
        validate_catalogue(d)
    d = specimen()
    d["releases"] = [release("17.12.7", "2026-11-26")]
    with pytest.raises(ValueError, match="receipt"):
        validate_catalogue(d)


def test_notice_dates_not_used_as_release_dates():
    d = specimen()
    d["releases"] = [release("17.12.7", None)]
    d["notices"] = [
        {
            "vendor": "cisco",
            "family": "IOS XE",
            "train": "17.12",
            "notice_id": "FN00001",
            "title": "Configuration notice",
            "notice_date": "2025-01-01",
            "action_date": None,
            "affected_releases": ["17.12.7"],
            "platforms_stated": ["Catalyst 9200"],
            "replacement_release": None,
            "classification": "configuration_remediation",
            "evidence": evidence(),
        }
    ]
    assert catalogue_summary(d, config())["undated"][0]["versions"] == ["17.12.7"]
    assert find_respins(d, config()) == []


def test_same_base_suffix_pair_and_thresholds():
    d = specimen()
    d["releases"] = [
        release("17.12.7", "2025-01-01"),
        release("17.12.7a", "2025-01-20"),
        release("17.12.8", "2025-01-22"),
    ]
    rows = find_respins(d, config())
    assert len(rows) == 1
    assert rows[0]["classification"] == "possible_respin"
    assert rows[0]["days"] == 19 and rows[0]["within_30_days"] and rows[0]["within_90_days"]
    assert rows[0]["reason"] is None and len(rows[0]["evidence"]) == 2


def test_distinct_platforms_cannot_create_respin_pair():
    d = specimen()
    d["releases"] = [
        release("17.12.7", "2025-01-01", platforms=["Catalyst 9200"]),
        release("17.12.7a", "2025-01-20", platforms=["Catalyst 9300"]),
    ]
    assert find_respins(d, config()) == []


def test_duplicate_release_dates_deduped_conflicts_fail():
    d = specimen()
    row = release("17.12.7", "2025-01-01")
    d["releases"] = [row, deepcopy(row)]
    assert catalogue_summary(d, config())["annual"][1]["observed_dated_releases"] == 1
    d["releases"][1]["release_date"] = "2025-01-02"
    with pytest.raises(ValueError, match="Conflicting"):
        validate_catalogue(d)


def test_different_trains_and_unsupported_urls_rejected():
    d = specimen()
    d["releases"] = [release("17.9.6", "2025-01-01")]
    with pytest.raises(ValueError, match="train"):
        validate_catalogue(d)
    d = specimen()
    d["sources"][0]["source_url"] = "https://mirror.example/cisco"
    with pytest.raises(ValueError):
        validate_catalogue(d)


def test_complete_coverage_needs_all_models_and_dated_original_evidence():
    d = specimen()
    d["releases"] = [release("17.12.7", None)]
    d["coverage"] = [
        {
            "vendor": "cisco",
            "train": "17.12",
            "year": 2025,
            "status": "complete",
            "platforms": ["Catalyst 9200", "Catalyst 9300"],
            "enumeration_complete": True,
            "date_coverage_complete": True,
            "reason": "Closed publisher history",
            "source_ids": ["s1"],
        }
    ]
    with pytest.raises(ValueError, match="complete"):
        catalogue_summary(d, config())


def test_no_automatic_human_review():
    d = specimen()
    d["review_status"] = "reviewed"
    with pytest.raises(ValueError):
        validate_catalogue(d)


@pytest.mark.parametrize(
    ("vendor", "train", "base_pattern", "base_replacement", "versions", "expected"),
    [
        (
            "aruba",
            "10.13",
            r"^(10\.13\.\d{2})\d{2}$",
            r"\1xx",
            ["10.13.1000", "10.13.1010", "10.13.1100"],
            1,
        ),
        (
            "arista",
            "4.33",
            r"^(4\.33\.\d+)(?:\.\d+)?([FM])$",
            r"\1\2",
            ["4.33.1F", "4.33.1M", "4.33.1.1M"],
            1,
        ),
    ],
)
def test_vendor_maintenance_lines(
    vendor, train, base_pattern, base_replacement, versions, expected
):
    d = specimen()
    d["sources"][0].update(
        vendor=vendor,
        source_url=f"https://www.{'hpe' if vendor == 'aruba' else 'arista'}.com/release-notes",
    )
    d["releases"] = [
        release(v, f"2025-01-{day:02}", vendor, train, ["platform"])
        for v, day in zip(versions, [1, 10, 20], strict=True)
    ]
    c = config()
    c["trains"][0].update(
        vendor=vendor,
        family=d["releases"][0]["family"],
        train=train,
        platforms=["platform"],
        base_pattern=base_pattern,
        base_replacement=base_replacement,
    )
    assert len(find_respins(d, c)) == expected


def test_announcement_date_is_not_a_release_date_or_respin_date():
    d = specimen()
    d["releases"] = [release("17.12.7", None), release("17.12.7a", None)]
    for row, day in zip(d["releases"], ["2025-01-01", "2025-01-10"], strict=True):
        row["announcement_date"] = day
    assert find_respins(d, config()) == []


def test_older_release_on_newer_date_rejected():
    d = specimen()
    d["releases"] = [release("17.12.7a", "2025-01-01"), release("17.12.7", "2025-01-02")]
    with pytest.raises(ValueError, match="monotonic"):
        find_respins(d, config())


def test_cli_is_offline_and_does_not_overwrite_input(tmp_path):
    import json

    from infrastructure_impact.release_catalogue_cli import main

    d = specimen()
    path = tmp_path / "catalogue.json"
    path.write_text(json.dumps(d))
    output = tmp_path / "summary.json"
    assert main(["--catalogue", str(path), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["caveat"]
    with pytest.raises(SystemExit):
        main(["--catalogue", str(path), "--output", str(path)])
    assert json.loads(path.read_text()) == d


def test_complete_zero_requires_closed_original_enumeration():
    d = specimen()
    d["coverage"] = [
        {
            "vendor": "cisco",
            "train": "17.12",
            "year": 2024,
            "status": "complete",
            "platforms": ["Catalyst 9200", "Catalyst 9300"],
            "enumeration_complete": True,
            "date_coverage_complete": True,
            "reason": "Explicit closed publisher history",
            "source_ids": ["s1"],
        }
    ]
    result = catalogue_summary(d, config())["annual"]
    assert result[0]["denominator"] == result[0]["observed_dated_releases"] == 0
    assert result[1]["denominator"] is None
    assert result[2]["year_to_date"] is True


def test_day_precision_excerpt_receipt_is_preserved():
    d = specimen()
    d["sources"][0].update(
        retrieved_at="2026-11-25",
        capture_kind="tool_excerpt",
        original_sha256=None,
        excerpt_sha256="c" * 64,
    )
    assert validate_catalogue(d)["sources"][0]["retrieved_at"] == "2026-11-25"


def test_respin_outside_study_period_not_counted():
    d = specimen()
    d["releases"] = [release("17.12.1", "2023-01-01"), release("17.12.1a", "2023-01-02")]
    assert find_respins(d, config()) == []


def test_per_model_respins_keep_distinct_dates_and_provenance():
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
    rows = [
        release("17.12.7", "2025-01-01", platforms=["Catalyst 9200"]),
        release("17.12.7a", "2025-01-10", platforms=["Catalyst 9200"]),
        release("17.12.7", "2025-01-02", platforms=["Catalyst 9300"]),
        release("17.12.7a", "2025-02-15", platforms=["Catalyst 9300"]),
    ]
    for row in rows[2:]:
        row["evidence"] = evidence("s2")
    d["releases"] = rows
    pairs = find_respins(d, config())
    assert len(pairs) == 2
    assert {r["days"] for r in pairs} == {9, 44}
    assert {r["production_eligible"] for r in pairs} == {True, False}
    assert all(len(r["platforms_stated"]) == 1 for r in pairs)


def test_monotonic_check_applies_even_outside_respin_window():
    d = specimen()
    d["releases"] = [release("17.12.7a", "2025-01-01"), release("17.12.7", "2025-09-01")]
    with pytest.raises(ValueError, match="monotonic"):
        find_respins(d, config())


def test_lowercase_rfc3339_cannot_bypass_receipt_order():
    d = specimen()
    d["sources"][0]["retrieved_at"] = "2026-11-25t23:59:59z"
    with pytest.raises(ValueError, match="receipt"):
        validate_catalogue(d)
    d["sources"][0]["retrieved_at"] = "2026-11-25t10:00:00z"
    validate_catalogue(d)


def test_future_year_never_has_partial_coverage():
    d = specimen()
    c = config()
    c["end"] = "2027-12-31"
    d["coverage"] = [
        {
            "vendor": "cisco",
            "train": "17.12",
            "year": 2027,
            "status": "partial",
            "platforms": ["Catalyst 9200"],
            "enumeration_complete": False,
            "date_coverage_complete": False,
            "reason": "Current index",
            "source_ids": ["s1"],
        }
    ]
    assert catalogue_summary(d, c)["annual"][-1]["coverage"] == "unknown"


def test_outside_period_excerpt_does_not_invalidate_complete_year():
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
    older = release("17.12.1", "2023-01-01")
    older["evidence"] = evidence("s2")
    d["releases"] = [older, release("17.12.7", "2025-01-01")]
    d["coverage"] = [
        {
            "vendor": "cisco",
            "train": "17.12",
            "year": 2025,
            "status": "complete",
            "platforms": ["Catalyst 9200", "Catalyst 9300"],
            "enumeration_complete": True,
            "date_coverage_complete": True,
            "reason": "Closed publisher history",
            "source_ids": ["s1"],
        }
    ]
    assert catalogue_summary(d, config())["annual"][1]["denominator"] == 1


def test_corrective_relationship_requires_matching_family_and_stated_reason():
    d = specimen()
    d["releases"] = [release("17.12.7", "2025-01-01"), release("17.12.7a", "2025-01-10")]
    d["statements"] = [
        {
            "vendor": "cisco",
            "family": "Other OS",
            "train": "17.12",
            "version": "17.12.7",
            "related_release": "17.12.7a",
            "status": "corrective_respin",
            "notice_date": "2025-01-10",
            "action_date": None,
            "platforms_stated": ["Catalyst 9200"],
            "evidence": evidence(),
        }
    ]
    assert find_respins(d, config())[0]["classification"] == "possible_respin"
    d["statements"][0]["family"] = "IOS XE"
    row = find_respins(d, config())[0]
    assert row["classification"] == "corrective_respin" and row["reason"] == evidence()[0]["quote"]


def test_duplicate_prefers_original_for_same_model_pair():
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
    rows = [release("17.12.7", "2025-01-01"), release("17.12.7a", "2025-01-10")]
    duplicate = deepcopy(rows[0])
    duplicate["evidence"] = evidence("s2")
    d["releases"] = [duplicate, *rows]
    assert find_respins(d, config())[0]["production_eligible"] is True


def test_fixed_release_requires_same_train_and_stated_model():
    d = specimen()
    d["notices"] = [
        {
            "vendor": "cisco",
            "family": "IOS XE",
            "train": "17.12",
            "notice_id": "FN00001",
            "title": "Conditional fix",
            "notice_date": "2025-01-01",
            "action_date": None,
            "affected_releases": [],
            "platforms_stated": ["Catalyst 9200"],
            "replacement_release": None,
            "classification": "configuration_remediation",
            "evidence": evidence(),
            "fixed_releases": [
                {
                    "version": "17.12.2",
                    "platforms_stated": ["Catalyst 9300"],
                    "conditions": "Display defect only",
                }
            ],
        }
    ]
    with pytest.raises(ValueError, match="scope"):
        validate_catalogue(d)
