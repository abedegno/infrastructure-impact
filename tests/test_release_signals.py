import csv
import json
from importlib import resources
from io import StringIO

import pytest

from infrastructure_impact.application import release_signals as signals

URL = "https://www.arista.com/en/support/release-notes"
NOW = "2026-11-25T12:00:00Z"


def event(release="4.33.11M", day="2026-10-15", **fields):
    return {
        "kind": "release",
        "vendor": "arista",
        "train": "4.33",
        "release": release,
        "related_release": None,
        "date": day,
        "platforms": [],
        "statement": f"EOS {release} release",
        "bug_ids": [],
        "source_locator": f"item/{release}",
        **fields,
    }


def report_for(dataset, **options):
    return signals.build_report(dataset, start="2024-01-01", end="2026-11-25", **options)


def test_revision_cache_and_reversion_only_count_latest_facts():
    archive = URL + "/archive"
    dataset = signals.new_dataset("2026-11-23T12:00:00Z")
    first = signals.add_document(dataset, b"a", archive, "2026-11-23T12:00:00Z", [event()])
    assert signals.add_document(dataset, b"a", archive, "2026-11-24T12:00:00Z", []) == first
    assert len(dataset["documents"]) == 1
    second = signals.add_document(
        dataset, b"b", archive, "2026-11-24T12:00:00Z", [event("4.33.12M", "2026-11-01")]
    )
    third = signals.add_document(dataset, b"a", archive, NOW, [event()])
    assert third not in (first, second)
    assert [doc["previous_revision_id"] for doc in dataset["documents"]] == [None, first, second]
    report = report_for(dataset)
    assert [fact["release"] for fact in report["events"]] == ["4.33.11M"]
    assert report["metrics"][0]["observed_releases"] == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://www.arista.com/feed",
        "https://www.arista.com.evil.test/feed",
        "https://arista.com@www.arista.com/feed",
        "https://www.arista.com:444/feed",
        "https://www.arista.com:443/feed",
        "https://community.cisco.com/feed",
        "https://www.cisco.com/feed",
        "https://www.arista.com\\@www.arista.com/feed",
    ],
)
def test_rejects_invalid_provenance_without_mutating_dataset(url):
    dataset = signals.new_dataset(NOW)
    with pytest.raises(ValueError):
        signals.add_document(dataset, b"a", url, NOW, [event()])
    assert dataset["documents"] == []


def test_rejects_altered_revision_and_future_receipt():
    dataset = signals.new_dataset(NOW)
    signals.add_document(dataset, b"a", URL, NOW, [event()])
    changed = json.loads(json.dumps(dataset))
    changed["documents"][0]["events"][0]["statement"] = "Changed"
    with pytest.raises(ValueError):
        signals.validate_dataset(changed)
    dataset["generated_at"] = "2026-11-24T12:00:00Z"
    with pytest.raises(ValueError):
        report_for(dataset)


@pytest.mark.parametrize(
    "distance,day,within_14,within_30",
    [
        (14, "2026-10-29", True, True),
        (19, "2026-11-03", False, True),
        (30, "2026-11-14", False, True),
    ],
)
def test_supports_dated_adjacent_eos_follow_up_thresholds(distance, day, within_14, within_30):
    dataset = signals.new_dataset(NOW)
    signals.add_document(dataset, b"a", URL, NOW, [event("4.33.11.2M", day), event()])
    report = report_for(dataset)
    [pair] = report["candidate_pairs"]
    assert (pair["calendar_days"], pair["within_14_days"], pair["within_30_days"]) == (
        distance,
        within_14,
        within_30,
    )
    assert pair["corrective_respin_confirmed"] is False
    assert len(set(pair["event_ids"])) == 2


@pytest.mark.parametrize(
    "second",
    [
        event("4.33.11.2M", "2026-11-15"),
        event("4.33.11.2M", "2026-10-15"),
        event("4.33.11.2M", None),
        event("4.33.10M", "2026-11-03"),
        event("4.33.11.2F", "2026-11-03"),
        event("4.33.11.2M", "2026-11-03", platforms=["7500"]),
    ],
)
def test_ineligible_neighbors_do_not_establish_follow_up(second):
    dataset = signals.new_dataset(NOW)
    signals.add_document(dataset, b"a", URL, NOW, [event(), second])
    assert report_for(dataset)["candidate_pairs"] == []


def test_conflicting_announcement_dates_cannot_support_chronology():
    dataset = signals.new_dataset(NOW)
    signals.add_document(dataset, b"a", URL, NOW, [event(), event("4.33.11.2M", "2026-11-03")])
    signals.add_document(dataset, b"b", URL + "/archive", NOW, [event(day="2026-11-02")])
    report = report_for(dataset)
    assert report["candidate_pairs"] == []
    assert report["metrics"][0]["observed_releases"] == 2


def test_exact_upgrade_annotation_preserves_claims_but_leaves_model_unresolved():
    dataset = signals.new_dataset(NOW)
    signals.add_document(
        dataset,
        b"a",
        URL,
        NOW,
        [
            event(day="2026-10-14"),
            event(kind="withdrawn", day="2026-11-03", platforms=["7500"]),
            event("4.33.11.2M", day="2026-11-03"),
        ],
    )
    upgrades = {
        "rows": [
            {
                "vendor": "arista",
                "train": "4.33",
                "year": 2026,
                "scenario": "publisher_first_fixed",
                "policy": "all_affected",
                "events": [{"date": "2026-10-15", "target": "4.33.11M", "claim_ids": ["claim-1"]}],
            }
        ]
    }
    links = report_for(dataset, upgrades=upgrades)["upgrade_links"]
    assert {link["signal"] for link in links} == {"release", "withdrawn", "candidate_follow_up"}
    assert {link["relation"] for link in links} == {"model_unresolved"}
    assert all(link["claim_ids"] == ["claim-1"] and link["target"] == "4.33.11M" for link in links)
    chronology = {link["signal"]: link["chronology"] for link in links}
    assert chronology == {
        "release": "not_later",
        "withdrawn": "later",
        "candidate_follow_up": "later",
    }


def test_seed_coverage_is_explicit_and_observations_do_not_establish_rates():
    base = resources.files("infrastructure_impact").joinpath("resources/release-signals.json")
    dataset = json.loads(base.read_text())
    assert dataset["documents"] == []
    report = report_for(dataset)
    assert {row["vendor"] for row in report["coverage"]} == {"arista", "aruba", "cisco"}
    assert len(report["metrics"]) == 9
    assert all(row["withdrawal_rate"] is None for row in report["metrics"])
    assert all(row["coverage"] == "not_established" for row in report["metrics"])
    assert all(row["partial_year"] == (row["year"] == 2026) for row in report["metrics"])
    signals.validate_report(report)


def test_csv_escapes_formula_cells_in_upgrade_evidence():
    dataset = signals.new_dataset(NOW)
    signals.add_document(dataset, b"a", URL, NOW, [event(statement="  =1+1")])
    output = signals.to_csv(report_for(dataset))
    assert any("'  =1+1" in row for row in csv.reader(StringIO(output)))


def test_unmatched_upgrade_is_visible_and_supplied_input_is_fingerprinted():
    dataset = signals.new_dataset(NOW)
    upgrades = {
        "rows": [
            {
                "vendor": "arista",
                "train": "4.33",
                "year": 2026,
                "scenario": "publisher_first_fixed",
                "policy": "all_affected",
                "events": [{"date": "2026-10-15", "target": "4.33.11M", "claim_ids": ["claim-1"]}],
            }
        ]
    }
    assert report_for(dataset)["upgrades_sha256"] is None
    report = report_for(dataset, upgrades=upgrades)
    assert len(report["upgrades_sha256"]) == 64
    [link] = report["upgrade_links"]
    assert link["signal"] == "unknown" and link["event_id"] is None
    assert link["chronology"] == "unknown" and link["model_applicability"] == "unresolved"


def test_rejects_staircase_event_with_target_from_different_train():
    dataset = signals.new_dataset(NOW)
    upgrades = {
        "rows": [
            {
                "vendor": "arista",
                "train": "4.33",
                "year": 2026,
                "scenario": "publisher_first_fixed",
                "policy": "all_affected",
                "events": [{"date": "2026-10-15", "target": "4.34.1M", "claim_ids": ["claim-1"]}],
            }
        ]
    }
    with pytest.raises(ValueError):
        report_for(dataset, upgrades=upgrades)


def test_undated_bug_ids_are_visible_in_evidence_without_dated_disclosure_counts():
    dataset = signals.new_dataset(NOW)
    signals.add_document(
        dataset,
        b"a",
        URL,
        NOW,
        [
            event(kind="bug_list", day=None, bug_ids=["BUG-123"]),
        ],
    )
    report = report_for(dataset)
    assert report["metrics"] == []
    assert report["events"][0]["bug_ids"] == ["BUG-123"]


def test_confirmed_corrective_respin_links_exact_predecessor():
    dataset = signals.new_dataset(NOW)
    signals.add_document(
        dataset,
        b"a",
        URL,
        NOW,
        [
            event(
                "4.33.11.2M",
                "2026-11-03",
                kind="corrective_respin",
                related_release="4.33.11M",
                statement="This corrective release replaces EOS 4.33.11M.",
            ),
        ],
    )
    upgrades = {
        "rows": [
            {
                "vendor": "arista",
                "train": "4.33",
                "year": 2026,
                "scenario": "publisher_first_fixed",
                "policy": "all_affected",
                "events": [{"date": "2026-10-15", "target": "4.33.11M", "claim_ids": ["claim-1"]}],
            }
        ]
    }
    report = report_for(dataset, upgrades=upgrades)
    [link] = report["upgrade_links"]
    assert link["signal"] == "corrective_respin" and link["chronology"] == "later"
    assert link["event_id"] == report["events"][0]["event_id"]
    assert link["model_applicability"] == "unresolved"


def test_conflicting_withdrawal_dates_cannot_assert_later():
    dataset = signals.new_dataset(NOW)
    signals.add_document(dataset, b"a", URL, NOW, [event(day="2026-10-14", kind="withdrawn")])
    signals.add_document(
        dataset, b"b", URL + "/archive", NOW, [event(day="2026-11-02", kind="withdrawn")]
    )
    upgrades = {
        "rows": [
            {
                "vendor": "arista",
                "train": "4.33",
                "year": 2026,
                "scenario": "publisher_first_fixed",
                "policy": "all_affected",
                "events": [{"date": "2026-10-15", "target": "4.33.11M", "claim_ids": ["claim-1"]}],
            }
        ]
    }
    links = report_for(dataset, upgrades=upgrades)["upgrade_links"]
    assert len(links) == 2
    assert all(link["chronology"] == "unknown" for link in links)


@pytest.mark.parametrize(
    ("kind", "metric"),
    [
        ("withdrawn", "explicit_withdrawals"),
        ("deferred", "explicit_deferred"),
        ("corrective_respin", "confirmed_corrective_respins"),
    ],
)
@pytest.mark.parametrize(("other_day", "count"), [("2026-10-13", 1), ("2025-12-31", 0)])
def test_conflicting_action_dates_count_one_identity_when_year_is_known(
    kind, metric, other_day, count
):
    dataset = signals.new_dataset(NOW)
    fields = {"kind": kind}
    if kind == "corrective_respin":
        fields["related_release"] = "4.33.10M"
    signals.add_document(dataset, b"a", URL, NOW, [event(**fields)])
    signals.add_document(dataset, b"b", URL + "/archive", NOW, [event(day=other_day, **fields)])
    result = signals.build_report(dataset, start="2026-01-01", end="2026-11-25")
    assert sum(row[metric] for row in result["metrics"]) == count
    if count == 0:
        assert [fact["date"] for fact in result["date_conflict_evidence"]] == [other_day]
        assert "date_conflict_evidence" in signals.to_csv(result)


def test_report_rejects_forged_metric():
    dataset = signals.new_dataset(NOW)
    signals.add_document(dataset, b"a", URL, NOW, [event()])
    report = report_for(dataset)
    report["metrics"][0]["observed_releases"] = 999
    with pytest.raises(ValueError, match="metrics"):
        signals.validate_report(report)


def test_same_bytes_advances_cutoff_without_changing_revision():
    dataset = signals.new_dataset("2026-11-23T12:00:00Z")
    signals.add_document(dataset, b"a", URL, dataset["generated_at"], [event()])
    [original] = dataset["documents"]
    assert signals.add_document(dataset, b"a", URL, NOW, [event()]) == original["revision_id"]
    assert dataset["documents"] == [original]
    assert dataset["generated_at"] == NOW
    report = report_for(
        dataset,
        upgrades={
            "rows": [
                {
                    "vendor": "arista",
                    "train": "4.33",
                    "year": 2026,
                    "scenario": "publisher_first_fixed",
                    "policy": "all_affected",
                    "events": [
                        {"date": "2026-11-24", "target": "4.33.11M", "claim_ids": ["claim-1"]}
                    ],
                }
            ]
        },
    )
    assert [link["date"] for link in report["upgrade_links"]] == ["2026-11-24"]


def test_rolling_announcements_retain_omitted_items_and_supersede_revised_items():
    dataset = signals.new_dataset(NOW)
    first = signals.add_document(
        dataset,
        b"a",
        URL,
        "2026-11-01T12:00:00Z",
        [event(), event("4.33.10M", "2026-10-01")],
    )
    second = signals.add_document(
        dataset,
        b"b",
        URL,
        NOW,
        [
            event("4.33.11M", "2026-10-16", source_locator="item/revised"),
            event("4.33.12M", "2026-11-25"),
        ],
    )
    report = report_for(dataset)
    assert [
        (fact["release"], fact["date"], fact["source"]["revision_id"]) for fact in report["events"]
    ] == [
        ("4.33.10M", "2026-10-01", first),
        ("4.33.11M", "2026-10-16", second),
        ("4.33.12M", "2026-11-25", second),
    ]
    assert report["metrics"][0]["observed_releases"] == 3
