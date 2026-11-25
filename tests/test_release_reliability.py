"""Generation-safe release metrics and exact, model-aware selected upgrade context."""

import pytest
from test_release_catalogue import config, evidence, release, specimen

from infrastructure_impact.application import release_reliability as rr

PUB = {"id": "release-test", "advisory_schema_version": 2}
NOW = "2026-11-25T18:00:00Z"


def build(d=None, c=None):
    return rr.build_report(d, c, publication=PUB, generated_at=NOW)


def action(status="withdrawn", action_date=None):
    return dict(
        vendor="cisco",
        family="IOS XE",
        train="17.12",
        version="17.12.7",
        related_release=None,
        status=status,
        notice_date="2025-02-01",
        action_date=action_date,
        platforms_stated=["Catalyst 9200"],
        evidence=evidence(),
    )


def selected(models=None):
    event = dict(date="2025-01-05", previous=None, target="17.12.7", claim_ids=["c1"])
    if models is not None:
        event["models"] = models
    return dict(
        publication=PUB,
        generated_at=NOW,
        selection={"window": "all"},
        rows=[
            dict(vendor="cisco", train="17.12", scenario=s, policy="all_affected", events=[event])
            for s in ["a", "b"]
        ],
    )


def test_frozen_metrics_preserve_research_and_unknown_rates():
    report = build()
    assert report["availability"] == "available"
    metrics = [m for a in report["annual"] for m in a["metrics"].values()]
    assert metrics and all(m["rate"] is None for m in metrics)
    assert any(m["research_only_count"] for m in metrics)
    assert all(
        r["review_status"] == "independent_human_review_pending" for r in report["review_packet"]
    )
    assert len(report["review_packet"]) == len(report["catalogue"]["notices"]) + len(
        report["catalogue"]["statements"]
    )


def test_future_capture_is_unavailable_and_identity_fails_closed():
    report = rr.build_report(publication=PUB, generated_at="2025-01-01T00:00:00Z")
    assert report["availability"] == "unavailable" and report["catalogue"] is None
    assert report["annual"] == []
    with pytest.raises(ValueError):
        rr.validate_report(build(), publication={"id": "other", "advisory_schema_version": 2})
    malformed = build()
    malformed["annual"][0]["metrics"]["releases_shipped"]["rate"] = 0.2
    with pytest.raises(ValueError):
        rr.validate_report(malformed)


def test_notice_date_does_not_create_action_chronology_and_dedup_models():
    d = specimen()
    d["releases"] = [release("17.12.7", "2024-12-25"), release("17.12.7a", "2025-01-10")]
    d["statements"] = [action()]
    original = build(d, config())
    report = rr.with_upgrades(original, selected())
    assert original["upgrade_annotations"] == []
    assert len(report["upgrade_annotations"]) == 1
    annotation = report["upgrade_annotations"][0]
    assert len(annotation["references"]) == 2
    assert {m["chronology"] for m in annotation["matches"] if m["type"] == "statement"} == {
        "unknown"
    }
    assert all(m["scope_status"] == "model_unresolved" for m in annotation["matches"])
    d["statements"][0]["action_date"] = "2025-01-02"
    report = rr.with_upgrades(build(d, config()), selected(["Catalyst 9200"]))
    assert report["upgrade_annotations"][0]["matches"][0]["chronology"] == "on_or_before_step"
    assert (
        rr.with_upgrades(build(d, config()), selected(["Catalyst 9500"]))["upgrade_annotations"][0][
            "matches"
        ]
        == []
    )
    other = selected()
    other["rows"][0]["events"][0]["target"] = "17.12.6"
    assert rr.with_upgrades(original, other)["upgrade_annotations"][0]["matches"] == []


def test_respin_uses_followup_cohort_and_counts_versions_not_models():
    d = specimen()
    d["releases"] = [
        release("17.12.7", "2024-12-25", platforms=["Catalyst 9200", "Catalyst 9300"]),
        release("17.12.7a", "2025-01-10", platforms=["Catalyst 9200", "Catalyst 9300"]),
    ]
    report = build(d, config())
    assert report["annual"][0]["metrics"]["possible_respin_30"]["observed_count"] is None
    assert report["annual"][1]["metrics"]["possible_respin_30"]["observed_count"] == 1
    assert report["annual"][1]["metrics"]["possible_respin_30"]["rate"] is None


def test_csv_is_safe_and_keeps_publication_context():
    report = build()
    report["limitations"][0] = "=SUM(A1)"
    output = rr.csv_export(report)
    assert "release-test" in output and "2026-11-25T18:00:00Z" in output
    assert "'=SUM(A1)" in output
    with pytest.raises(ValueError):
        rr.csv_export(report, max_bytes=10)


def test_unsafe_source_and_extra_fields_rejected():
    report = build()
    report["catalogue"]["sources"][0]["source_url"] = "javascript:alert(1)"
    with pytest.raises(ValueError):
        rr.validate_report(report)
    report = build()
    report["unexpected"] = True
    with pytest.raises(ValueError):
        rr.validate_report(report)


def complete_coverage(year=2025):
    return dict(
        vendor="cisco",
        train="17.12",
        year=year,
        status="complete",
        platforms=["Catalyst 9200", "Catalyst 9300"],
        enumeration_complete=True,
        date_coverage_complete=True,
        reason="Explicit closed original release and signal history",
        source_ids=["s1"],
        signal_coverage={k: "complete" for k in rr.METRICS},
        prior_release_history_start="2024-01-01",
    )


def test_rates_require_explicit_signal_coverage_and_prior_history():
    d = specimen()
    d["releases"] = [release("17.12.7", "2024-12-25"), release("17.12.7a", "2025-01-10")]
    d["statements"] = [action(action_date="2025-01-15")]
    d["coverage"] = [complete_coverage()]
    metrics = build(d, config())["annual"][1]["metrics"]
    assert metrics["possible_respin_30"]["rate"] == 1
    assert metrics["possible_respin_30"]["denominator"] == 1
    assert metrics["corrective_respin_30"]["rate"] == 0
    # The action concerns a 2024 release, not a release shipped in the notice year.
    assert metrics["deferred_or_withdrawn"]["rate"] == 0
    del d["coverage"][0]["signal_coverage"]
    assert build(d, config())["annual"][1]["metrics"]["possible_respin_30"]["rate"] is None
    d["coverage"] = [complete_coverage()]
    d["coverage"][0]["prior_release_history_start"] = "2024-12-15"
    metrics = build(d, config())["annual"][1]["metrics"]
    assert metrics["possible_respin_30"]["rate"] is None
    assert metrics["possible_respin_90"]["rate"] is None


def test_forged_annotation_evidence_and_chronology_rejected():
    d = specimen()
    d["statements"] = [action()]
    report = rr.with_upgrades(build(d, config()), selected())
    report["upgrade_annotations"][0]["matches"][0]["chronology"] = "after_step"
    with pytest.raises(ValueError):
        rr.validate_report(report)


def test_legacy_unavailable_supports_selection_without_evidence():
    report = rr.unavailable_report(publication=PUB, generated_at=NOW)
    result = rr.with_upgrades(report, selected())
    assert result["upgrade_selection"] == {"window": "all"}
    assert result["upgrade_annotations"] == []
    assert result["annual"] == []


def test_count_only_metrics_and_metric_specific_coverage():
    d = specimen()
    d["releases"] = [release("17.12.7", "2025-01-01")]
    d["coverage"] = [complete_coverage()]
    d["notices"] = [
        dict(
            vendor="cisco",
            family="IOS XE",
            train="17.12",
            notice_id=f"FN{i}",
            title="Software defect",
            notice_date="2025-02-01",
            action_date=None,
            affected_releases=["17.12.7"],
            platforms_stated=["Catalyst 9200"],
            replacement_release=None,
            classification="software_defect",
            evidence=evidence(),
        )
        for i in range(2)
    ]
    metrics = build(d, config())["annual"][1]["metrics"]
    assert metrics["software_defect_notices"]["observed_count"] == 2
    assert metrics["software_defect_notices"]["rate"] is None
    assert metrics["software_defect_notices"]["denominator"] is None
    assert metrics["releases_shipped"]["rate"] is None
    del d["coverage"][0]["signal_coverage"]
    metrics = build(d, config())["annual"][1]["metrics"]
    assert metrics["possible_respin_30"]["coverage"] == "unknown"
    assert metrics["releases_shipped"]["coverage"] == "complete"


def test_explicit_deferral_notice_uses_release_year_not_notice_year():
    d = specimen()
    d["releases"] = [release("17.12.7", "2024-12-25")]
    d["notices"] = [
        dict(
            vendor="cisco",
            family="IOS XE",
            train="17.12",
            notice_id="FN1",
            title="Release deferred",
            notice_date="2025-02-01",
            action_date=None,
            affected_releases=["17.12.7"],
            platforms_stated=["Catalyst 9200"],
            replacement_release=None,
            classification="release_deferral",
            evidence=evidence(),
        )
    ]
    annual = build(d, config())["annual"]
    assert annual[0]["metrics"]["deferred_or_withdrawn"]["observed_count"] == 1
    assert annual[1]["metrics"]["deferred_or_withdrawn"]["observed_count"] is None
    assert annual[1]["metrics"]["deferral_notices"]["observed_count"] == 1


def test_partial_model_scope_is_context_and_not_group_applicability():
    d = specimen()
    d["statements"] = [action()]
    upgrades = selected(["Catalyst 9200"])
    # Independent objects: changing one scenario's models must not change the other.
    from copy import deepcopy

    upgrades["rows"][1]["events"] = deepcopy(upgrades["rows"][1]["events"])
    upgrades["rows"][1]["events"][0]["models"] = ["Catalyst 9300"]
    report = rr.with_upgrades(build(d, config()), upgrades)
    annotation = report["upgrade_annotations"][0]
    assert annotation["models"] == ["Catalyst 9200", "Catalyst 9300"]
    assert annotation["matches"][0]["scope_status"] == "model_unresolved"
    assert annotation["caveats"]


def test_standalone_review_items_retain_full_source_identity_and_scope():
    report = build()
    items = report["review_packet"]
    assert items
    for item in items:
        section = "notices" if item["type"] == "notice" else "statements"
        assert item["fact"] == report["catalogue"][section][item["index"]]


def test_research_only_counts_exclude_original_eligible_duplicate_versions():
    d = specimen()
    d["sources"].append(
        {
            **d["sources"][0],
            "source_id": "excerpt",
            "capture_kind": "tool_excerpt",
            "original_sha256": None,
            "excerpt_sha256": "b" * 64,
        }
    )
    original = release("17.12.7", "2025-01-01")
    from copy import deepcopy

    excerpt = deepcopy(original)
    excerpt["evidence"] = evidence("excerpt")
    d["releases"] = [original, excerpt]
    metric = build(d, config())["annual"][1]["metrics"]["releases_shipped"]
    assert metric["observed_count"] == metric["numerator"] == 1
    assert metric["research_only_count"] is None


def test_explicit_null_publication_is_checked_and_future_step_rejected():
    report = build()
    with pytest.raises(ValueError):
        rr.validate_report(report, publication=None)
    upgrades = selected()
    upgrades["rows"][0]["events"][0]["date"] = "2027-01-01"
    with pytest.raises(ValueError):
        rr.with_upgrades(report, upgrades)


@pytest.mark.parametrize(
    "metric,classification",
    [
        ("software_defect_notices", "software_defect"),
        ("deferral_notices", "release_deferral"),
    ],
)
def test_complete_notice_counts_require_dated_applicable_observations(metric, classification):
    d = specimen()
    d["coverage"] = [complete_coverage()]
    d["coverage"][0].update(
        status="partial", enumeration_complete=False, date_coverage_complete=False
    )
    notice = dict(
        vendor="cisco",
        family="IOS XE",
        train="17.12",
        notice_id="FN1",
        title="Undated notice",
        notice_date=None,
        action_date=None,
        affected_releases=["17.12.7"],
        platforms_stated=["Catalyst 9200"],
        replacement_release=None,
        classification=classification,
        evidence=evidence(),
    )
    d["notices"] = [notice]
    metric_row = build(d, config())["annual"][1]["metrics"][metric]
    assert metric_row["coverage"] == "unknown"
    assert metric_row["observed_count"] is None
    assert metric_row["numerator"] is None
    notice["platforms_stated"] = ["Catalyst 9500"]
    metric_row = build(d, config())["annual"][1]["metrics"][metric]
    assert metric_row["coverage"] == "complete"
    assert metric_row["observed_count"] == 0
    notice["platforms_stated"] = []
    assert build(d, config())["annual"][1]["metrics"][metric]["observed_count"] is None
    notice["notice_date"] = "2024-12-01"
    assert build(d, config())["annual"][1]["metrics"][metric]["observed_count"] == 0


def test_complete_notice_counts_require_all_configured_model_coverage_and_current_period():
    d = specimen()
    judgement = complete_coverage()
    judgement.update(
        status="partial",
        enumeration_complete=False,
        date_coverage_complete=False,
        platforms=["Catalyst 9200"],
    )
    d["coverage"] = [judgement]
    metric = build(d, config())["annual"][1]["metrics"]["software_defect_notices"]
    assert metric["observed_count"] is None
    assert metric["coverage"] == "unknown"
    judgement["platforms"] = ["Catalyst 9200", "Catalyst 9300"]
    metric = build(d, config())["annual"][1]["metrics"]["software_defect_notices"]
    assert metric["observed_count"] == 0 and metric["coverage"] == "complete"
    c = config()
    c["end"] = "2027-12-31"
    judgement["year"] = 2027
    metric = build(d, c)["annual"][-1]["metrics"]["software_defect_notices"]
    assert metric["observed_count"] is None
    assert metric["coverage"] == "unknown"


def test_csv_retains_resolvable_source_facts_and_review_items():
    import csv
    import io
    import json

    report = rr.build_report(
        publication={"id": "csv-proof", "advisory_schema_version": 2},
        generated_at="2026-11-26T00:00:00Z",
    )
    rows = list(csv.DictReader(io.StringIO(rr.csv_export(report))))
    sources = [json.loads(row["payload"]) for row in rows if row["row_type"] == "catalogue_source"]
    assert sources == report["catalogue"]["sources"]
    assert [json.loads(row["payload"]) for row in rows if row["row_type"] == "coverage"] == report[
        "catalogue"
    ]["coverage"]
    for section, kind in (
        ("releases", "release"),
        ("notices", "notice"),
        ("statements", "statement"),
    ):
        assert [json.loads(row["payload"]) for row in rows if row["row_type"] == kind] == report[
            "catalogue"
        ][section]
    assert [json.loads(row["payload"]) for row in rows if row["row_type"] == "respin"] == report[
        "respins"
    ]
    assert [
        json.loads(row["payload"]) for row in rows if row["row_type"] == "review_item"
    ] == report["review_packet"]


@pytest.mark.parametrize(
    "variant,model_unresolved",
    [("action_scope", 1), ("missing_release", 0), ("release_scope", 1), ("undated_release", 0)],
)
def test_unresolved_actions_block_complete_zero_without_inventing_cohort_counts(
    variant, model_unresolved
):
    d = specimen()
    d["releases"] = [release("17.12.7", "2025-01-01")]
    d["statements"] = [action()]
    d["coverage"] = [complete_coverage()]
    if variant == "action_scope":
        d["statements"][0]["platforms_stated"] = []
    elif variant == "missing_release":
        d["statements"][0]["version"] = "17.12.8"
    elif variant == "release_scope":
        d["releases"][0]["platforms_stated"] = []
        d["coverage"][0].update(
            status="partial", enumeration_complete=False, date_coverage_complete=False
        )
    else:
        d["releases"][0].update(release_date=None, date_status="unknown")
        d["coverage"][0].update(
            status="partial", enumeration_complete=False, date_coverage_complete=False
        )
    metric = build(d, config())["annual"][1]["metrics"]["deferred_or_withdrawn"]
    assert metric["rate"] is None
    assert metric["observed_count"] is None
    assert metric["numerator"] is None
    assert metric["coverage"] == "unknown"
    assert metric["model_unresolved_count"] == model_unresolved
    assert "Unresolved action inputs: 1" in metric["reason"]


def test_scoped_outside_cohort_and_explicitly_disjoint_actions_do_not_block_zero():
    d = specimen()
    d["releases"] = [release("17.12.7", "2024-12-25"), release("17.12.9", "2025-01-01")]
    d["statements"] = [action()]
    d["coverage"] = [complete_coverage()]
    metric = build(d, config())["annual"][1]["metrics"]["deferred_or_withdrawn"]
    assert metric["observed_count"] == metric["rate"] == 0
    d["statements"][0].update(version="17.12.8", platforms_stated=["Catalyst 9500"])
    metric = build(d, config())["annual"][1]["metrics"]["deferred_or_withdrawn"]
    assert metric["observed_count"] == metric["rate"] == 0


def test_deferral_notice_without_affected_release_identity_blocks_zero():
    d = specimen()
    d["releases"] = [release("17.12.7", "2025-01-01")]
    d["coverage"] = [complete_coverage()]
    d["notices"] = [
        dict(
            vendor="cisco",
            family="IOS XE",
            train="17.12",
            notice_id="FN1",
            title="Explicit deferral without a literal version",
            notice_date="2025-01-15",
            action_date=None,
            affected_releases=[],
            platforms_stated=["Catalyst 9200"],
            replacement_release=None,
            classification="release_deferral",
            evidence=evidence(),
        )
    ]
    metric = build(d, config())["annual"][1]["metrics"]["deferred_or_withdrawn"]
    assert metric["observed_count"] is None
    assert metric["rate"] is None
    assert "Unresolved action inputs: 1" in metric["reason"]
