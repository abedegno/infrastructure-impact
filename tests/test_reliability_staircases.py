"""Exact release joins, bounded publication context and historical compatibility."""

from copy import deepcopy

import pytest
from test_release_catalogue import config, release, specimen
from test_release_reliability import NOW, action, selected

from infrastructure_impact.application import release_reliability as rr


def report(cat=None):
    return rr.build_report(
        cat or specimen(),
        config(),
        publication={"id": "release-test", "advisory_schema_version": 2},
        generated_at=NOW,
        staircase_join_version=1,
    )


def test_catalogue_join_keeps_variant_separate_from_exact_actions():
    cat = specimen()
    cat["releases"] = [release("17.12.7a", None)]
    cat["statements"] = [dict(action(), version="17.12.7a")]
    joined = rr.with_upgrades(report(cat), selected())
    (row,) = joined["upgrade_annotations"]
    assert row["target_catalogue"]["present"] is False
    assert row["target_catalogue"]["match_type"] == "suffix_variant"
    assert row["target_catalogue"]["versions"] == ["17.12.7a"]
    assert row["target_catalogue"]["evidence"]
    assert row["matches"] == []


def test_exact_missing_and_scope_mismatch_catalogue_states():
    cat = specimen()
    cat["releases"] = [release("17.12.7", None, platforms=["Catalyst 9300"])]
    join = rr.with_upgrades(report(cat), selected(["Catalyst 9200"]))["upgrade_annotations"][0][
        "target_catalogue"
    ]
    assert join["present"] and join["match_type"] == "exact"
    assert join["scope_status"] == "model_unresolved"
    assert join["release_observations"][0]["release_date"] is None
    missing = rr.with_upgrades(report(), selected())["upgrade_annotations"][0]["target_catalogue"]
    assert missing["present"] is False and missing["match_type"] == "not_found"


def test_respin_marker_distinguishes_release_gap_and_step_gap():
    cat = specimen()
    cat["releases"] = [release("17.12.7", "2025-01-01"), release("17.12.7a", "2025-01-10")]
    (row,) = rr.with_upgrades(report(cat), selected())["upgrade_annotations"]
    (match,) = row["matches"]
    assert match["related_release"] == "17.12.7a"
    assert match["days"] == 9 and match["days_after_step"] == 5
    assert match["action_date"] is None and match["notice_date"] is None
    assert len(row["references"]) == 2


def test_only_configured_train_and_period_get_markers():
    events = selected()
    events["rows"].append(dict(events["rows"][0], train="17.9"))
    events["rows"][0]["events"] = [dict(events["rows"][0]["events"][0], date="2023-01-01")]
    joined = rr.with_upgrades(report(), events)
    assert [(r["train"], r["date"]) for r in joined["upgrade_annotations"]] == [
        ("17.12", "2025-01-05")
    ]


def test_selected_report_is_not_an_authorised_published_default():
    joined = rr.with_upgrades(report(), selected())
    with pytest.raises(ValueError, match="selected analysis"):
        rr.validate_published_report(joined)


def test_tampered_catalogue_match_is_rejected():
    joined = rr.with_upgrades(report(), selected())
    bad = deepcopy(joined)
    bad["upgrade_annotations"][0]["target_catalogue"]["present"] = True
    with pytest.raises(ValueError, match="annotation"):
        rr.validate_report(bad)


def test_csv_contains_complete_catalogue_annotation_payload():
    import csv
    import io
    import json

    joined = rr.with_upgrades(report(), selected())
    rows = list(csv.DictReader(io.StringIO(rr.csv_export(joined))))
    annotations = [json.loads(r["payload"]) for r in rows if r["row_type"] == "upgrade_annotation"]
    assert annotations == joined["upgrade_annotations"]


def test_publication_discriminator_alone_does_not_authorise_writer(tmp_path):
    from test_switching_analysis import fixture

    from infrastructure_impact.application.publication import write_reliability_assets

    joined = rr.with_upgrades(report(), selected())
    study = fixture()[-1]
    joined["upgrade_selection"] = rr._published_selection(joined, study["selection"])
    joined["published_staircase_version"] = 1
    with pytest.raises(ValueError, match="source context"):
        write_reliability_assets(
            tmp_path,
            {k: joined[k] for k in ("publication", "generated_at")}
            | dict(release_reliability=joined),
        )


def test_published_context_uses_owned_requirements_without_full_selected_hydration(monkeypatch):
    from test_switching_analysis import api, fixture
    from test_switching_upgrades import AT

    ev, ff, k, study = fixture()
    cat = specimen()
    cat["generated_at"] = AT
    cat["sources"][0]["retrieved_at"] = AT
    conf = config()
    conf["trains"][0].update(train="17.15", base_pattern=r"^(17\.15\.\d+)[a-z]?$")
    base = rr.build_report(cat, conf, publication=None, generated_at=AT, staircase_join_version=1)
    compact = api().compile_requirements(ev, ff, None, k, publication=None, generated_at=AT)
    compiled = dict(
        publication=None,
        generated_at=AT,
        requirements=compact,
        observation_end=AT[:10],
        definition_sha256=ev["definition_sha256"],
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("full selected analysis materialized")

    monkeypatch.setattr(api(), "select_report", forbidden)
    monkeypatch.setattr(api(), "select_upgrades", forbidden)
    published = rr._with_published_analysis(base, compiled, study)
    rr.validate_published_report(published)
    assert published["upgrade_selection"]["kind"] == "configured_staircases"
    assert {(a["date"], a["target"]) for a in published["upgrade_annotations"]} == {
        ("2024-12-31", "17.15.3"),
    }
    assert published["annual"] == base["annual"]
    bad = deepcopy(published)
    bad["upgrade_selection"]["start"] = "2021-01-01"
    with pytest.raises(ValueError, match="published staircase"):
        rr.validate_published_report(bad)
