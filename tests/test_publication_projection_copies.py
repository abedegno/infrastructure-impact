"""Compatibility of borrowing switching input until its allowlist projection."""

import copy
import json

import pytest
from test_current_evidence_delivery import arista_case, delivery_db  # noqa: F401
from test_current_evidence_delivery import delivery as _delivery
from test_publication_v2_runtime import inputs
from test_static_delivery import dataset

from infrastructure_impact.application import current_views, publication

delivery = _delivery


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_input_stays_outside_general_clone_and_rebuild(monkeypatch, fmt):
    data = dataset()
    data["research"]["switching_input"] = inputs()
    expected = publication.public_projection(data, publication_format=fmt)
    dumps = json.dumps
    rebuild = current_views.rebuild
    from infrastructure_impact.application import switching_evidence

    project = switching_evidence._project
    trees = []

    def checked_dumps(value, *args, **kwargs):
        if isinstance(value, dict) and "research" in value:
            assert "switching_input" not in value["research"]
            trees.append("json")
        return dumps(value, *args, **kwargs)

    def checked_rebuild(value, *args, **kwargs):
        assert "switching_input" not in value["research"]
        trees.append("rebuild")
        return rebuild(value, *args, **kwargs)

    def checked_project(value, *args, **kwargs):
        assert value is not data["research"]["switching_input"]
        assert value["claims"][0] is not data["research"]["switching_input"]["claims"][0]
        assert (
            value["claims"][0]["source"]
            is data["research"]["switching_input"]["claims"][0]["source"]
        )
        return project(value, *args, **kwargs)

    monkeypatch.setattr(switching_evidence, "_project", checked_project)
    monkeypatch.setattr(json, "dumps", checked_dumps)
    monkeypatch.setattr(current_views, "rebuild", checked_rebuild)
    actual = publication.public_projection(data, publication_format=fmt)
    assert actual == expected
    assert {
        "switching_evidence",
        "switching_comparison",
        "switching_release_history",
    } <= actual.keys()
    assert trees == ["json", "rebuild"]


@pytest.mark.parametrize("fmt", ["v1", "v2"])
@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), float("-inf"), object(), {1, 2}])
def test_switching_unknown_fields_keep_strict_json_rejection(fmt, invalid):
    data = dataset()
    data["research"]["switching_input"] = {**inputs(), "ignored": {"nested": invalid}}
    with pytest.raises((ValueError, TypeError)):
        publication.public_projection(data, publication_format=fmt)


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_noncanonical_containers_keep_legacy_normalization(fmt):
    data = dataset()
    raw = inputs()
    raw["claims"] = tuple(raw["claims"])
    raw["ignored"] = {1: ("extra",), None: "null key"}
    data["research"]["switching_input"] = raw
    expected_data = copy.deepcopy(data)
    expected_data["research"]["switching_input"] = json.loads(json.dumps(raw, allow_nan=False))
    assert publication.public_projection(
        data, publication_format=fmt
    ) == publication.public_projection(expected_data, publication_format=fmt)
    assert isinstance(raw["claims"], tuple)
    assert 1 in raw["ignored"]


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_null_and_missing_input_remain_equivalent(fmt):
    data = dataset()
    data["research"].pop("switching_input", None)
    expected = publication.public_projection(data, publication_format=fmt)
    data["research"]["switching_input"] = None
    assert publication.public_projection(data, publication_format=fmt) == expected
    assert "switching_evidence" not in expected


@pytest.mark.parametrize("fmt", ["v1", "v2"])
@pytest.mark.parametrize("with_score_input", [False, True])
def test_switching_projection_owns_nested_output_and_score_header(fmt, with_score_input):
    data = dataset()
    raw = inputs()
    c = raw["claims"][0]
    raw["score_availability"] = [
        dict(
            vendor=c["vendor"],
            advisory_id=c["advisory_id"],
            source_url=c["source"]["source_url"],
            source=copy.deepcopy(c["source"]),
            cve_id=c["cve_id"],
            product_id=c["product_id"],
            context="study_claim",
            state="unavailable",
            issues=["score_unavailable"],
            attempts=[],
        )
    ]
    data["research"]["switching_input"] = raw
    data["research"].pop("score_input", None)
    if with_score_input:
        data["research"]["score_input"] = {
            "advisories": [
                dict(
                    vendor=c["vendor"],
                    advisory_id=c["advisory_id"],
                    source_url=c["source"]["source_url"],
                    source=copy.deepcopy(c["source"]),
                )
            ]
        }
    original = copy.deepcopy(data)
    projected = publication.public_projection(data, publication_format=fmt)
    assert data == original
    projected["switching_evidence"]["claims"][0]["source"]["source_url"] = "output mutation"
    projected["switching_evidence"]["score_availability"][0]["source"]["source_url"] = (
        "output mutation"
    )
    assert data == original
    saved = copy.deepcopy(projected)
    raw["claims"][0]["source"]["source_url"] = "input mutation"
    raw["score_availability"][0]["source"]["source_url"] = "input mutation"
    assert projected == saved


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_unknown_cycle_still_rejects(fmt):
    data = dataset()
    raw = inputs()
    raw["ignored"] = raw
    data["research"]["switching_input"] = raw
    with pytest.raises(ValueError, match="Circular reference"):
        publication.public_projection(data, publication_format=fmt)


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_scalar_subclasses_and_object_keys_normalize(monkeypatch, fmt):
    from infrastructure_impact.application import switching_evidence

    class Text(str):
        pass

    data = dataset()
    raw = inputs()
    raw["claims"][0]["advisory_id"] = Text("A")
    raw["ignored"] = {1: ("extra",), None: "null key"}
    data["research"]["switching_input"] = raw
    project = switching_evidence._project

    def checked_project(value, *args, **kwargs):
        assert type(value["claims"][0]["advisory_id"]) is str
        assert value["ignored"] == {"1": ["extra"], "null": "null key"}
        return project(value, *args, **kwargs)

    monkeypatch.setattr(switching_evidence, "_project", checked_project)
    result = publication.public_projection(data, publication_format=fmt)
    assert type(result["switching_evidence"]["claims"][0]["advisory_id"]) is str
    assert type(raw["claims"][0]["advisory_id"]) is Text


@pytest.mark.parametrize("fmt", ["v1", "v2"])
@pytest.mark.parametrize("location", ["switching_evidence", "switching_comparison"])
@pytest.mark.parametrize("null_input", [False, True])
def test_switching_cached_evidence_fallback_survives(fmt, location, null_input):
    from infrastructure_impact.application import switching_evidence

    data = dataset()
    data["research"].pop("switching_input", None)
    if null_input:
        data["research"]["switching_input"] = None
    cached = switching_evidence.project(
        inputs(), publication=data.get("publication"), generated_at=data["generated_at"]
    )
    data[location] = (
        cached if location == "switching_evidence" else {"inputs": {"evidence": cached}}
    )
    result = publication.public_projection(data, publication_format=fmt)
    assert result["switching_evidence"]["claims"] == cached["claims"]


@pytest.mark.parametrize("fmt", ["v1", "v2"])
@pytest.mark.parametrize("ambiguous", [False, True])
def test_switching_excluded_source_ownership_is_preserved(delivery, fmt, ambiguous):
    raw = inputs()
    excluded = delivery["retained_advisories"][0]["record"]
    c = raw["claims"][0]
    c.update(vendor=excluded["vendor"], advisory_id=excluded["advisory_id"])
    c["source"].update(source_url=excluded["source_url"], source_sha256=excluded["sha256"])
    if ambiguous:
        c["source"].pop("source_sha256")
    delivery["research"]["switching_input"] = raw
    original = copy.deepcopy(delivery)
    if ambiguous:
        with pytest.raises(ValueError, match="Ambiguous current research source ownership"):
            publication.public_projection(delivery, publication_format=fmt)
    else:
        result = publication.public_projection(delivery, publication_format=fmt)
        assert result["switching_evidence"]["claims"] == []
    assert delivery == original


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_severity_filter_keeps_borrowed_claim_unchanged(delivery, fmt):
    raw = inputs()
    excluded = delivery["retained_advisories"][0]["record"]
    raw["claims"][0]["vendor_severity"] = [
        {
            "vendor": excluded["vendor"],
            "advisory_id": excluded["advisory_id"],
            "source": {"source_url": excluded["source_url"], "source_sha256": excluded["sha256"]},
        }
    ]
    delivery["research"]["switching_input"] = raw
    original = copy.deepcopy(delivery)
    result = publication.public_projection(delivery, publication_format=fmt)
    assert result["switching_evidence"]["claims"][0]["vendor_severity"] == []
    assert delivery == original


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_array_of_pairs_claim_is_not_coerced_to_object(fmt):
    data = dataset()
    raw = inputs()
    raw["claims"][0] = list(raw["claims"][0].items())
    data["research"]["switching_input"] = raw
    with pytest.raises(AttributeError, match="get"):
        publication.public_projection(data, publication_format=fmt)


@pytest.mark.parametrize("fmt", ["v1", "v2"])
@pytest.mark.parametrize("container", ["list", "dict"])
def test_switching_container_subclass_length_keeps_legacy_normalization(fmt, container):
    class Claims(list):
        def __len__(self):
            raise RuntimeError("custom length must not be called")

    class Claim(dict):
        def __len__(self):
            raise RuntimeError("custom length must not be called")

    data = dataset()
    raw = inputs()
    if container == "list":
        raw["claims"] = Claims(raw["claims"])
    else:
        raw["claims"][0] = Claim(raw["claims"][0])
    data["research"]["switching_input"] = raw
    result = publication.public_projection(data, publication_format=fmt)
    assert len(result["switching_evidence"]["claims"]) == 1


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_deep_native_unknown_field_keeps_legacy_json_acceptance(fmt):
    data = dataset()
    raw = inputs()
    nested = "leaf"
    for _ in range(350):
        nested = {"nested": nested}
    raw["ignored"] = nested
    data["research"]["switching_input"] = raw
    result = publication.public_projection(data, publication_format=fmt)
    assert len(result["switching_evidence"]["claims"]) == 1


def test_switching_json_boundary_falls_back_when_native_walk_exceeds_depth():
    nested = "leaf"
    for _ in range(600):
        nested = {"nested": nested}
    raw = {"ignored": nested}
    # The legacy JSON boundary accepts this depth even if the Python guard
    # consumes its recursion budget sooner than the C encoder/decoder.
    normalized = json.loads(json.dumps(raw, allow_nan=False))["ignored"]
    actual = publication._switching_projection_input(raw)["ignored"]
    for _ in range(600):
        actual = actual["nested"]
        normalized = normalized["nested"]
    assert actual == normalized == "leaf"


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_surrogate_pair_in_product_keeps_legacy_normalization(fmt):
    data = dataset()
    raw = inputs()
    raw["claims"][0]["product"] = "Rocket \ud83d\ude80"
    data["research"]["switching_input"] = raw
    result = publication.public_projection(data, publication_format=fmt)
    assert result["switching_evidence"]["claims"][0]["product"] == "Rocket 🚀"
    assert raw["claims"][0]["product"] == "Rocket \ud83d\ude80"


def test_switching_surrogate_pair_in_key_keeps_legacy_normalization():
    actual = publication._switching_projection_input({"\ud83d\ude80": ["value"]})
    assert actual == {"🚀": ["value"]}


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_switching_ignored_lone_surrogate_keeps_legacy_projection(fmt):
    data = dataset()
    data["research"]["switching_input"] = inputs()
    expected = publication.public_projection(data, publication_format=fmt)
    data["research"]["switching_input"]["ignored"] = "unpaired \ud800"
    assert publication.public_projection(data, publication_format=fmt) == expected


def test_switching_ordinary_unicode_keeps_borrowed_native_input():
    raw = {"claims": [{"product": "Rocket 🚀"}]}
    actual = publication._switching_projection_input(raw)
    assert actual["claims"] is raw["claims"]
