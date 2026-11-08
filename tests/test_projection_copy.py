"""One public JSON copy preserves partition isolation and deterministic projections."""

import copy
import json
from hashlib import sha256

import pytest
from test_current_evidence_delivery import (  # noqa: F401
    arista_case,
    delivery_db,
)
from test_current_evidence_delivery import (
    delivery as _delivery,
)
from test_static_delivery import dataset

from infrastructure_impact.application.current_views import rebuild
from infrastructure_impact.application.publication import public_projection

delivery = _delivery


@pytest.mark.parametrize("json_copy", [False, True])
def test_rebuild_isolates_input_and_computed_partition(delivery, json_copy):
    partition = copy.deepcopy(
        {k: delivery[k] for k in ("records", "retained_advisories", "current_evidence")}
    )
    before_data = copy.deepcopy(delivery)
    before_partition = copy.deepcopy(partition)
    result = rebuild(delivery, partition, json_copy=json_copy)
    assert delivery == before_data
    assert partition == before_partition
    result["records"][0]["notes"].append("output mutation")
    result["retained_advisories"][0]["record"]["notes"].append("output mutation")
    result["current_evidence"]["counts"]["current"] = 999
    result["research"]["release_documents"].append({"output": True})
    assert delivery == before_data
    assert partition == before_partition
    partition["records"][0]["notes"].append("partition mutation")
    delivery["research"]["release_documents"].append({"input": True})
    assert "partition mutation" not in result["records"][0]["notes"]
    assert {"input": True} not in result["research"]["release_documents"]
    assert "current_evidence_input" not in result["research"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), b"bytes", {1}])
@pytest.mark.parametrize("location", ["data", "partition"])
def test_json_rebuild_rejects_non_json_public_values(delivery, value, location):
    partition = copy.deepcopy(
        {k: delivery[k] for k in ("records", "retained_advisories", "current_evidence")}
    )
    (delivery if location == "data" else partition)["invalid_public_value"] = value
    with pytest.raises((TypeError, ValueError), match="Out of range|not JSON serializable"):
        rebuild(delivery, partition, json_copy=True)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), b"bytes", {1}])
def test_projection_still_rejects_non_json_input(delivery, value):
    delivery["invalid_public_value"] = value
    with pytest.raises((TypeError, ValueError), match="Out of range|not JSON serializable"):
        public_projection(delivery)


def test_public_projection_matches_pinned_synthetic_output(monkeypatch):
    from infrastructure_impact.application import query
    from infrastructure_impact.storage import repository

    at = "2026-11-07T18:00:00Z"
    monkeypatch.setattr(repository, "now", lambda: at)
    monkeypatch.setattr(query, "now", lambda: at)
    data = dataset()
    data["source_audit"]["audited_at"] = at
    data["synthetic_json_types"] = {7: ("unicode \u03bb", 2)}
    before = copy.deepcopy(data)
    projected = public_projection(data)
    assert projected["synthetic_json_types"] == {"7": ["unicode \u03bb", 2]}
    assert data == before
    encoded = json.dumps(projected, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    assert (
        sha256(encoded.encode()).hexdigest()
        == "ca01ec01c770287032278aadc0c29c4384d03e8acade38cb50ecb2d22147a7ad"
    )
