"""Study reports follow public generation identity and never trust supplied outcomes."""

import json

import pytest
from test_static_delivery import dataset

from infrastructure_impact.application.publication import public_projection, publish
from infrastructure_impact.http import Application


def test_projection_recomputes_study_reports_and_drops_unowned_digest_fields():
    data = dataset()
    data["switching_validation"] = {"passed": 999, "private_note": "secret"}
    data["switching_review_packet"] = {"expected_status": "affected"}
    record = data["records"][0]
    data["switching_reviewed_source_scopes"] = [
        dict(
            source_url=record["source_url"],
            source_sha256=record["sha256"],
            scheme="arista_advisory_body_v1",
            scope_sha256="a" * 64,
            private_note="secret",
        ),
        dict(
            source_url="https://private.invalid",
            source_sha256="b" * 64,
            scheme="arista_advisory_body_v1",
            scope_sha256="c" * 64,
        ),
    ]
    result = public_projection(data)
    assert result["switching_validation"]["passed"] == 0
    assert result["switching_validation"]["independent_human_review_completed"] is False
    assert "expected_status" not in str(result["switching_review_packet"])
    assert len(result["switching_reviewed_source_scopes"]) == 1
    assert set(result["switching_reviewed_source_scopes"][0]) == {
        "source_url",
        "source_sha256",
        "scheme",
        "scope_sha256",
    }
    assert "secret" not in str(result)


@pytest.mark.parametrize("format", ["v1", "v2"])
def test_reports_share_generation_in_roots_api_and_bootstrap(tmp_path, format):
    root = publish(dataset(), tmp_path, publication_format=format)
    app = Application(tmp_path)
    for name in ("switching-validation", "switching-review-packet"):
        expected = json.loads((root / (name + ".json")).read_text())
        code, _, raw = app.route(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/" + name, "QUERY_STRING": ""}
        )
        assert code == 200
        assert json.loads(raw) == expected
        code, _, raw = app.route(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/bootstrap", "QUERY_STRING": ""}
        )
        bootstrap = json.loads(raw)
        assert bootstrap[name.replace("-", "_")]["study"] == "campus-branch-switching"
        assert expected["publication"] == bootstrap["publication"]
        assert expected["generated_at"] == bootstrap["generated_at"]


def test_query_computes_switching_digests_from_retained_bytes(monkeypatch):
    import hashlib

    from infrastructure_impact.adapters.common import assessment, base
    from infrastructure_impact.application import query, switching_validation
    from infrastructure_impact.application.source_scope import scope_sha256
    from infrastructure_impact.storage.repository import connect, ingest

    raw = b"<html><div class='item-page'>Synthetic reviewed article</div></html>"
    url = "https://www.arista.com/synthetic-reviewed-article"
    scheme = "arista_advisory_body_v1"
    review = switching_validation.definition()
    review["cases"][0].update(
        source_url=url, reviewed_scope={"scheme": scheme, "sha256": scope_sha256(raw, scheme)}
    )
    monkeypatch.setattr(switching_validation, "definition", lambda: review)
    record = base("arista", url, "SYNTHETIC", "Synthetic", "2025-01-01T00:00:00Z")
    record.update(
        cves=["CVE-2025-12345"],
        assessments=[assessment("CVE-2025-12345", "EOS", "affected", "Synthetic", [])],
    )
    with connect(":memory:") as db:
        ingest(db, raw, url, lambda *_: record, "arista")
        result = query.state(db)
    assert result["switching_reviewed_source_scopes"] == [
        dict(
            source_url=url,
            source_sha256=hashlib.sha256(raw).hexdigest(),
            scheme=scheme,
            scope_sha256=scope_sha256(raw, scheme),
        )
    ]


def test_old_generation_native_report_is_unavailable(tmp_path):
    from infrastructure_impact.application.static_delivery import encode

    root = publish(dataset(), tmp_path)
    path = root / "snapshot.json"
    data = json.loads(path.read_text())
    for key in (
        "switching_validation",
        "switching_review_packet",
        "switching_reviewed_source_scopes",
    ):
        data.pop(key, None)
    path.write_bytes(encode(data))
    # Direct accepted old snapshot bypasses manifest checks; this tests route compatibility.
    app = Application(tmp_path)
    for name in ("switching-validation", "switching-review-packet"):
        code, _, _ = app.route(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/" + name}, _opened=(root, data)
        )
        assert code == 404


def test_projection_keeps_exact_structural_and_missing_alternate_distinct(monkeypatch):
    import copy
    import re

    from infrastructure_impact.application import switching_validation

    data = dataset()
    record = next(r for r in data["records"] if r.get("document_status") != "draft")
    claim = record["assessments"][0]
    review = switching_validation.definition()
    case = dict(
        id="synthetic-projection",
        vendor=record["vendor"],
        source_url=record["source_url"],
        source_sha256=record["sha256"],
        cve_id=claim["cve_id"],
        product_pattern="^" + re.escape(claim["product"]) + "$",
        expected_status=claim["status"],
        source_locator="Synthetic",
        rationale="Synthetic",
        reviewed_scope=dict(scheme="arista_advisory_body_v1", sha256="a" * 64),
    )
    review["cases"] = [case]
    monkeypatch.setattr(switching_validation, "definition", lambda: copy.deepcopy(review))
    assert public_projection(data)["switching_validation"]["cases"][0]["outcome"] == "pass"
    case["source_sha256"] = "b" * 64
    data["switching_reviewed_source_scopes"] = [
        dict(
            source_url=record["source_url"],
            source_sha256=record["sha256"],
            scheme="arista_advisory_body_v1",
            scope_sha256="a" * 64,
            private_note="discard",
        )
    ]
    result = public_projection(data)["switching_validation"]
    assert result["cases"][0]["outcome"] == "reviewed_scope_match_source_changed"
    assert result["passed"] == 0 and result["scope_matches"] == 1
    case["source_url"] += "/absent-alternate"
    assert (
        public_projection(data)["switching_validation"]["cases"][0]["outcome"] == "source_missing"
    )


def test_rebuild_recomputes_alternate_context_and_keeps_packet_blind(monkeypatch):
    from test_switching_validation import alternate_inputs

    from infrastructure_impact.application import switching_validation

    record, choice = alternate_inputs(monkeypatch)
    data = dict(
        records=[record],
        source_audit=dict(source_selections=[choice]),
        switching_validation=dict(cases=[dict(source_context={"private": "secret"})]),
    )
    switching_validation.rebuild(data)
    assert data["switching_validation"]["cases"][0]["source_context"]["state"] == (
        "retained_unselected_representation"
    )
    assert "source_context" not in str(data["switching_review_packet"])
    assert "PRIVATE_SENTINEL" not in str(data["switching_validation"])
    data["source_audit"]["source_selections"] = []
    switching_validation.rebuild(data)
    assert "source_context" not in str(data["switching_validation"])
