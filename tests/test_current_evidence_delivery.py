"""Current delivery excludes exact evidence identities, while audit keeps them."""

import copy
import csv
import io
import json

import pytest
from test_arista_current_evidence import (  # noqa: F401
    AT,
    CSAF,
    URL,
    alternate_bytes,
    primary_bytes,
)
from test_arista_current_evidence import (
    arista_case as _arista_case,
)

from infrastructure_impact.application.publication import public_projection, publish
from infrastructure_impact.application.query import state
from infrastructure_impact.exports import csv_export
from infrastructure_impact.http import Application
from infrastructure_impact.storage.repository import connect, ingest

arista_case = _arista_case


@pytest.fixture
def delivery_db(arista_case):
    from infrastructure_impact.collection.service import resolve_document, retain_resolution
    from infrastructure_impact.plugins.shared import structured

    registry = arista_case["registry"]
    primary = b"<!-- PRIVATE_BODY_SENTINEL_DO_NOT_PUBLISH -->" + primary_bytes()
    with connect(":memory:") as db:
        legacy = registry.finalize(structured(alternate_bytes(), CSAF, "arista"), CSAF, "arista")
        previous = copy.deepcopy(legacy)
        previous["assessments"][0]["status"] = "unaffected"
        ingest(db, b"synthetic previous interpretation", CSAF, lambda *_: previous, "arista")
        ingest(db, alternate_bytes(), CSAF, lambda *_: legacy, "arista")
        ingest(db, primary, URL, registry.normalize, "arista")
        unrelated = copy.deepcopy(legacy)
        unrelated.update(
            advisory_id="UNRELATED-SAME-CVE",
            source_url="https://www.arista.com/en/support/advisories-notices/security-advisory/unrelated",
            document_status="published",
        )
        ingest(db, b"synthetic unrelated", unrelated["source_url"], lambda *_: unrelated, "arista")
        resolution = resolve_document(
            db,
            URL,
            "arista",
            fetcher=lambda _db, url, _v: primary if url == URL else alternate_bytes(),
        )
        retain_resolution(db, "arista", URL, resolution)
        yield db


@pytest.fixture
def delivery(delivery_db):
    return state(delivery_db, ["CVE-2023-5501", "CVE-2024-6858"])


def test_query_partitions_before_current_reducers(delivery):
    assert len(delivery["records"]) == 2
    assert delivery["counts"]["advisories"] == 2
    assert delivery["current_evidence"]["counts"] == {
        "current": 2,
        "excluded": 1,
        "retained_total": 3,
    }
    assert delivery["all_cves"] == ["CVE-2023-5501", "CVE-2024-6858"]
    assert (
        next(v for v in delivery["catalogue"]["vendors"] if v["vendor"] == "arista")["advisories"]
        == 2
    )
    assert (
        delivery["retained_advisories"][0]["record"]["advisory_id"]
        == "Arista Networks Security Advisory 103"
    )
    assert "current_evidence_input" in delivery["research"]
    assert all(
        c["advisory_id"] != "Arista Networks Security Advisory 103"
        for c in delivery["research"]["switching_input"]["claims"]
    )


def test_current_csv_does_not_reintroduce_excluded_identity(delivery):
    rows = list(csv.DictReader(io.StringIO(csv_export(delivery))))
    assert not any(r["advisory_id"] == "Arista Networks Security Advisory 103" for r in rows)
    assert any(r["advisory_id"] == "UNRELATED-SAME-CVE" for r in rows)


def test_projection_rebuilds_and_removes_private_input_without_mutation(delivery):
    before = copy.deepcopy(delivery)
    projected = public_projection(delivery)
    assert delivery == before
    assert "current_evidence_input" not in projected["research"]
    assert "raw_b64" not in json.dumps(projected)
    assert len(projected["records"]) == 2
    assert projected["current_evidence"]["counts"]["retained_total"] == 3
    assert (
        projected["retained_advisories"][0]["target_key"]
        == projected["current_evidence"]["decisions"][0]["target_key"]
    )


@pytest.mark.parametrize("mutation", ["count", "reference", "generation", "restore"])
def test_boundary_rejects_supplied_inconsistent_partition(delivery, mutation):
    if mutation == "count":
        delivery["current_evidence"]["counts"]["current"] = 99
    elif mutation == "reference":
        delivery["retained_advisories"][0]["decision_id"] = "0" * 64
    elif mutation == "generation":
        delivery["current_evidence"]["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    else:
        delivery["records"].append(delivery["retained_advisories"].pop()["record"])
    with pytest.raises(ValueError):
        public_projection(delivery)


def test_retained_exports_and_api_are_explicit(delivery, tmp_path):
    from infrastructure_impact.exports import retained_assessment_export, retained_csv_export

    projected = public_projection(delivery)
    exported = retained_assessment_export(projected)
    assert len(exported["records"]) == 1
    row = list(csv.DictReader(io.StringIO(retained_csv_export(projected))))[0]
    assert row["record_scope"] == "retained_latest_excluded"
    assert row["disposition"] == "excluded_from_current"
    assert row["decision_id"] and row["policy_fingerprint"] and row["reason"]
    root = tmp_path / "publications"
    generation = publish(delivery, root)
    app = Application(root)
    for path in ["/api/v1/current-evidence", "/api/v1/retained-advisories"]:
        status, _, body = app.route(
            {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": ""}
        )
        assert status == 200
        assert json.loads(body)["publication"]["id"] == generation.name
    status, mime, body = app.route(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/v1/retained-advisories",
            "QUERY_STRING": "format=csv",
        }
    )
    assert status == 200 and mime == "text/csv"
    assert list(csv.DictReader(io.StringIO(body.decode())))[0]["decision_id"]


def test_excluded_evaluation_preserves_expectation_and_historical_outcome():
    from infrastructure_impact.application.evaluation import evaluate
    from infrastructure_impact.application.extraction_validation import validation_report

    record = {
        "vendor": "arista",
        "source_url": CSAF,
        "sha256": "a" * 64,
        "assessments": [
            {
                "cve_id": "CVE-2023-5501",
                "product": "EOS",
                "status": "affected",
                "scope": "product",
                "versions": [],
                "remediations": [],
            }
        ],
    }
    case = {
        "id": "synthetic",
        "vendor": "arista",
        "source_url": CSAF,
        "source_sha256": "a" * 64,
        "cve_id": "CVE-2023-5501",
        "product_pattern": "EOS",
        "expected_status": "affected",
    }
    definition = {
        "cases": [case],
        "limitations": [],
        "reviewed_at": AT,
        "review_method": "synthetic",
        "sample_strategy": "synthetic",
    }
    wrappers = [
        {"record": record, "decision_id": "b" * 64, "record_scope": "retained_latest_excluded"}
    ]
    for result in [
        evaluate([], definition=definition, retained_advisories=wrappers),
        validation_report([], definition, retained_advisories=wrappers),
    ]:
        assert result["passed"] == 0
        assert result["cases"][0]["outcome"] == "current_scope_excluded"
        assert result["cases"][0]["historical_outcome"] == "pass"
        assert result["cases"][0]["expected_status"] == "affected"
        assert result["cases"][0]["decision_ids"] == ["b" * 64]


def test_old_reader_reports_unavailable_counts_without_reinterpretation(tmp_path):
    generation = tmp_path / "generations" / ("a" * 32)
    generation.mkdir(parents=True)
    old = {
        "publication": {"id": "a" * 32, "advisory_schema_version": 2},
        "generated_at": AT,
        "records": [],
        "counts": {"advisories": 7},
    }
    (generation / "snapshot.json").write_text(json.dumps(old))
    (tmp_path / "current").symlink_to(generation)
    _, read = Application(tmp_path).store.read()
    assert read["current_evidence"]["availability"] == "unavailable"
    assert read["current_evidence"]["counts"] == {
        "current": None,
        "retained_total": None,
        "excluded": None,
    }
    assert read["counts"]["advisories"] == 7


def test_public_writer_rejects_missing_report_and_private_input(delivery, tmp_path):
    from infrastructure_impact.application.publication import write_bundle

    data = copy.deepcopy(delivery)
    data["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    data["current_evidence"]["publication"] = data["publication"]
    projected = public_projection(data)
    broken = copy.deepcopy(projected)
    broken.pop("current_evidence")
    with pytest.raises((ValueError, KeyError)):
        write_bundle(tmp_path / "bad", broken)
    projected["research"]["current_evidence_input"] = {"sources": [], "selections": []}
    with pytest.raises(ValueError, match="Private"):
        write_bundle(tmp_path / "private", projected)


def test_shared_rebuild_ignores_cached_coverage_and_catalogue(delivery):
    from infrastructure_impact.application.current_views import rebuild

    before = copy.deepcopy(delivery)
    data = copy.deepcopy(delivery)
    data["research"].pop("current_evidence_input")
    data["catalogue"]["vendors"][0]["advisories"] = 999
    for row in data["coverage"]:
        row["state"] = "assessment_available"
        row["advisory_sources"] = [CSAF]
    partition_result = {k: data[k] for k in ("records", "retained_advisories", "current_evidence")}
    result = rebuild(data, partition_result)
    assert (
        next(v for v in result["catalogue"]["vendors"] if v["vendor"] == "cisco")["advisories"] == 0
    )
    assert next(r for r in result["coverage"] if r["vendor"] == "cisco")["state"] == "not_checked"
    assert all(CSAF not in r["advisory_sources"] for r in result["coverage"])
    assert delivery == before


@pytest.mark.parametrize("command", ["evaluate", "validation", "switching-validation"])
def test_cli_current_validation_excludes_retained_source(delivery_db, monkeypatch, capsys, command):
    from infrastructure_impact import cli
    from infrastructure_impact.application import (
        evaluation,
        extraction_validation,
        switching_validation,
    )
    from infrastructure_impact.storage import repository

    excluded = next(r for r in repository.latest(delivery_db) if r["source_url"] == CSAF)
    definition = {
        "cases": [
            {
                "id": "synthetic-excluded",
                "vendor": "arista",
                "source_url": CSAF,
                "source_sha256": excluded["sha256"],
                "cve_id": "CVE-2023-5501",
                "product_pattern": "EOS",
                "expected_status": "affected",
                "source_locator": "synthetic",
            }
        ],
        "limitations": [],
        "reviewed_at": AT,
        "review_method": "synthetic",
        "sample_strategy": "synthetic",
    }
    original = evaluation.evaluate
    monkeypatch.setattr(
        evaluation,
        "evaluate",
        lambda records, **kw: original(records, definition=kw.pop("definition", definition), **kw),
    )
    monkeypatch.setattr(extraction_validation, "definition", lambda: definition)
    monkeypatch.setattr(switching_validation, "definition", lambda: definition)
    # The command reads the real synthetic database; it never opens an ambient vault.
    clone = connect(":memory:")
    delivery_db.backup(clone)
    monkeypatch.setattr(repository, "connect", lambda **kw: clone)
    cli.main([command])
    result = json.loads(capsys.readouterr().out)
    assert result["cases"][0]["outcome"] == "current_scope_excluded"
    assert result["cases"][0]["decision_ids"]
    assert result["passed"] == 0


def test_historical_cve_keeps_kev_context_without_current_vendor_claim(delivery):
    data = copy.deepcopy(delivery)
    data["records"] = [r for r in data["records"] if r["advisory_id"] != "UNRELATED-SAME-CVE"]
    # Author a fresh retained inventory, leaving the private proof graph intact.
    data.pop("current_evidence")
    excluded = data.pop("retained_advisories")[0]["record"]
    data["records"].append(excluded)
    projected = public_projection(data)
    assert projected["all_cves"] == ["CVE-2024-6858"]
    assert "CVE-2023-5501" in projected["kev"]["selection"]["requested_cve_ids"]
    assert not any(
        a["cve_id"] == "CVE-2023-5501" for r in projected["records"] for a in r["assessments"]
    )


def test_retained_csv_escapes_formula_cells(delivery):
    from infrastructure_impact.exports import retained_csv_export

    delivery["retained_advisories"][0]["record"]["assessments"][0]["product"] = "=1+1"
    row = list(csv.DictReader(io.StringIO(retained_csv_export(delivery))))[0]
    assert row["product"] == "'=1+1"


def test_private_frames_never_reach_public_artifacts_or_logs(delivery, tmp_path, capsys):
    import base64

    from infrastructure_impact.exports import assessment_export, retained_assessment_export

    before = copy.deepcopy(delivery)
    frames = delivery["research"]["current_evidence_input"]["sources"]
    generated = publish(delivery, tmp_path / "publications")
    for artifact in generated.rglob("*"):
        if artifact.is_file():
            raw = artifact.read_bytes()
            assert b"PRIVATE_BODY_SENTINEL_DO_NOT_PUBLISH" not in raw
            assert b"raw_b64" not in raw
            assert b"current_evidence_input" not in raw
            for frame in frames:
                assert frame["raw_b64"].encode() not in raw
                assert base64.b64decode(frame["raw_b64"]) not in raw
    for exported in (assessment_export(delivery), retained_assessment_export(delivery)):
        assert "current_evidence_input" not in json.dumps(exported)
    logs = capsys.readouterr()
    assert "raw_b64" not in logs.out + logs.err
    assert delivery == before


def test_hook_diagnostics_are_not_exposed(delivery, monkeypatch, capsys):
    import infrastructure_impact.plugins.arista_current_evidence as policy

    def broken(*args):
        raise RuntimeError("PRIVATE_FREE_FORM_HOOK_DIAGNOSTIC")

    monkeypatch.setattr(policy, "_proofs", broken)
    with pytest.raises(ValueError) as error:
        public_projection(delivery)
    assert "PRIVATE_FREE_FORM_HOOK_DIAGNOSTIC" not in str(error.value)
    logs = capsys.readouterr()
    assert "PRIVATE_FREE_FORM_HOOK_DIAGNOSTIC" not in logs.out + logs.err


def test_public_decision_binds_literal_typed_target_without_browser_hash(delivery):
    from infrastructure_impact.application.current_evidence import validate_report

    report = copy.deepcopy(delivery["current_evidence"])
    decision = report["decisions"][0]
    record = delivery["retained_advisories"][0]["record"]
    assert decision.get("target") == {
        k: record[k] for k in ("vendor", "advisory_id", "revision_id", "source_url", "sha256")
    }
    decision["target"]["revision_id"] = str(decision["target"]["revision_id"])
    with pytest.raises(ValueError):
        validate_report(report)


def test_original_blind_packet_and_frozen_definitions_are_preserved(delivery):
    from infrastructure_impact.application.extraction_validation import review_packet
    from infrastructure_impact.settings import PACKAGE

    names = (
        "benchmark-cases.json",
        "extraction-review.json",
        "switching-extraction-review.json",
        "switching-study.json",
    )
    before = {name: (PACKAGE / "resources" / name).read_bytes() for name in names}
    union = delivery["records"] + [w["record"] for w in delivery["retained_advisories"]]
    original_packet = review_packet(union)
    projected = public_projection(delivery)
    assert projected["review_packet"] == original_packet
    assert projected["evidence_scopes"]["review_packet"] == "retained_review_context"
    assert projected["evidence_scopes"]["changes"] == "retained_history"
    assert any(
        c.get("advisory_id") == "Arista Networks Security Advisory 103"
        for c in projected["changes"]
    )
    assert CSAF in json.dumps(projected["source_audit"])
    assert {name: (PACKAGE / "resources" / name).read_bytes() for name in names} == before


def test_large_integer_revision_is_preserved_in_target_and_wrapper(delivery):
    data = copy.deepcopy(delivery)
    excluded = data.pop("retained_advisories")[0]["record"]
    excluded["revision_id"] = 9007199254740993
    data["records"].append(excluded)
    data.pop("current_evidence")
    projected = public_projection(data)
    assert projected["retained_advisories"][0]["record"]["revision_id"] == 9007199254740993
    assert (
        projected["current_evidence"]["decisions"][0]["target"]["revision_id"] == 9007199254740993
    )
    encoded = json.dumps(projected)
    assert "9007199254740993" in encoded


def test_new_bundle_requires_explicit_wrapper_target_reference(delivery, tmp_path):
    from infrastructure_impact.application.publication import write_bundle

    publication = {"id": "a" * 32, "advisory_schema_version": 2}
    data = copy.deepcopy(delivery)
    data["publication"] = publication
    data["current_evidence"]["publication"] = publication
    projected = public_projection(data)
    projected["retained_advisories"][0].pop("target_key")
    with pytest.raises(ValueError, match="target"):
        write_bundle(tmp_path / "bad-reference", projected)


def test_new_api_controls_remain_bounded_and_read_only(delivery, tmp_path):
    from infrastructure_impact.http import BadRequest

    root = tmp_path / "publications"
    publish(delivery, root)
    app = Application(root)
    path = "/api/v1/retained-advisories"
    for query in (
        "limit=501",
        "limit=0",
        "offset=-1",
        "limit=1&limit=2",
        "format=raw",
        "format=json&format=csv",
        "vendor=unknown",
        "cves=" + ",".join("CVE-2025-" + str(n) for n in range(10000, 10201)),
    ):
        with pytest.raises(BadRequest):
            app.route({"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": query})
    for route in (path, "/api/v1/current-evidence"):
        status, _, _ = app.route({"REQUEST_METHOD": "POST", "PATH_INFO": route, "QUERY_STRING": ""})
        assert status == 405
        headers = []
        body = app(
            {"REQUEST_METHOD": "HEAD", "PATH_INFO": route, "QUERY_STRING": ""},
            lambda status, fields: headers.append((status, dict(fields))),
        )
        assert body == [b""]
        assert headers[0][0] == "200 OK"
        assert int(headers[0][1]["Content-Length"]) > 0
    status, _, body = app.route(
        {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": "offset=1&limit=500"}
    )
    page = json.loads(body)
    assert status == 200 and page["items"] == [] and page["total"] == 1


def test_cached_switching_report_is_rebuilt_from_current_public_input(delivery):
    from infrastructure_impact.settings import PACKAGE

    data = copy.deepcopy(delivery)
    cached = json.loads((PACKAGE.parent / "tests/fixtures/switching-cases.json").read_text())[
        "comparison_base_report"
    ]["inputs"]["evidence"]
    excluded = data["retained_advisories"][0]["record"]
    claim = next(c for c in cached["claims"] if c["vendor"] == "arista")
    claim.update(advisory_id=excluded["advisory_id"], cve_id="CVE-2023-5501")
    claim["source"].update(source_url=excluded["source_url"], source_sha256=excluded["sha256"])
    unrelated = copy.deepcopy(claim)
    unrelated.update(advisory_id="UNRELATED-SAME-CVE", scores=[])
    unrelated["publisher"]["id"] = "UNRELATED-SAME-CVE"
    # The same CVE remains a current, independently owned statement.
    cached["claims"] = [claim, unrelated]
    data["research"].pop("switching_input")
    data["switching_evidence"] = cached
    data["switching_comparison"] = {"stale_cache_marker": True}
    projected = public_projection(data)
    assert "stale_cache_marker" not in projected["switching_comparison"]
    assert [c["advisory_id"] for c in projected["switching_evidence"]["claims"]] == [
        "UNRELATED-SAME-CVE"
    ]


def test_uninstalled_vendor_stays_current_without_policy_or_private_proof(delivery):
    from infrastructure_impact.application.current_evidence import partition
    from infrastructure_impact.plugins.registry import default_registry

    record = copy.deepcopy(delivery["records"][0])
    record.update(vendor="external-example", source_url="https://external.example/advisory")
    result = partition(
        [record],
        {"selections": [], "sources": []},
        registry=default_registry(),
        publication=None,
        generated_at=AT,
    )
    assert result["records"] == [record]
    assert result["current_evidence"]["policies"] == []
    assert result["retained_advisories"] == []
    context = copy.deepcopy(delivery["research"]["current_evidence_input"])
    with pytest.raises(ValueError):
        partition([record], context, registry=default_registry(), publication=None, generated_at=AT)


def test_uninstalled_vendor_cannot_inherit_supplied_exclusion(delivery):
    data = copy.deepcopy(delivery)
    data["retained_advisories"][0]["record"]["vendor"] = "external-example"
    data["research"]["current_evidence_input"] = {"selections": [], "sources": []}
    with pytest.raises(ValueError):
        public_projection(data)


@pytest.mark.parametrize("revision", [None, "9999"])
def test_switching_shared_bytes_require_unambiguous_record_ownership(delivery, revision):
    from infrastructure_impact.application.current_views import rebuild

    data = copy.deepcopy(delivery)
    record = copy.deepcopy(data["retained_advisories"][0]["record"])
    record["revision_id"] = 9999
    data["records"].append(record)
    data["current_evidence"]["counts"]["current"] += 1
    data["current_evidence"]["counts"]["retained_total"] += 1
    data["research"]["switching_input"]["claims"] = [
        {
            "vendor": record["vendor"],
            "advisory_id": record["advisory_id"],
            "revision": revision,
            "source": {"source_url": record["source_url"], "source_sha256": record["sha256"]},
        }
    ]
    result = {k: data[k] for k in ("records", "retained_advisories", "current_evidence")}
    if revision is None:
        with pytest.raises(ValueError, match="ownership"):
            rebuild(data, result)
    else:
        rebuilt = rebuild(data, result)
        assert rebuilt["research"]["switching_input"]["claims"][0]["revision"] == "9999"


@pytest.mark.parametrize("command", ["validation", "switching-validation"])
def test_blind_packet_cli_uses_retained_context_without_policy(
    delivery_db, monkeypatch, capsys, command
):
    from infrastructure_impact import cli
    from infrastructure_impact.application import query
    from infrastructure_impact.application.extraction_validation import review_packet
    from infrastructure_impact.application.switching_validation import packet
    from infrastructure_impact.storage import repository

    records = repository.latest(delivery_db)
    expected = (packet if command == "switching-validation" else review_packet)(records)
    clone = connect(":memory:")
    delivery_db.backup(clone)
    monkeypatch.setattr(repository, "connect", lambda **kw: clone)

    def forbidden(*args, **kwargs):
        raise AssertionError("Retained blind packets must not execute current policy")

    monkeypatch.setattr(query, "current_partition", forbidden)
    cli.main([command, "--packet"])
    assert json.loads(capsys.readouterr().out) == expected
