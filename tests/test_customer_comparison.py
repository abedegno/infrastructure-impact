"""Customer composition uses synthetic, already validated public study facts."""

import copy
import csv
import importlib
import io
import json

import pytest
from jsonschema import ValidationError
from test_kev_delivery import request
from test_static_delivery import dataset
from test_switching_aruba_fix_links import projected, reidentify
from test_switching_release_history import build as history
from test_switching_release_history import frame, study

from infrastructure_impact.application import publication, switching_comparison, switching_releases
from infrastructure_impact.application.publication_reader import PublicationReader
from infrastructure_impact.http import Application


def api():
    return importlib.import_module("infrastructure_impact.application.customer_comparison")


def selected(**options):
    ev = projected()
    summary = study(ev, **options)
    return summary, switching_releases.select_report(history(ev, [frame()]), summary)


def test_envelope_preserves_selected_study_and_sparse_history_without_new_counts():
    summary, releases = selected(vendor="aruba", window="2024")
    result = api().build(summary, releases)
    assert set(result) == {
        "schema_version",
        "publication",
        "generated_at",
        "study",
        "release_history",
        "limitations",
    }
    assert result["schema_version"] == 1
    assert result["study"] == summary
    assert result["release_history"] == releases
    assert result["study"]["rows"][0]["counts"]["affected_cves"] == 1
    assert len(result["release_history"]["sources"]) == 5
    assert result["limitations"]
    result["study"]["rows"].clear()
    assert summary["rows"]  # Composition cannot mutate its retained inputs.


def test_missing_history_preserves_study_with_matching_unavailable_envelope():
    summary, _ = selected(vendor="aruba")
    missing = switching_releases.select_report(None, summary)
    result = api().build(summary, missing)
    assert result["study"] == summary
    assert result["release_history"]["availability"] == "unavailable"
    assert result["release_history"]["selection"] == summary["selection"]


@pytest.mark.parametrize("field", ["publication", "generated_at", "selection", "observation_end"])
def test_mixed_history_identity_or_selection_is_rejected(field):
    summary, releases = selected(vendor="aruba")
    if field == "publication":
        summary[field] = {"id": "f" * 32, "advisory_schema_version": 2}
    elif field == "generated_at":
        summary[field] = "2026-10-01T00:00:00Z"
    elif field == "selection":
        releases = switching_releases.select_report(history(projected()), study(projected()))
    else:
        releases[field] = "2026-01-01"
    with pytest.raises(ValueError):
        api().build(summary, releases)


def test_envelope_rejects_private_extensions_and_full_study_inputs():
    summary, releases = selected()
    for target in (summary, releases):
        bad = copy.deepcopy(target)
        bad["private"] = "PRIVATE_SENTINEL"
        with pytest.raises(ValidationError):
            api().build(
                bad if target is summary else summary, bad if target is releases else releases
            )
    full = dict(summary, inputs={"private": "PRIVATE_SENTINEL"})
    with pytest.raises(ValidationError):
        api().build(full, releases)


def test_fixed_only_context_cannot_increase_affected_or_event_counts():
    ev = projected()
    ev["claims"] = [c for c in ev["claims"] if c["status"] == "fixed"]
    reidentify(ev)
    summary = study(ev, vendor="aruba", window="2024")
    result = api().build(summary, switching_releases.select_report(history(ev), summary))
    row = result["study"]["rows"][0]
    assert row["counts"]["affected_cves"] == row["counts"]["remediation_events"] == 0
    assert any(
        r["vendor_reported_fixed_cve_count"] == 1 for r in result["release_history"]["releases"]
    )
    assert all(r["affected_scope_cve_count"] is None for r in result["release_history"]["releases"])


def test_csv_has_separate_context_rows_unknown_counts_and_safe_spreadsheet_cells():
    summary, releases = selected(vendor="aruba", window="2024")
    result = api().build(summary, releases)
    # A literal advisory identity may begin with spreadsheet control syntax.
    for node in result["release_history"]["releases"]:
        for ref in node["references"]:
            ref["advisory_id"] = "=SYNTHETIC()"
    rows = list(csv.DictReader(io.StringIO(api().csv_export(result))))
    assert {r["row_type"] for r in rows} >= {
        "study_summary",
        "release_reference",
        "source_coverage",
    }
    assert all(r["totals_basis"] == "repeated_totals_nonadditive" for r in rows)
    fixed = next(r for r in rows if r["version"] == "10.14.0007")
    assert fixed["vendor_reported_fixed_cve_count"] == "1"
    assert fixed["affected_scope_cve_count"] == "1"
    assert fixed["advisory_id"] == "'=SYNTHETIC()"
    context = next(r for r in rows if r["version"] == "10.14.0001")
    assert context["affected_scope_cve_count"] == ""
    with pytest.raises(ValueError):
        api().csv_export(result, max_bytes=100)


@pytest.fixture(params=["v1", "v2"])
def published(tmp_path, request):
    data = dataset()
    data["research"]["switching_input"] = projected()
    data["research"]["release_input"] = [frame()]
    root = tmp_path / "public"
    out = publication.publish(data, root, publication_format=request.param)
    return root, out, request.param


@pytest.mark.parametrize(
    "query",
    [
        "",
        "vendor=aruba&window=2024",
        "scope=model_qualified",
        "cves=CVE-1999-99999",
        "format=csv",
        "format=json&vendor=aruba",
    ],
)
def test_native_json_csv_use_existing_study_and_selected_history(published, query):
    root, out, fmt = published
    app = Application(root)
    code, raw = request(app, "/api/v1/customer-comparison", query)
    assert code == 200, raw
    study_query = query.replace("format=csv", "format=json")
    code, study_raw = request(app, "/api/v1/switching-comparison", study_query)
    assert code == 200
    summary = json.loads(study_raw)
    if fmt == "v2":
        reader = PublicationReader(out)
        if query in ("", "format=csv"):
            overview = reader.switching_overview(evaluated_at=summary["evaluated_at"])
            for overview_row, summary_row in zip(overview["rows"], summary["rows"]):
                for key in ("counts", "severity", "kev", "coverage", "affected_cve_ids"):
                    assert overview_row[key] == summary_row[key]
            summary = overview
        releases = reader.switching_release_history(summary)
    else:
        releases = switching_releases.select_report(
            json.loads((out / "switching-release-history.json").read_text()), summary
        )
    expected = api().build(summary, releases)
    if "format=csv" in query:
        assert raw.decode() == api().csv_export(expected)
    else:
        actual = json.loads(raw)
        actual["study"]["evaluated_at"] = summary["evaluated_at"]
        assert actual == expected
    assert request(app, "/schemas/customer-comparison-v1.json")[0] == 200
    assert request(app, "/schemas/switching-release-history-v1.json")[0] == 200


@pytest.mark.parametrize(
    "query",
    [
        "vendor=aruba&vendor=aruba",
        "scope=",
        "window=2020",
        "format=csv&format=json",
        "unknown=x",
        "kev=listed",
        "cve=CVE-2024-6387",
        "cves=cve-2024-6387",
        "cves=CVE-2024-6387,CVE-2024-6387",
        "format=xml",
    ],
)
def test_native_customer_rejects_unknown_duplicate_or_invalid_study_queries(published, query):
    assert request(Application(published[0]), "/api/v1/customer-comparison", query)[0] == 400


def test_v2_customer_stays_metadata_first_and_selects_study_only_once(published, monkeypatch):
    root, out, fmt = published
    if fmt != "v2":
        pytest.skip("v2 reader bounds")
    reader = PublicationReader(out)
    original = reader.switching_selection
    selections = []

    def select(options, **kwargs):
        selections.append(options)
        return original(options, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("customer API hydrated a generic/full report")

    monkeypatch.setattr(reader, "runtime_snapshot", forbidden)
    monkeypatch.setattr(reader, "switching_selection", select)
    original_materialize = reader.materialize_range

    def bounded(bound, **kwargs):
        if bound["root"] in {"runtime-snapshot", "switching-comparison.json"}:
            assert bound != reader.ranges(bound["root"])[()]
        return original_materialize(bound, **kwargs)

    monkeypatch.setattr(reader, "materialize_range", bounded)
    code, _, raw = Application(root)._route_v2(
        {"PATH_INFO": "/api/v1/customer-comparison", "QUERY_STRING": "vendor=aruba&window=2024"},
        out,
        reader,
    )
    assert code == 200 and json.loads(raw)["study"]["rows"][0]["counts"]["affected_cves"] == 1
    assert len(selections) == 1
    assert reader.read_bytes < 2_000_000


def test_native_old_history_keeps_study_and_mixed_history_fails(published):
    root, out, fmt = published
    app = Application(root)
    generation, data = app.store.open()
    if fmt == "v2":
        data.catalog["roots"].pop("switching-release-history.json")
    else:
        (out / "switching-release-history.json").unlink()
    code, _, raw = app.route(
        {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/customer-comparison"},
        _opened=(generation, data),
    )
    assert code == 200
    value = json.loads(raw)
    assert value["study"]["availability"] == "available"
    assert value["release_history"]["availability"] == "unavailable"
    if fmt == "v1":
        bad = switching_releases.select_report(None, value["study"])
        bad["generated_at"] = "2026-01-01T00:00:00Z"
        (out / "switching-release-history.json").write_text(json.dumps(bad))
        assert request(app, "/api/v1/customer-comparison")[0] == 503


def test_csv_retains_study_row_cve_sets_provider_facets_and_kev_without_recounting():
    from test_switching_comparison import AT, FIXTURE, claim, report

    c = claim()
    base = copy.deepcopy(FIXTURE["evidence"]["claims"][0]["scores"][0])
    c["scores"] = [
        dict(base, value=0, provider="vendor", preferred=True),
        dict(base, value=9.8, provider="other", preferred=False),
    ]
    family_only = claim(
        "B", cid="CVE-2026-98765", scope_level="os_family", named_platforms=[], platform_bindings=[]
    )
    full = report([c, family_only])
    for scope, affected, unknown in [("os_family", 2, 2), ("model_qualified", 1, 1)]:
        summary = switching_comparison.summary(
            switching_comparison.select_report(
                full, vendor="arista", scope_level=scope, evaluated_at=AT
            )
        )
        result = api().build(summary, switching_releases.select_report(None, summary))
        row = result["study"]["rows"][0]
        assert row["counts"]["affected_cves"] == affected
        assert row["kev"]["unknown_count"] == unknown
        assert {(f["provider"], f["band"]) for f in row["severity"]} >= {
            ("vendor", "None"),
            ("other", "Critical"),
        }
        rows = list(csv.DictReader(io.StringIO(api().csv_export(result))))
        study_rows = [r for r in rows if r["row_type"] == "study_summary"]
        assert {r["severity_provider"] for r in study_rows} >= {"vendor", "other"}
        assert all(json.loads(r["details"]) == row for r in study_rows)
        assert all(r["affected_cves"] == str(affected) for r in study_rows)
        assert all(r["kev_unknown"] == str(unknown) for r in study_rows)


def test_csv_keeps_bundle_and_sku_context_separate_from_release_references():
    from test_software_release_sources import ARISTA, MODELS, bundle, models

    from infrastructure_impact.references import software_releases as sources

    ev = projected()
    summary = study(ev)
    root = history(
        ev,
        [
            frame(ARISTA, sources.parse_arista_0148(bundle())),
            frame(MODELS, sources.parse_aruba_support_10_14(models())),
        ],
    )
    selected_history = switching_releases.select_report(root, summary)
    result = api().build(summary, selected_history)
    rows = list(csv.DictReader(io.StringIO(api().csv_export(result))))
    bundles = [json.loads(r["details"]) for r in rows if r["row_type"] == "bundle_context"]
    support = [json.loads(r["details"]) for r in rows if r["row_type"] == "platform_support"]
    assert bundles == selected_history["bundles"] and bundles
    assert support == selected_history["platform_support"] and support
    assert bundles[0]["initial_published_at"] == "2026-09-02"
    assert bundles[0]["member_publication_date"] == "2026-09-09"
    assert all(
        not r["reported_release_dates"]
        for r in rows
        if r["row_type"] in {"bundle_context", "platform_support"}
    )


def test_v2_mixed_history_body_fails_before_release_array_read(tmp_path, monkeypatch):
    from infrastructure_impact.application import publication_v2

    data = dataset()
    data["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    data["current_evidence"]["publication"] = data["publication"]
    data["research"]["switching_input"] = projected()
    data["research"]["release_input"] = [frame()]
    public = publication.public_projection(data, publication_format="v2")
    public["switching_release_history"]["generated_at"] = "2026-01-01T00:00:00Z"
    out = tmp_path / "malformed-publication"
    out.mkdir()
    # Bypass the validating publication boundary to simulate a foreign logical asset
    # inside otherwise correctly hashed v2 transport envelopes.
    from infrastructure_impact.application.switching_row_sources import derive

    publication_v2._write_bundle(out, public, derive(public["switching_comparison"]))
    reader = PublicationReader(out)
    original = reader.materialize_range

    history_reads = []

    def reject_full_history(bound, **kwargs):
        if bound["root"] == "switching-release-history.json":
            history_reads.append(kwargs.get("path"))
        return original(bound, **kwargs)

    monkeypatch.setattr(reader, "materialize_range", reject_full_history)
    app = Application(tmp_path)
    monkeypatch.setattr(app.store, "open", lambda: (out, reader))
    assert request(app, "/api/v1/customer-comparison")[0] == 503
    assert history_reads == [("publication",), ("generated_at",)]


def test_customer_csv_reserves_actual_utf8_output_limit():
    summary, releases = selected(vendor="aruba")
    result = api().build(summary, releases)
    raw = api().csv_export(result)
    size = len(raw.encode("utf-8"))
    assert api().csv_export(result, max_bytes=size) == raw
    with pytest.raises(ValueError):
        api().csv_export(result, max_bytes=size - 1)


@pytest.mark.parametrize(
    "literal", ["=SYNTHETIC()", " +SUM(1)", "-1", "@name", "\tname", "\rname", "\nname"]
)
def test_customer_csv_reuses_spreadsheet_escape_policy(literal):
    summary, releases = selected(vendor="aruba")
    for node in releases["releases"]:
        for ref in node["references"]:
            ref["advisory_id"] = literal
    rows = list(csv.DictReader(io.StringIO(api().csv_export(api().build(summary, releases)))))
    refs = [
        r
        for r in rows
        if r["row_type"] == "release_reference" and r["reference_kind"] != "history_context"
    ]
    assert refs and all(r["advisory_id"] == "'" + literal for r in refs)


def test_customer_preserves_fresh_listed_and_stale_unknown_kev_membership():
    from test_switching_comparison import AT, claim, report

    from infrastructure_impact.settings import PACKAGE

    kev = json.loads((PACKAGE.parent / "tests/fixtures/kev-selection-cases.json").read_text())[
        "base_report"
    ]
    kev.update(publication=None, generated_at=AT, evaluated_at=AT)
    kev["source"]["checked_at"] = AT
    kev["source"]["latest_attempt"]["checked_at"] = AT
    full = report([claim(cid="CVE-2099-99999")])
    full = switching_comparison.build_report(
        full["inputs"]["evidence"],
        kev,
        definition=full["definition"],
        publication=None,
        generated_at=AT,
        observation_end="2026-11-04",
    )
    for evaluated, listed, unknown in [(AT, 1, 0), ("2026-11-07T10:00:00Z", 0, 1)]:
        summary = switching_comparison.summary(
            switching_comparison.select_report(full, vendor="arista", evaluated_at=evaluated)
        )
        result = api().build(summary, switching_releases.select_report(None, summary))
        row = result["study"]["rows"][0]
        assert (row["kev"]["listed_count"], row["kev"]["unknown_count"]) == (listed, unknown)
        csv_rows = list(csv.DictReader(io.StringIO(api().csv_export(result))))
        assert all(
            (r["kev_listed"], r["kev_unknown"]) == (str(listed), str(unknown))
            for r in csv_rows
            if r["row_type"] == "study_summary"
        )


def test_real_v2_overview_composes_and_exports_without_deferred_claim_reads(published, monkeypatch):
    _, out, fmt = published
    if fmt != "v2":
        pytest.skip("v2 overview contract")
    reader = PublicationReader(out)

    def forbidden(*args, **kwargs):
        pytest.fail("overview composition hydrated deferred study facts")

    monkeypatch.setattr(reader, "iter_claims", forbidden)
    monkeypatch.setattr(reader, "switching_selection", forbidden)
    monkeypatch.setattr(reader, "runtime_snapshot", forbidden)
    overview = reader.switching_overview()
    assert overview["schema_version"] == 2
    assert overview["representation"] == "switching-overview"
    assert "claim_ids" not in overview["rows"][0]
    result = api().build(overview, reader.switching_release_history(overview))
    assert result["study"] == overview
    relabelled = copy.deepcopy(overview)
    relabelled.update(schema_version=1, representation="summary")
    with pytest.raises(ValidationError):
        api().build(relabelled, reader.switching_release_history(overview))
    rows = list(csv.DictReader(io.StringIO(api().csv_export(result))))
    assert all(
        row["study_representation"] == "switching-overview" and row["study_schema_version"] == "2"
        for row in rows
    )
    assert all(
        "claim_ids" not in json.loads(row["details"])
        for row in rows
        if row["row_type"] == "study_summary"
    )


def test_default_v2_customer_route_uses_overview_without_claim_scan(published, monkeypatch):
    root, out, fmt = published
    if fmt != "v2":
        pytest.skip("v2 overview fast path")
    reader = PublicationReader(out)

    def forbidden(*args, **kwargs):
        pytest.fail("default customer request scanned study claims")

    monkeypatch.setattr(reader, "iter_claims", forbidden)
    monkeypatch.setattr(reader, "runtime_snapshot", forbidden)
    monkeypatch.setattr(reader, "switching_selection", forbidden)
    for query in ("", "format=csv", "scope=os_family&window=all&format=json"):
        code, _, raw = Application(root)._route_v2(
            {"PATH_INFO": "/api/v1/customer-comparison", "QUERY_STRING": query}, out, reader
        )
        assert code == 200
        if "format=csv" not in query:
            assert json.loads(raw)["study"]["representation"] == "switching-overview"
    assert "switching-evidence.json" not in reader._roots


def test_exported_customer_schema_validates_using_only_publication_schemas(published):
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource

    root, out, _ = published
    schemas = {}
    for path in (out / "schemas").glob("*.json"):
        schema = json.loads(path.read_text())
        if path.name == "kev-v1.json":
            schema["$id"] = "urn:infrastructure-impact:kev:1"
        schemas[path.name] = schema
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema))
        for schema in schemas.values()
        if "$id" in schema
    )
    validator = Draft202012Validator(
        schemas["customer-comparison-v1.json"], registry=registry, format_checker=FormatChecker()
    )
    app = Application(root)
    for query in ("", "vendor=aruba"):
        status, raw = request(app, "/api/v1/customer-comparison", query)
        assert status == 200
        validator.validate(json.loads(raw))
    for name in (
        "customer-comparison-v1.json",
        "switching-overview-v2.json",
        "publication-v2.json",
    ):
        status, raw = request(app, "/schemas/" + name)
        assert status == 200, name
        assert json.loads(raw) == schemas[name]


def test_native_documented_history_asset_returns_present_root_and_absent_v1_404(published):
    root, out, fmt = published
    asset = out / "switching-release-history.json"
    complete = json.loads(asset.read_text())
    app = Application(root)
    status, raw = request(app, "/switching-release-history.json")
    assert status == 200
    assert json.loads(raw) == complete
    assert json.loads(raw)["selection"] is None
    if fmt == "v1":
        asset.unlink()
        assert request(app, "/switching-release-history.json")[0] == 404
