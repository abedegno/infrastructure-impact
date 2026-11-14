"""Compact source-owned requirements use the native walk without native matrices."""

import copy
import importlib
import json

import pytest
from jsonschema import ValidationError
from test_switching_upgrades import AT, inputs

from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as contracts
from infrastructure_impact.application import switching_upgrades as upgrades


def api():
    return importlib.import_module("infrastructure_impact.application.switching_analysis")


def fixture():
    ev, ff, k = inputs([("2024-12-31", ["17.15.3"]), ("2025-02-01", ["17.15.2"]), (None, [])])
    study = comparison.build_report(
        ev,
        k,
        definition=contracts.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    return ev, ff, k, study


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"vendor": "cisco", "window": "2025"},
        {"scope_level": "model_qualified"},
        {"cve_ids": ["CVE-1999-99999"]},
    ],
)
def test_compact_selection_exact_native_projection(options):
    ev, ff, k, study = fixture()
    selected = comparison.select_report(study, **options, evaluated_at=AT)
    compact = api().compile_requirements(ev, ff, None, k, publication=None, generated_at=AT)
    native = upgrades.build_report(ev, ff, None, k, publication=None, generated_at=AT)
    result = api().select_upgrades(compact, selected)
    assert result == api().project_native(native, selected)
    assert list(api().detailed_rows(result)) == upgrades.select_report(native, selected)["rows"]
    assert len(json.dumps(compact)) < len(json.dumps(native))


def test_compiler_never_builds_native_matrix_and_rejects_tampering(monkeypatch):
    ev, ff, k, study = fixture()

    def forbidden(*args, **kwargs):
        raise AssertionError("native matrix materialized")

    monkeypatch.setattr(upgrades, "build_report", forbidden)
    compact = api().compile_requirements(ev, ff, None, k, publication=None, generated_at=AT)
    api().validate_requirements(compact, evidence=ev)
    bad = copy.deepcopy(compact)
    bad["requirements"][0]["target"] = "17.15.99"
    with pytest.raises(ValueError):
        api().validate_requirements(bad, evidence=ev)
    with pytest.raises(ValueError):
        api().compile_requirements(
            ev, ff, None, k, publication=None, generated_at=AT, max_bytes=100
        )


def test_missing_and_csv_bounds():
    _, _, _, study = fixture()
    missing = api().select_upgrades(None, study)
    assert missing["availability"] == "unavailable"
    assert missing["selection"] == study["selection"]
    with pytest.raises(ValueError):
        api().csv_export(missing, max_bytes=10)


def test_composition_selected_children_match_native_and_private_inputs_stay_out():
    from infrastructure_impact.application import switching_disclosure as disclosure
    from infrastructure_impact.application import switching_model_coverage as models

    ev, ff, k, study = fixture()
    compiled = api().build_report([], [], study, source_frame={})
    for options in ({}, {"vendor": "cisco", "window": "2025"}, {"scope_level": "model_qualified"}):
        selected = comparison.select_report(study, **options, evaluated_at=AT)
        result = api().select_report(compiled, selected)
        assert result["disclosure"] == disclosure.build_report(
            [], selected, evidence=ev, publication=None, generated_at=AT
        )
        assert result["model_coverage"] == models.build_report(
            ev, selected, publication=None, generated_at=AT
        )
    with pytest.raises(ValueError):
        api().build_report([], [], study, source_frame={"private_notes": "PRIVATE_SENTINEL"})


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_optional_publication_delivery_no_bootstrap_leak(tmp_path, fmt):
    from test_kev_delivery import request
    from test_static_delivery import dataset
    from test_switching_aruba_fix_links import projected

    from infrastructure_impact.application import publication
    from infrastructure_impact.application.publication_reader import PublicationReader
    from infrastructure_impact.http import Application

    data = dataset()
    data["research"]["switching_input"] = projected()
    root = tmp_path / "public"
    out = publication.publish(data, root, publication_format=fmt, include_switching_analysis=True)
    app = Application(root)
    for path in ("switching-analysis", "switching-upgrades"):
        code, raw = request(app, "/api/v1/" + path, "vendor=aruba&window=2024")
        assert code == 200, raw
        assert json.loads(raw)["availability"] == "available"
        code, raw = request(app, "/api/v1/" + path, "vendor=aruba&format=csv")
        assert code == 200, raw
        code, raw = request(app, "/api/v1/" + path, "bogus=1")
        assert code == 400
    index = json.loads((out / "data/index.json").read_text())
    bootstrap = json.loads((out / index["bootstrap"]["path"]).read_text())["data"]
    assert "switching_analysis" not in bootstrap
    if fmt == "v2":
        reader = PublicationReader(out)
        assert "switching-analysis.json" in reader.catalog["roots"]

        def forbidden():
            raise AssertionError("full claims hydrated")

        reader.iter_claims = forbidden
        result = reader.switching_analysis(options={"vendor": "aruba", "window": "2024"})
        assert result["selection"]["requested_vendor"] == "aruba"


def test_compact_closed_shape_and_reference_closure_even_with_rehashed_payload():
    ev, ff, k, _ = fixture()
    compact = api().compile_requirements(ev, ff, None, k, publication=None, generated_at=AT)
    for change in ("extra", "reference", "date"):
        bad = copy.deepcopy(compact)
        if change == "extra":
            bad["private_notes"] = "PRIVATE_SENTINEL"
        elif change == "reference":
            bad["requirements"][0]["proof_ref"] = "a" * 64
        else:
            bad["observation_end"] = "2021-01-01"
        bad["content_sha256"] = api()._hash({k: v for k, v in bad.items() if k != "content_sha256"})
        with pytest.raises(ValueError):
            api().validate_requirements(bad)


def test_analysis_composes_owned_chronology_and_csv_children():
    _, _, _, study = fixture()
    compiled = api().build_report([], [], study)
    result = api().select_report(compiled, study)
    assert result["release_history"]["availability"] == "unavailable"
    assert result["release_history"]["selection"] == study["selection"]
    text = api().analysis_csv_export(result)
    assert "upgrade" in text and "model_coverage" in text


def test_disclosure_scope_filters_pair_model_products_and_severity():
    from test_switching_disclosure import claim
    from test_switching_disclosure import inputs as disclosure_inputs

    from infrastructure_impact.application import switching_disclosure as disclosure

    qualified = claim(product_id="qualified")
    family = claim(product_id="family", scope_level="os_family", platform_bindings=[])
    ev, study = disclosure_inputs([family, qualified])
    compiled = api().build_report([], [], study)
    selected = comparison.select_report(
        study, scope_level="model_qualified", evaluated_at=study["generated_at"]
    )
    actual = api().select_report(compiled, selected)["disclosure"]
    expected = disclosure.build_report(
        [], selected, evidence=ev, publication=None, generated_at=study["generated_at"]
    )
    assert actual == expected


def test_nonadvancing_requirement_becomes_event_after_cve_filter():
    ev, ff, k = inputs([("2024-01-01", ["17.15.3"]), ("2025-01-01", ["17.15.2"])])
    claims = copy.deepcopy(ev["claims"])
    claims[1]["cve_id"] = "CVE-2025-99999"
    for remediation in claims[1]["remediations"]:
        if remediation.get("scope_binding"):
            remediation["scope_binding"]["cve_id"] = claims[1]["cve_id"]
    ev = contracts.project(
        dict(claims=claims, coverage=[], issues=[]), publication=None, generated_at=AT
    )
    study = comparison.build_report(
        ev,
        k,
        definition=contracts.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    compact = api().compile_requirements(ev, ff, None, k, publication=None, generated_at=AT)
    selected = comparison.select_report(
        study, cve_ids=["CVE-2025-99999"], window="2025", evaluated_at=AT
    )
    actual = api().select_upgrades(compact, selected)
    native = upgrades.build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert actual == api().project_native(native, selected)
    assert any(r["event_count"] == 1 for r in actual["rows"])


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_old_optional_absence_and_strict_queries(tmp_path, fmt):
    from test_kev_delivery import request
    from test_static_delivery import dataset
    from test_switching_aruba_fix_links import projected

    from infrastructure_impact.application import publication
    from infrastructure_impact.http import Application

    data = dataset()
    data["research"]["switching_input"] = projected()
    root = tmp_path / "public"
    out = publication.publish(data, root, publication_format=fmt)
    assert not (out / "switching-analysis.json").exists()
    app = Application(root)
    for path in ("switching-analysis", "switching-upgrades"):
        code, raw = request(app, "/api/v1/" + path)
        assert code == 200
        assert json.loads(raw)["availability"] == "unavailable"
        for query in (
            "vendor=",
            "vendor=cisco&vendor=cisco",
            "format=yaml",
            "cves=cve-2024-1234",
            "cves=CVE-2024-1234,CVE-2024-1234",
            "scope=unknown",
            "window=1900",
        ):
            code, raw = request(app, "/api/v1/" + path, query)
            assert code == 400, query


def test_optional_source_frame_malformed_is_not_absent():
    _, _, _, study = fixture()
    for value in ([], "", False):
        with pytest.raises(ValueError):
            api().build_report([], [], study, source_frame=value)


def test_schema_registry_openapi_and_local_flag_defaults(monkeypatch):
    from infrastructure_impact import cli
    from infrastructure_impact.application import publication, publication_v2
    from infrastructure_impact.settings import PACKAGE

    calls = []
    monkeypatch.setattr(publication, "build", lambda *args, **kwargs: calls.append((args, kwargs)))
    cli.main(["snapshot"])
    assert calls[-1][1] == {}
    cli.main(["snapshot", "--include-switching-analysis"])
    assert calls[-1][1] == {"include_switching_analysis": True}
    spec = json.loads((PACKAGE / "resources/openapi.json").read_text())
    for route, definition in [
        ("switching-analysis", "selected"),
        ("switching-upgrades", "selected_upgrades"),
    ]:
        endpoint = spec["paths"]["/api/v1/" + route]["get"]
        assert (
            endpoint["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
            == "./schemas/switching-analysis-v1.json#/$defs/" + definition
        )
    _, _, _, study = fixture()
    compiled = api().build_report([], [], study)
    publication_v2.validate(compiled, "switching-analysis-v1.json")
    publication_v2.validate(api().select_report(compiled, study), "switching-analysis-v1.json")


def test_owned_disclosure_metadata_and_kev_absent_vendor_parity():
    from test_switching_disclosure import cisco_owned
    from test_switching_disclosure import inputs as disclosure_inputs
    from test_switching_kev_reconciliation import inputs as kev_inputs

    from infrastructure_impact.application import switching_disclosure as disclosure
    from infrastructure_impact.application import switching_kev_reconciliation as reconciliation

    c, record = cisco_owned()
    ev, study = disclosure_inputs([c])
    record["notes"] = [{"text": "PRIVATE_NOTES_SENTINEL"}]
    compiled = api().build_report([record], [], study)
    assert "PRIVATE_NOTES_SENTINEL" not in json.dumps(compiled)
    for options in ({}, {"vendor": "cisco", "window": "post"}, {"scope_level": "model_qualified"}):
        selected = comparison.select_report(study, **options, evaluated_at=study["generated_at"])
        assert api().select_report(compiled, selected)["disclosure"] == disclosure.build_report(
            [record], selected, evidence=ev, publication=None, generated_at=study["generated_at"]
        )
    k, ev, inventory, study = kev_inputs()
    compiled = api().build_report([], [], study)
    for options in ({}, {"cve_ids": ["CVE-2025-99999"]}, {"vendor": "cisco"}):
        selected = comparison.select_report(study, **options, evaluated_at=study["generated_at"])
        expected = reconciliation.build_report(
            k,
            study["definition"],
            ev,
            inventory,
            publication=None,
            generated_at=study["generated_at"],
            evaluated_at=study["generated_at"],
            selection=selected,
        )
        assert api().select_report(compiled, selected)["kev_reconciliation"] == expected


@pytest.mark.parametrize(
    "case",
    [
        "test_cisco_inference_is_only_inclusive_and_keeps_heldout_source",
        "test_inference_groups_all_affected_leaf_versions_before_predicting",
        "test_unassigned_migration_cannot_veto_explicit_fixed_train",
        "test_earlier_train_migration_does_not_apply_to_unlisted_later_train",
        "test_shared_bundle_high_metric_does_not_leak_to_selected_low_cve",
    ],
)
def test_compact_oracle_replays_reviewed_source_cases(monkeypatch, case):
    import test_switching_upgrades as vectors

    original = upgrades.build_report

    def checked(ev, ff, history, k, **identity):
        native = original(ev, ff, history, k, **identity)
        compact = api().compile_requirements(ev, ff, history, k, **identity)
        study = comparison.build_report(
            ev,
            k,
            definition=contracts.definition(),
            observation_end=identity["generated_at"][:10],
            **identity,
        )
        for options in ({"vendor": "cisco", "window": "2025"}, {"scope_level": "model_qualified"}):
            selected = comparison.select_report(
                study, **options, evaluated_at=identity["generated_at"]
            )
            assert api().select_upgrades(compact, selected) == api().project_native(
                native, selected
            )
        return native

    monkeypatch.setattr(upgrades, "build_report", checked)
    getattr(vectors, case)()


def test_portable_vectors_exact_json_and_csv():
    from pathlib import Path

    vectors = json.loads(
        (Path(__file__).parent / "fixtures/switching-analysis-vectors.json").read_text()
    )
    for vector in vectors["numeric_cases"]:
        assert api().analysis_csv_export(vector["selected"]) == vector["expected"]
    for case in vectors["cases"]:
        context = api().selection_context(vectors["compiled"], case["options"])
        assert context == case["context"]
        result = api().select_report(vectors["compiled"], context)
        assert result == case["expected"]
        assert api().csv_export(result["upgrades"]) == case["upgrades_csv"]
        assert api().analysis_csv_export(result) == case["analysis_csv"]


def test_writer_rejects_rebound_current_reference_and_malformed_present(tmp_path):
    from test_static_delivery import dataset
    from test_switching_aruba_fix_links import projected

    from infrastructure_impact.application import publication

    data = dataset()
    data["research"]["switching_input"] = projected()
    data["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    data["current_evidence"]["publication"] = data["publication"]
    public = publication.public_projection(data, include_switching_analysis=True)
    for mutation in ("generation", "claim"):
        bad = copy.deepcopy(public)
        report = bad["switching_analysis"]
        if mutation == "generation":
            report["generated_at"] = "2026-01-01T00:00:00Z"
        else:
            member = next(iter(report["claims"].values()))
            member["claim_sha256"] = "b" * 64
        report["content_sha256"] = api()._hash(
            {k: v for k, v in report.items() if k != "content_sha256"}
        )
        with pytest.raises(ValueError):
            publication.write_bundle(tmp_path / mutation, bad)


def test_selected_output_cannot_mutate_compiled_source_facts():
    _, _, _, study = fixture()
    compiled = api().build_report([], [], study)
    before = copy.deepcopy(compiled)
    result = api().select_report(compiled, study)
    result["upgrades"]["requirements"]["kev_context"]["source"]["availability"] = "available"
    assert compiled == before


def test_current_reference_gate_rejects_removed_owned_claim_even_with_fresh_digests():
    ev, ff, k, _ = fixture()
    compact = api().compile_requirements(ev, ff, None, k, publication=None, generated_at=AT)
    cid = next(iter(compact["members"]))
    compact["members"].pop(cid)
    compact["requirements"] = [r for r in compact["requirements"] if r["claim_id"] != cid]
    compact["membership_count"] = len(compact["members"])
    compact["membership_sha256"] = api()._hash(compact["members"])
    compact["content_sha256"] = api()._hash(
        {k: v for k, v in compact.items() if k != "content_sha256"}
    )
    with pytest.raises(ValueError, match="complete"):
        api().validate_requirements(compact, evidence=ev)


def test_explicit_local_source_frame_cli_and_absent_calibration(tmp_path, monkeypatch):
    from infrastructure_impact import cli
    from infrastructure_impact.application import publication

    frame = {"policy_source": None, "api_results": [], "calibration_records": []}
    path = tmp_path / "analysis-input.json"
    path.write_text(json.dumps(frame))
    calls = []
    monkeypatch.setattr(publication, "build", lambda *args, **kwargs: calls.append(kwargs))
    cli.main(["snapshot", "--include-switching-analysis", "--switching-analysis-input", str(path)])
    assert calls == [{"include_switching_analysis": True, "switching_analysis_input": frame}]
    with pytest.raises(SystemExit):
        cli.main(["snapshot", "--switching-analysis-input", str(path)])
    _, _, _, study = fixture()
    assert api().build_report([], [], study, source_frame=frame) == api().build_report(
        [], [], study
    )


@pytest.mark.parametrize("payload", ["null", "duplicate", "oversize"])
def test_v1_present_analysis_is_strict_bounded_and_never_absent(tmp_path, monkeypatch, payload):
    from test_kev_delivery import request
    from test_static_delivery import dataset
    from test_switching_aruba_fix_links import projected

    from infrastructure_impact.application import publication
    from infrastructure_impact.http import Application

    data = dataset()
    data["research"]["switching_input"] = projected()
    root = tmp_path / "public"
    generation = publication.publish(data, root, include_switching_analysis=True)
    asset = generation / "switching-analysis.json"
    if payload == "null":
        raw = b"null"
    elif payload == "duplicate":
        raw = asset.read_bytes().replace(
            b'"schema_version": 1,', b'"schema_version": 1, "schema_version": 1,', 1
        )
    else:
        from infrastructure_impact import publication_codec

        monkeypatch.setattr(publication_codec, "MAX_SELECTED", 1024)
        raw = b" " * 1025 + b"null"
    asset.write_bytes(raw)
    app = Application(root)
    for endpoint in ("switching-analysis", "switching-upgrades"):
        code, body = request(app, "/api/v1/" + endpoint)
        assert code >= 500, body


@pytest.mark.parametrize("mutation", ["foreign", "misbound_source", "misbound_cve"])
def test_disclosure_child_closure_rejects_rehashed_refs(mutation):
    ev, _, _, study = fixture()
    bad = api().build_report([], [], study)
    pair = bad["disclosure"]["pairs"][0]
    if mutation == "foreign":
        pair["claim_ids"] = ["f" * 64]
    elif mutation == "misbound_source":
        pair["source"]["source_locator"] = "foreign-owned-row"
    else:
        pair["cve_id"] = "CVE-2025-99999"
        # Keep internal child aggregates coherent, to exercise composition ownership.
        from infrastructure_impact.application import switching_disclosure as disclosure

        pairs = bad["disclosure"]["pairs"]
        bad["disclosure"]["periods"] = {
            p: disclosure._summary([x for x in pairs if x["date_period"] == p])
            for p in ("pre_july", "from_july", "unknown")
        }
        bad["disclosure"]["years"] = {
            y: disclosure._summary(
                [
                    x
                    for x in pairs
                    if (comparison.day(x["initial_published_at"]) or "unknown")[:4] == y
                ]
            )
            for y in bad["disclosure"]["years"]
        }
        bad["disclosure"]["year_periods"] = disclosure._year_periods(pairs)
    bad["content_sha256"] = api()._hash({k: v for k, v in bad.items() if k != "content_sha256"})
    with pytest.raises(ValueError):
        api().validate_report(bad, evidence=ev)


@pytest.mark.parametrize("mutation", ["source", "claim_id"])
def test_kev_claim_reference_closure_rejects_rehashed_source(mutation):
    from test_switching_kev_reconciliation import claim
    from test_switching_kev_reconciliation import inputs as kev_inputs

    _, ev, _, study = kev_inputs([claim()])
    bad = api().build_report([], [], study)
    ref = bad["kev_reconciliation"]["entries"][0]["current_claims"][0]
    if mutation == "source":
        ref["source"]["source_locator"] = "foreign-row"
    else:
        ref["claim_id"] = "f" * 64
    bad["content_sha256"] = api()._hash({k: v for k, v in bad.items() if k != "content_sha256"})
    with pytest.raises(ValueError):
        api().validate_report(bad, evidence=ev)


@pytest.mark.parametrize("field", ["current_records", "retained_records"])
def test_kev_record_reference_ownership_uses_authoritative_records(field):
    from test_switching_kev_reconciliation import CID
    from test_switching_kev_reconciliation import inputs as kev_inputs

    from infrastructure_impact.adapters.common import base

    _, ev, _, study = kev_inputs()
    current = base(
        "arista",
        "https://www.arista.com/en/support/advisories-notices/security-advisory/123",
        "current",
        "Authored",
        "2026-05-01",
    )
    current.update(cves=[CID], sha256="a" * 64, source_observed_at=study["generated_at"])
    retained = copy.deepcopy(current)
    retained.update(advisory_id="retained", sha256="b" * 64)
    bad = api().build_report([current], [retained], study)
    bad["kev_reconciliation"]["entries"][0][field][0]["source"]["source_sha256"] = "f" * 64
    bad["content_sha256"] = api()._hash({k: v for k, v in bad.items() if k != "content_sha256"})
    with pytest.raises(ValueError):
        api().validate_report(bad, evidence=ev, records=[current], retained=[retained])


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_common_writer_rejects_present_null_analysis(tmp_path, fmt):
    from test_static_delivery import dataset
    from test_switching_aruba_fix_links import projected

    from infrastructure_impact.application import publication

    data = dataset()
    data["research"]["switching_input"] = projected()
    data["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    data["current_evidence"]["publication"] = data["publication"]
    public = publication.public_projection(data)
    public["switching_analysis"] = None
    with pytest.raises(ValueError):
        publication.write_bundle(tmp_path / fmt, public, publication_format=fmt)


def test_compact_facets_keep_exact_frozen_families_without_losing_unknowns_or_inventory():
    from test_switching_kev_reconciliation import AT as kev_at
    from test_switching_kev_reconciliation import CID, claim
    from test_switching_kev_reconciliation import inputs as kev_inputs

    from infrastructure_impact.adapters.common import base
    from infrastructure_impact.application import first_fixed
    from infrastructure_impact.application import switching_disclosure as disclosure
    from infrastructure_impact.application import switching_kev_reconciliation as reconciliation
    from infrastructure_impact.application import switching_model_coverage as models

    # Same CVE and vendor must not pull unrelated/unclassified software into the
    # study. All in-family statuses, missing dates and unresolved model scopes stay.
    inside = [
        claim(
            advisory_id="inside-" + str(i),
            status=status,
            initial_published_at=date,
            platform_bindings=[],
            named_platforms=[],
            scope_level="os_family",
            publisher=dict(id="inside-" + str(i), sequence="1", status=publisher),
        )
        for i, (status, date, publisher) in enumerate(
            [
                ("affected", "2025-01-01", "final"),
                ("unknown", None, "final"),
                ("unaffected", "2026-05-05", "final"),
                ("affected", "2026-05-06", "draft"),
                ("fixed", "2020-01-01", "final"),
                ("investigating", "2027-01-01", "final"),
            ]
        )
    ]
    inside.append(claim(advisory_id="inside-qualified", initial_published_at="2026-08-01"))
    outside = [
        claim(
            advisory_id="outside-" + str(i),
            family=None if i % 2 else "cisco-iosxe",
            status="affected",
            cve_id=CID if i % 2 else "CVE-2025-99999",
            product="Unclassified source context",
            platform_bindings=[],
            named_platforms=[],
            scope_level="os_family",
        )
        for i in range(80)
    ]
    kev, ev, _, study = kev_inputs(inside + outside)
    record = base(
        "arista",
        "https://www.arista.com/en/support/advisories-notices/security-advisory/authored-outside",
        "outside-inventory",
        "Authored inventory context",
        "2025-01-01",
    )
    record.update(
        cves=[CID], sha256="b" * 64, source_observed_at=kev_at, document_status="published"
    )
    compiled = api().build_report([record], [], study)
    expected_ids = {c["claim_id"] for c in ev["claims"] if c["family"] == "arista-eos"}
    assert set(compiled["claims"]) == expected_ids
    assert len(compiled["claims"]) == len(inside)
    assert compiled["requirements"]["evidence_sha256"] == contracts.definition_sha256(ev)
    assert len(compiled["kev_reconciliation"]["entries"][0]["current_records"]) == 1
    assert (
        compiled["kev_reconciliation"]["entries"][0]["current_records"][0]["advisory_id"]
        == "outside-inventory"
    )
    ff = first_fixed.build_report([record], api_results=[], publication=None, generated_at=kev_at)
    native = upgrades.build_report(ev, ff, None, kev, publication=None, generated_at=kev_at)
    inventory = reconciliation.build_inventory(
        [record], [], publication=None, generated_at=kev_at, study_definition=contracts.definition()
    )
    for scope in ("os_family", "model_qualified"):
        for window in ("all", "pre", "post", "undated", "2025", "2026"):
            options = dict(vendor="arista", scope_level=scope, window=window, cve_ids=[CID])
            selected = comparison.select_report(study, **options, evaluated_at=kev_at)
            actual = api().select_report(compiled, api().selection_context(compiled, options))
            assert actual["selection"] == selected["selection"]
            assert actual["upgrades"] == api().project_native(native, selected)
            assert actual["model_coverage"] == models.build_report(
                ev, selected, publication=None, generated_at=kev_at
            )
            assert actual["disclosure"] == disclosure.build_report(
                [record], selected, evidence=ev, publication=None, generated_at=kev_at
            )
            assert actual["kev_reconciliation"] == reconciliation.build_report(
                kev,
                contracts.definition(),
                ev,
                inventory,
                publication=None,
                generated_at=kev_at,
                evaluated_at=kev_at,
                selection=selected,
            )
    # Complete-membership validation still rejects omission of an in-family unknown.
    missing = copy.deepcopy(compiled)
    unknown = next(cid for cid, c in missing["claims"].items() if c["status"] == "unknown")
    del missing["claims"][unknown]
    missing["content_sha256"] = contracts.definition_sha256(
        {k: v for k, v in missing.items() if k != "content_sha256"}
    )
    with pytest.raises(ValueError, match="membership|claim/source"):
        api().validate_report(missing, evidence=ev, records=[record], retained=[])


def test_claim_sources_are_pooled_with_typed_closure_and_no_redundant_requirement_refs():
    ev, _, _, study = fixture()
    before = copy.deepcopy(study)
    compiled = api().build_report([], [], study)
    assert study == before
    assert all("source" not in c and "source_ref" in c for c in compiled["claims"].values())
    assert all(
        "source_ref" not in r and "severity_facets_ref" not in r
        for r in compiled["requirements"]["requirements"]
    )
    expanded = {c["claim_id"]: c for c in api().claim_facets(compiled)}
    assert all(expanded[c["claim_id"]]["source"] == c["source"] for c in ev["claims"])
    for cid, member in compiled["requirements"]["members"].items():
        assert compiled["claims"][cid]["source_ref"] == member["source_ref"]
    for ref in (
        "0" * 64,
        next(k for k, v in compiled["requirements"]["facts"].items() if isinstance(v, list)),
    ):
        changed = copy.deepcopy(compiled)
        next(iter(changed["claims"].values()))["source_ref"] = ref
        changed["content_sha256"] = contracts.definition_sha256(
            {k: v for k, v in changed.items() if k != "content_sha256"}
        )
        with pytest.raises(ValueError, match="source reference"):
            api().validate_report(changed)
    selected = api().select_report(compiled, api().selection_context(compiled, {}))
    next(iter(selected["upgrades"]["requirements"]["facts"].values())).update(
        {"unused-test-key": True}
    )
    api().validate_report(compiled)


def test_indexed_row_evidence_exact_native_walk_and_tampering():
    ev, ff, k, study = fixture()
    selected = comparison.select_report(study, evaluated_at=AT)
    compact = api().compile_requirements(ev, ff, None, k, publication=None, generated_at=AT)
    native = upgrades.select_report(
        upgrades.build_report(ev, ff, None, k, publication=None, generated_at=AT), selected
    )
    result = api().select_upgrades(compact, selected)
    assert list(api().detailed_rows(result)) == native["rows"]
    assert result["row_evidence"]["member_count"] == len(result["requirements"]["members"])
    assert all(
        "affected_claim_ids" not in row and "unresolved" not in row for row in result["rows"]
    )
    assert len(result["row_evidence"]["affected"]) < len(result["rows"])
    for mutation in (
        "digest",
        "missing_ref",
        "bad_index",
        "duplicate_index",
        "unused_ref",
        "wrong_type",
    ):
        bad = copy.deepcopy(result)
        table = bad["row_evidence"]
        if mutation == "digest":
            table["member_order_sha256"] = "0" * 64
        elif mutation == "missing_ref":
            bad["rows"][0]["affected_ref"] = "0" * 64
        elif mutation == "unused_ref":
            table["affected"]["0" * 64] = []
        elif mutation == "wrong_type":
            values = [dict(member_index=0, issues=[])]
            key = api()._hash(values)
            table["affected"][key] = values
            bad["rows"][0]["affected_ref"] = key
        else:
            row = next(r for r in bad["rows"] if table["affected"][r["affected_ref"]])
            values = table["affected"][row["affected_ref"]]
            values[:] = (
                [len(bad["requirements"]["members"])]
                if mutation == "bad_index"
                else [values[0], values[0]]
            )
            new = api()._hash(values)
            table["affected"][new] = values
            row["affected_ref"] = new
        with pytest.raises(ValueError):
            list(api().detailed_rows(bad))


@pytest.mark.parametrize("publication_format", ["v1", "v2"])
def test_opt_in_publication_discovers_full_feed_candidates_absent_from_collection(
    publication_format,
):
    from test_static_delivery import dataset
    from test_switching_aruba_fix_links import projected
    from test_switching_kev_reconciliation import AT as kev_at
    from test_switching_kev_reconciliation import CID

    from infrastructure_impact.application import publication
    from infrastructure_impact.references.kev import parse

    data = dataset()
    data["research"]["switching_input"] = projected()
    raw = json.dumps(
        dict(
            catalogVersion="2026.11.13",
            dateReleased=kev_at,
            count=1,
            vulnerabilities=[
                dict(
                    cveID=CID,
                    vendorProject="Arista",
                    product="Extensible Operating System",
                    vulnerabilityName="Absent example",
                    dateAdded="2026-11-12",
                    shortDescription="Example",
                    requiredAction="Review",
                    dueDate="2026-12-01",
                )
            ],
        )
    ).encode()
    data["research"]["kev_input"] = dict(
        configured=True,
        enabled=True,
        checked_at=None,
        latest_attempt=None,
        retained=dict(
            catalogue=parse(raw),
            sha256="a" * 64,
            revision_id="1",
            source_observed_at=kev_at,
            parsed_at=kev_at,
        ),
    )
    public = publication.public_projection(
        data, include_switching_analysis=True, publication_format=publication_format
    )
    alternate = publication.public_projection(
        data,
        include_switching_analysis=True,
        publication_format="v2" if publication_format == "v1" else "v1",
    )
    assert contracts._json(public) == contracts._json(alternate)
    assert CID not in public["kev"]["entries"]
    assert CID not in public["switching_comparison"]["inputs"]["kev"]["entries"]
    gap = public["switching_analysis"]["kev_reconciliation"]
    entry = next(e for e in gap["entries"] if e["cve_id"] == CID)
    assert entry["claim_state"] == "no_observed_vendor_record"
    assert entry["historically_listed"] is True and entry["membership"] == "unknown"
    assert entry["current_claims"] == entry["current_records"] == entry["retained_records"] == []
    for options, requested in [({}, True), ({"cve_ids": []}, False), ({"cve_ids": [CID]}, True)]:
        selected = api().select_report(
            public["switching_analysis"],
            api().selection_context(public["switching_analysis"], options),
        )
        row = next(e for e in selected["kev_reconciliation"]["entries"] if e["cve_id"] == CID)
        assert row["in_requested_cve_filter"] is requested
        assert row["in_effective_study_cohort"] is False
    default = publication.public_projection(data, publication_format=publication_format)
    assert "switching_analysis" not in default and CID not in default["kev"]["entries"]


@pytest.mark.parametrize(
    "options",
    [{}, {"scope_level": "model_qualified"}, {"cve_ids": []}, {"cve_ids": ["CVE-2026-7473"]}],
)
def test_complete_feed_compact_audit_matches_native_core(options):
    from test_switching_kev_reconciliation import AT as evaluated
    from test_switching_kev_reconciliation import claim
    from test_switching_kev_reconciliation import inputs as source_inputs

    from infrastructure_impact.application import switching_kev_reconciliation as reconciliation

    k, ev, inventory, study = source_inputs([claim()])
    compiled = api().build_report([], [], study)
    context = comparison.select_report(study, **options, evaluated_at=evaluated)
    native = reconciliation.build_report(
        k,
        study["definition"],
        ev,
        inventory,
        publication=None,
        generated_at=evaluated,
        evaluated_at=evaluated,
        selection=context,
    )
    audited = reconciliation.from_compiled(
        compiled, k, [], [], evaluated_at=evaluated, options=options
    )
    assert audited == native
    broken = copy.deepcopy(k)
    broken["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    with pytest.raises(ValueError):
        reconciliation.from_compiled(compiled, broken, [], [], evaluated_at=evaluated)


def test_complete_feed_selection_inflates_source_facets_once(monkeypatch):
    from test_switching_kev_reconciliation import inputs as kev_inputs

    _, _, _, study = kev_inputs()
    compiled = api().build_report([], [], study)
    second = copy.deepcopy(compiled["kev_reconciliation"]["entries"][0])
    second["cve_id"] = "CVE-2026-99999"
    compiled["kev_reconciliation"]["entries"].append(second)
    original = api().claim_facets
    calls = []

    def counted(value):
        calls.append(True)
        yield from original(value)

    monkeypatch.setattr(api(), "claim_facets", counted)
    selection = api().selection_context(compiled, {})["selection"]
    calls.clear()
    result = api()._kev_selected(compiled, selection)
    assert len(result["entries"]) == 2
    assert len(calls) == 1


def composition_input():
    from test_static_delivery import dataset
    from test_switching_aruba_fix_links import projected

    data = dataset()
    data["publication"] = None
    data["research"]["switching_input"] = projected()
    return data


def test_optional_v2_composes_one_fresh_full_evidence_validation(monkeypatch):
    from infrastructure_impact.application import publication

    inputs = [composition_input(), composition_input()]
    counts = dict(shape=0, semantics=0, comparison=0, comparison_shape=0)
    for module, name, key in (
        (contracts, "validate_evidence", "shape"),
        (contracts, "_validate_evidence_semantics", "semantics"),
        (
            comparison,
            "_validate_semantics"
            if hasattr(comparison, "_validate_semantics")
            else "validate_semantics",
            "comparison",
        ),
    ):
        original = getattr(module, name)

        def counted(*args, _original=original, _key=key, **kwargs):
            counts[_key] += 1
            return _original(*args, **kwargs)

        monkeypatch.setattr(module, name, counted)
    validate_shape = contracts._validate

    def counted_shape(value, schema):
        if schema == "switching-comparison-v1.json":
            counts["comparison_shape"] += 1
        return validate_shape(value, schema)

    monkeypatch.setattr(contracts, "_validate", counted_shape)
    for invocation in range(1, 3):
        result = publication.public_projection(
            inputs[invocation - 1], publication_format="v2", include_switching_analysis=True
        )
        assert counts == dict(
            shape=invocation,
            semantics=invocation,
            comparison=3 * invocation,
            comparison_shape=4 * invocation,
        )
        # Complete strict JSON serialization also rejects any leaked capability.
        assert json.loads(contracts._json(result))["switching_analysis"]


def test_writer_mints_independently_once_each_time(tmp_path, monkeypatch):
    from infrastructure_impact.application import publication, publication_v2

    data = publication.public_projection(
        composition_input(), publication_format="v2", include_switching_analysis=True
    )
    calls = []
    validate = contracts._validate_evidence_semantics

    def counted(*args, **kwargs):
        calls.append(1)
        return validate(*args, **kwargs)

    monkeypatch.setattr(contracts, "_validate_evidence_semantics", counted)
    written = []
    monkeypatch.setattr(publication_v2, "_write_bundle", lambda *args: written.append(args))
    for invocation in range(1, 3):
        publication.write_bundle(tmp_path, data, publication_format="v2")
        assert len(calls) == invocation
    assert len(written) == 2


COMPOSED_CONSUMERS = (
    "comparison",
    "releases",
    "prepare",
    "compile",
    "requirements",
    "analysis",
    "analysis_validation",
    "disclosure",
    "reconciliation",
    "writer_relationship",
)


@pytest.fixture
def composed_values():
    from infrastructure_impact.application import switching_kev_reconciliation as reconciliation

    ev, ff, kev, study = fixture()
    compiled = api().build_report([], [], study)
    return dict(
        ev=ev,
        ff=ff,
        kev=kev,
        study=study,
        compiled=compiled,
        inventory=reconciliation.build_inventory(
            [], [], study_definition=study["definition"], publication=None, generated_at=AT
        ),
        proof=contracts._ValidatedEvidence(ev, publication=None, generated_at=AT),
    )


def consume_composed(which, values, proof=None, *, private=True, context=None):
    from infrastructure_impact.application import switching_disclosure as disclosure
    from infrastructure_impact.application import switching_kev_reconciliation as reconciliation
    from infrastructure_impact.application import switching_releases as releases

    ev, study = values["ev"], values["study"]
    kwargs = dict(publication=None, generated_at=AT) if context is None else context
    args = dict(evidence_proof=values["proof"] if proof is None else proof) if private else {}

    def core(module, name):
        return getattr(module, ("_" if private else "") + name)

    if which == "comparison":
        return core(contracts, "validate_comparison")(study, **args)
    if which == "releases":
        return core(releases, "build")(ev, [], observation_end=AT[:10], **kwargs, **args)
    if which == "prepare":
        header, constraints = core(upgrades, "prepare_report")(
            ev, values["ff"], None, values["kev"], **kwargs, **args
        )
        return header, list(constraints)
    if which == "compile":
        return core(api(), "compile_requirements")(
            ev, values["ff"], None, values["kev"], **kwargs, **args
        )
    if which == "requirements":
        return core(api(), "validate_requirements")(
            values["compiled"]["requirements"], evidence=ev, **args
        )
    if which == "analysis":
        return core(api(), "build_report")([], [], study, **args)
    if which == "analysis_validation":
        return core(api(), "validate_report")(values["compiled"], evidence=ev, **args)
    if which == "disclosure":
        return core(disclosure, "build_report")([], study, evidence=ev, **kwargs, **args)
    if which == "reconciliation":
        return core(reconciliation, "build_report")(
            values["kev"],
            study["definition"],
            ev,
            values["inventory"],
            evaluated_at=AT,
            selection=study,
            **kwargs,
            **args,
        )
    return contracts._validate_comparison_evidence(study, ev, **kwargs, **args)


@pytest.mark.parametrize("consumer", COMPOSED_CONSUMERS)
def test_private_consumers_match_complete_public_bytes_and_allow_equal_copies(
    composed_values, consumer
):
    values = composed_values
    values["ev"] = copy.deepcopy(values["ev"])
    values["study"] = copy.deepcopy(values["study"])
    public = consume_composed(consumer, values, private=False)
    private = consume_composed(consumer, values)
    # prepare exposes its historical tuple; its private generator is consumed here.
    assert contracts._json(list(public) if consumer == "prepare" else public) == contracts._json(
        list(private) if consumer == "prepare" else private
    )


@pytest.mark.parametrize("consumer", COMPOSED_CONSUMERS)
@pytest.mark.parametrize(
    "mutation",
    ["unused", "last", "middle_source", "coverage", "scores", "bool", "float", "python", "time"],
)
def test_private_consumers_reject_complete_value_drift(composed_values, consumer, mutation):
    values = composed_values
    # Mutate both actual frames so every consumer sees drift, regardless of aliasing.
    for ev in (values["ev"], values["study"]["inputs"]["evidence"]):
        if mutation == "unused":
            ev["unused"] = "not selected"
        elif mutation == "last":
            ev["claims"][-1]["issues"].append("changed_after_mint")
        elif mutation == "middle_source":
            ev["claims"][len(ev["claims"]) // 2]["source"]["retrieved_at"] = "2025-01-01"
        elif mutation == "coverage":
            ev["coverage"].append({})
        elif mutation == "scores":
            ev["score_availability"] = {"unused": True}
        elif mutation in ("bool", "float"):
            ev["schema_version"] = True if mutation == "bool" else 1.0
        elif mutation == "python":
            ev["issues"] = tuple(ev["issues"])
        else:
            ev["generated_at"] = "2026-11-05T00:00:00Z"
    with pytest.raises((ValueError, TypeError, ValidationError)):
        consume_composed(consumer, values)


@pytest.mark.parametrize("consumer", COMPOSED_CONSUMERS)
@pytest.mark.parametrize("wrong", ["bool", "dict", "duck", "subclass"])
def test_private_consumers_require_exact_capability_type(composed_values, consumer, wrong):
    class Duck:
        def require(self, *args, **kwargs):
            pytest.fail("duck capability invoked")

    class Subclass(contracts._ValidatedEvidence):
        def require(self, *args, **kwargs):
            pytest.fail("overridden capability invoked")

    values = composed_values
    proof = {"bool": True, "dict": {}, "duck": Duck(), "subclass": object.__new__(Subclass)}[wrong]
    with pytest.raises(TypeError, match="fresh validated evidence capability"):
        consume_composed(consumer, values, proof=proof)


@pytest.mark.parametrize(
    "consumer", ["comparison", "analysis", "disclosure", "reconciliation", "writer_relationship"]
)
@pytest.mark.parametrize("context", ["publication", "generated_at"])
def test_private_consumers_check_actual_enclosing_context(composed_values, consumer, context):
    values = composed_values
    values["study"][context] = (
        {"id": "b" * 32, "advisory_schema_version": 2}
        if context == "publication"
        else "2026-11-05T00:00:00Z"
    )
    with pytest.raises(ValueError):
        consume_composed(consumer, values)


@pytest.mark.parametrize("consumer", ["disclosure", "reconciliation", "writer_relationship"])
@pytest.mark.parametrize("which", ["standalone", "embedded"])
def test_private_consumers_guard_original_and_copied_evidence(composed_values, consumer, which):
    values = composed_values
    ev = values["ev"] if which == "standalone" else values["study"]["inputs"]["evidence"]
    ev["schema_version"] = 1.0
    with pytest.raises(ValueError, match="complete value/context"):
        consume_composed(consumer, values)


@pytest.mark.parametrize("mutation", ["rows", "sources", "selection", "definition", "kev"])
def test_capability_does_not_authorize_comparison_output(composed_values, mutation):
    values = composed_values
    study = values["study"]
    if mutation == "rows":
        study["rows"][0]["counts"]["advisories"] += 1
    elif mutation == "sources":
        study["sources"] = []
    elif mutation == "selection":
        study["selection"]["effective_cve_ids"] = []
    elif mutation == "definition":
        study["definition"]["start_date"] = "2020-01-01"
    else:
        study["inputs"]["kev"]["generated_at"] = "2026-11-05T00:00:00Z"
    with pytest.raises(ValueError):
        consume_composed("comparison", values)


def test_private_compile_detects_generator_mutation_without_per_yield_hash(
    composed_values, monkeypatch
):
    values = composed_values
    original = upgrades._constraints
    calls = []
    require = contracts._ValidatedEvidence.require

    def counted(self, *args, **kwargs):
        calls.append(1)
        return require(self, *args, **kwargs)

    monkeypatch.setattr(contracts._ValidatedEvidence, "require", counted)
    consume_composed("compile", values)
    assert len(calls) == 4  # prepare, before/after eager pack, requirements guard

    def mutated(*args, **kwargs):
        yield from original(*args, **kwargs)
        values["ev"]["coverage"].append({})

    monkeypatch.setattr(upgrades, "_constraints", mutated)
    with pytest.raises(ValueError, match="complete value/context"):
        consume_composed("compile", values)


@pytest.mark.parametrize("release_present", [False, True])
def test_complete_optional_projection_strict_bytes_equal_public_path(release_present):
    from test_switching_release_history import frame

    from infrastructure_impact.application import publication

    data = composition_input()
    if release_present:
        data["research"]["release_input"] = [frame()]
    expected = publication.public_projection(data, include_switching_analysis=True)
    actual = publication.public_projection(
        data, publication_format="v2", include_switching_analysis=True
    )
    assert contracts._json(actual) == contracts._json(expected)


@pytest.mark.parametrize("consumer", COMPOSED_CONSUMERS)
def test_default_consumers_repeat_full_semantics(composed_values, consumer, monkeypatch):
    original = contracts._validate_evidence_semantics
    calls = []

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(contracts, "_validate_evidence_semantics", counted)
    consume_composed(consumer, composed_values, private=False)
    first = len(calls)
    assert first >= 1
    consume_composed(consumer, composed_values, private=False)
    assert len(calls) == 2 * first


@pytest.mark.parametrize("mutation", ["claim", "requirement", "disclosure"])
def test_private_report_validator_rejects_rehashed_output_ownership(composed_values, mutation):
    values = composed_values
    bad = values["compiled"]
    if mutation == "claim":
        del bad["claims"][next(iter(bad["claims"]))]
    elif mutation == "requirement":
        bad["requirements"]["requirements"].pop()
        child = bad["requirements"]
        child["content_sha256"] = api()._hash(
            {k: v for k, v in child.items() if k != "content_sha256"}
        )
    else:
        bad["disclosure"]["pairs"][0]["source"]["source_locator"] = "foreign-owned-row"
    bad["content_sha256"] = api()._hash({k: v for k, v in bad.items() if k != "content_sha256"})
    with pytest.raises(ValueError):
        consume_composed("analysis_validation", values)


@pytest.mark.parametrize("which", ["standalone", "embedded"])
def test_projection_final_guard_rejects_mutation_after_analysis(which, monkeypatch):
    from infrastructure_impact.application import publication
    from infrastructure_impact.application import switching_releases as releases

    standalone = []
    build_release = releases._build
    build_analysis = api()._build_report

    def remember(ev, *args, **kwargs):
        standalone.append(ev)
        return build_release(ev, *args, **kwargs)

    def mutate(*args, **kwargs):
        result = build_analysis(*args, **kwargs)
        ev = standalone[0] if which == "standalone" else args[2]["inputs"]["evidence"]
        ev["schema_version"] = 1.0
        return result

    monkeypatch.setattr(releases, "_build", remember)
    monkeypatch.setattr(api(), "_build_report", mutate)
    with pytest.raises(ValueError, match="complete value/context"):
        publication.public_projection(
            composition_input(), publication_format="v2", include_switching_analysis=True
        )


@pytest.mark.parametrize("which", ["standalone", "embedded"])
def test_writer_final_guard_rejects_post_validation_mutation(tmp_path, which, monkeypatch):
    from infrastructure_impact.application import publication, publication_v2

    data = publication.public_projection(
        composition_input(), publication_format="v2", include_switching_analysis=True
    )
    validate = api()._validate_report

    def mutate(*args, **kwargs):
        validate(*args, **kwargs)
        ev = (
            data["switching_evidence"]
            if which == "standalone"
            else data["switching_comparison"]["inputs"]["evidence"]
        )
        ev["schema_version"] = 1.0

    monkeypatch.setattr(api(), "_validate_report", mutate)
    monkeypatch.setattr(
        publication_v2, "_write_bundle", lambda *args: pytest.fail("invalid data written")
    )
    with pytest.raises(ValueError, match="complete value/context"):
        publication.write_bundle(tmp_path, data, publication_format="v2")


@pytest.mark.parametrize("mutation", ["standalone", "embedded", "row", "child"])
def test_writer_independent_boundary_rejects_input_and_output_tampering(
    tmp_path, mutation, monkeypatch
):
    from infrastructure_impact.application import publication, publication_v2

    data = publication.public_projection(
        composition_input(), publication_format="v2", include_switching_analysis=True
    )
    if mutation == "standalone":
        data["switching_evidence"]["schema_version"] = 1.0
    elif mutation == "embedded":
        data["switching_comparison"]["inputs"]["evidence"]["schema_version"] = 1.0
    elif mutation == "row":
        data["switching_comparison"]["rows"][0]["counts"]["advisories"] += 1
    else:
        bad = data["switching_analysis"]
        del bad["claims"][next(iter(bad["claims"]))]
        bad["content_sha256"] = api()._hash({k: v for k, v in bad.items() if k != "content_sha256"})
    monkeypatch.setattr(
        publication_v2, "_write_bundle", lambda *args: pytest.fail("invalid data written")
    )
    with pytest.raises(ValueError):
        publication.write_bundle(tmp_path, data, publication_format="v2")


@pytest.mark.parametrize("private", [False, True])
def test_analysis_rejects_common_child_producer_corruption(composed_values, monkeypatch, private):
    from infrastructure_impact.application import switching_disclosure as disclosure

    original = disclosure._build_report

    def corrupted(*args, **kwargs):
        result = original(*args, **kwargs)
        result["pairs"][0]["source"]["source_locator"] = "foreign-producer-source"
        return result

    # Inject into the actual shared producer, so both public and composed calls
    # exercise final ownership validation after the child validated itself.
    monkeypatch.setattr(disclosure, "_build_report", corrupted)
    with pytest.raises(ValueError, match="ownership|source|membership"):
        consume_composed("analysis", composed_values, private=private)


def test_private_api_facts_compiler_keeps_all_scenarios_and_exact_bytes():
    from test_first_fixed import api_frame, record

    from infrastructure_impact.application import first_fixed

    ev, _, kev = inputs([("2025-01-01", ["17.15.3"])])
    raw = copy.deepcopy(ev)
    raw["claims"][0]["version_expressions"] = ["17.15.1"]
    ev = contracts.project(raw, publication=None, generated_at=AT)
    claim = ev["claims"][0]
    current = record(claim["advisory_id"], ["17.15.1"])
    current["assessments"][0]["cve_id"] = claim["cve_id"]
    ff = first_fixed.build_report(
        [current],
        api_results=[api_frame(claim["advisory_id"], "17.15.1", ["17.15.2"], [claim["cve_id"]])],
        publication=None,
        generated_at=AT,
    )
    assert ff["api_facts"]
    public = api().compile_requirements(ev, ff, None, kev, publication=None, generated_at=AT)
    private = api()._compile_requirements(
        ev,
        ff,
        None,
        kev,
        publication=None,
        generated_at=AT,
        evidence_proof=contracts._ValidatedEvidence(ev, publication=None, generated_at=AT),
    )
    assert contracts._json(private) == contracts._json(public)
    assert {r["scenario"] for r in private["requirements"]} == set(upgrades.SCENARIOS)
    assert any(
        p["kind"] == "publisher_api_first_fixed"
        for r in private["requirements"]
        for p in api()._expand(private, r)["proof"]
    )


def test_private_multivendor_reviewed_links_unknowns_and_model_unresolved_exact_bytes():
    from test_switching_arista_fix_links import CASES
    from test_switching_arista_fix_links import projected as arista
    from test_switching_aruba_fix_links import projected as aruba

    ev, _, kev, _ = fixture()
    raw = dict(
        claims=ev["claims"] + aruba()["claims"] + arista(CASES[0])["claims"], coverage=[], issues=[]
    )
    ev = contracts.project(raw, publication=None, generated_at=AT)
    study = comparison.build_report(
        ev,
        kev,
        definition=contracts.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    public = api().build_report([], [], study)
    private = api()._build_report(
        [],
        [],
        study,
        evidence_proof=contracts._ValidatedEvidence(ev, publication=None, generated_at=AT),
    )
    assert contracts._json(private) == contracts._json(public)
    assert {c["vendor"] for c in api().claim_facets(private)} == {"cisco", "aruba", "arista"}
    assert any(c["initial_published_at"] is None for c in api().claim_facets(private))
    assert any(c["scope_level"] == "os_family" for c in api().claim_facets(private))


def test_private_capability_requires_actual_comparison_inputs(composed_values):
    unavailable = comparison.select_report(None, evaluated_at=AT)
    contracts.validate_comparison(unavailable)
    with pytest.raises(ValueError, match="complete comparison inputs"):
        contracts._validate_comparison_evidence(
            unavailable,
            composed_values["ev"],
            publication=None,
            generated_at=AT,
            evidence_proof=composed_values["proof"],
        )


def test_private_reconciliation_rejects_different_complete_kev_catalogue():
    from test_switching_kev_reconciliation import claim
    from test_switching_kev_reconciliation import inputs as kev_inputs

    from infrastructure_impact.application import kev
    from infrastructure_impact.application import switching_kev_reconciliation as reconciliation

    _, ev, inventory, study = kev_inputs([claim()])
    at = study["generated_at"]
    other = kev.build_report({}, [], publication=None, generated_at=at)
    for proof_args in (
        {},
        dict(evidence_proof=contracts._ValidatedEvidence(ev, publication=None, generated_at=at)),
    ):
        with pytest.raises(ValueError, match="selection input identity"):
            reconciliation._build_report(
                other,
                study["definition"],
                ev,
                inventory,
                publication=None,
                generated_at=at,
                evaluated_at=at,
                selection=study,
                **proof_args,
            )
