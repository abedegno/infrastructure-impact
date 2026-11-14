"""Compact source-owned requirements use the native walk without native matrices."""

import copy
import importlib
import json

import pytest
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
    assert api().select_upgrades(compact, selected) == api().project_native(native, selected)
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
    record["notes"][0]["text"] = "PRIVATE_NOTES_SENTINEL"
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
    for mutation in ("digest", "missing_ref", "bad_index", "duplicate_index", "unused_ref"):
        bad = copy.deepcopy(result)
        table = bad["row_evidence"]
        if mutation == "digest":
            table["member_order_sha256"] = "0" * 64
        elif mutation == "missing_ref":
            bad["rows"][0]["affected_ref"] = "0" * 64
        elif mutation == "unused_ref":
            table["affected"]["0" * 64] = []
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
