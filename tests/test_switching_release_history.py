"""Authored release evidence and compact selection; no publisher captures."""

import copy
import importlib
import json
from hashlib import sha256

import pytest
from test_software_release_sources import ARUBA, ARUBA16, CISCO, history, models
from test_switching_arista_fix_links import CASES, VERSIONS
from test_switching_arista_fix_links import projected as arista_evidence
from test_switching_aruba_fix_links import AT, reidentify
from test_switching_aruba_fix_links import projected as aruba_evidence

from infrastructure_impact.application import kev, publication, switching_comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.application.publication_reader import PublicationReader
from infrastructure_impact.references import software_releases as sources
from infrastructure_impact.references.registry import SOURCES


def api():
    return importlib.import_module("infrastructure_impact.application.switching_releases")


def frame(identity=ARUBA, document=None, **changes):
    document = document or sources.parse_aruba_10_14(history())
    value = dict(
        source_id=identity,
        source_url=SOURCES[identity].url,
        purpose="release_history",
        configured=True,
        enabled=True,
        checked_at=AT,
        latest_attempt=dict(checked_at=AT, outcome="ok", error_code=None),
        retained=dict(
            document=document,
            sha256="a" * 64,
            normalized_sha256=sha256(
                json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            parser_fingerprint=document["parser_fingerprint"],
            revision_id="1",
            source_observed_at=AT,
            parsed_at=AT,
        ),
    )
    value.update(changes)
    return value


def build(ev=None, frames=None):
    return api().build(
        ev or aruba_evidence(),
        frames or [],
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )


def study(ev, **options):
    full = switching_comparison.build_report(
        ev,
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    return switching_comparison.summary(
        switching_comparison.select_report(full, evaluated_at=AT, **options)
    )


def release(report, version):
    return next(r for r in report["releases"] if r["version"] == version)


def test_exact_aruba_links_merge_history_without_counting_other_rows_as_zero_fixes():
    report = build(frames=[frame()])
    node = release(report, "10.14.0007")
    assert node["vendor_reported_fixed_cve_ids"] == ["CVE-2024-6387"]
    assert node["affected_scope_cve_ids"] == ["CVE-2024-6387"]
    assert {r["kind"] for r in node["references"]} == {"vendor_fixed", "affected_scope_fix"}
    assert node["reported_release_dates"] == ["2024-07-12"]
    assert all(
        r["claim_id"] in {c["claim_id"] for c in aruba_evidence()["claims"]}
        for r in node["references"]
    )
    context = release(report, "10.14.0001")
    assert context["vendor_reported_fixed_cve_count"] is None
    assert context["affected_scope_cve_count"] is None
    assert context["history"][0]["publisher_reports_posted"] is None
    assert len(report["sources"]) == 5
    assert report["coverage"]["expected_releases"] is None
    assert (
        next(s for s in report["sources"] if s["source_id"] == CISCO)["availability"]
        == "uncollected"
    )


@pytest.mark.parametrize("case", CASES)
def test_reviewed_arista_lists_keep_full_expression_and_literal_identity(case):
    ev = arista_evidence(case)
    result = build(ev)
    for expression in VERSIONS[case[1]]:
        node = release(result, expression.split()[0])
        assert {r["expression"] for r in node["references"]} == {expression}
        assert node["vendor_reported_fixed_cve_count"] == 1
        assert node["affected_scope_cve_count"] == 1
    assert not any("swix" in r["version"].lower() for r in result["releases"])


@pytest.mark.parametrize("change", ["absent", "unowned", "unavailable"])
def test_fixed_only_context_never_supplies_affected_scope_links(change):
    ev = aruba_evidence()
    for c in ev["claims"]:
        if c["status"] == "affected":
            c["remediations"] = []
        if change == "unowned":
            for r in c["remediations"]:
                r["product_ids"] = []
                if "remediation_product_scope_unresolved" not in c["issues"]:
                    c["issues"].append("remediation_product_scope_unresolved")
        if change == "unavailable":
            for r in c["remediations"]:
                r["availability"] = "unknown"
    reidentify(ev)
    result = build(ev)
    assert release(result, "10.14.0007")["affected_scope_cve_count"] is None
    assert release(result, "10.14.0007")["vendor_reported_fixed_cve_count"] == 1


@pytest.mark.parametrize(
    "expression",
    [
        "10.14.x",
        ">=10.14.0007",
        "10.14.0007 - 10.14.0010",
        "SecurityFix_10.14.0007.swix",
        "Upgrade to 10.14.0007",
    ],
)
def test_ranges_hotfixes_and_arbitrary_prose_never_become_release_ids(expression):
    ev = aruba_evidence()
    ev["claims"] = [c for c in ev["claims"] if c["status"] == "fixed"]
    for c in ev["claims"]:
        c["version_expressions"] = [expression]
        c["remediations"] = []
    reidentify(ev)
    result = build(ev)
    assert result["releases"] == []
    assert {d["code"] for d in result["diagnostics"]} == {"fixed_expression_unresolved"}


def test_selection_matches_original_advisory_dates_and_ref_scope_without_claim_ids():
    ev = aruba_evidence()
    # A qualified affected sibling cannot qualify its family-only fixed sibling.
    for c in ev["claims"]:
        if c["status"] == "affected":
            c.update(
                scope_level="model_qualified",
                named_platforms=["Synthetic 6300M"],
                platform_bindings=[
                    dict(
                        platform="Synthetic 6300M",
                        model="6300M",
                        basis="publisher_explicit",
                        source=c["source"].copy(),
                    )
                ],
            )
        if c["status"] == "fixed":
            c.update(scope_level="os_family", platform_bindings=[], named_platforms=[])
            if "model_binding_unresolved" not in c["issues"]:
                c["issues"].append("model_binding_unresolved")
    reidentify(ev)
    result = build(ev, [frame()])
    selected_study = study(ev, vendor="aruba", window="2024", scope_level="model_qualified")
    for row in selected_study["rows"]:
        row.pop("claim_ids")
    selected = api().select_report(result, selected_study)
    fixed = release(selected, "10.14.0007")
    assert fixed["vendor_reported_fixed_cve_count"] is None
    assert fixed["affected_scope_cve_count"] == 1
    # Release history dates do not select fixes for a different advisory window.
    empty = api().select_report(result, study(ev, vendor="aruba", window="2025"))
    assert not any(n["references"] for n in empty["releases"])
    assert release(empty, "10.14.0007")["history"]
    overview = copy.deepcopy(selected_study)
    overview.update(schema_version=2, representation="switching-overview")
    assert api().select_report(result, overview) == selected


@pytest.mark.parametrize(
    "initial,window,want",
    [
        (None, "all", 3),
        (None, "undated", 3),
        (None, "2024", 0),
        ("2020-01-01", "all", 0),
        ("2027-01-01", "all", 0),
    ],
)
def test_undated_and_outside_study_references_follow_study_semantics(initial, window, want):
    ev = aruba_evidence()
    for c in ev["claims"]:
        c["initial_published_at"] = initial
        if initial is None and "initial_publication_date_missing" not in c["issues"]:
            c["issues"].append("initial_publication_date_missing")
    reidentify(ev)
    result = api().select_report(build(ev), study(ev, vendor="aruba", window=window))
    assert sum(bool(r["references"]) for r in result["releases"]) == want


def test_source_binding_fingerprint_and_private_projection():
    value = frame()
    value["private"] = "TOPSECRET"
    value["retained"]["private"] = "TOPSECRET"
    value["latest_attempt"]["error"] = "TOPSECRET"
    result = build(frames=[value])
    assert "TOPSECRET" not in json.dumps(result)
    for key, replacement in [
        ("source_url", "https://evil.example/history"),
        ("source_id", ARUBA16),
    ]:
        bad = frame()
        bad[key] = replacement
        with pytest.raises(ValueError):
            build(frames=[bad])
    bad = frame()
    bad["retained"]["parser_fingerprint"] = "b" * 64
    with pytest.raises(ValueError):
        build(frames=[bad])


def test_disabled_retained_source_is_diagnostic_context_never_published_rows():
    result = build(frames=[frame(enabled=False)])
    assert not any(r["history"] for r in result["releases"])
    source = next(s for s in result["sources"] if s["source_id"] == ARUBA)
    assert source["availability"] == "excluded"
    assert source["retained"] is not None
    assert source["latest_attempt"]["outcome"] == "ok"


def test_release_date_contexts_preserve_unknown_conflicts_and_future_rows():
    value = frame()
    value["retained"]["document"]["releases"][0]["reported_release_date"] = "2027-01-01"
    value = frame(document=value["retained"]["document"])
    node = release(build(frames=[value]), "10.14.0007")
    assert node["reported_release_dates"] == ["2027-01-01"]
    assert "future_release_date" in node["issues"]
    # Scope-specific contexts survive; no future posting changes affected claims.
    assert node["affected_scope_cve_count"] == 1


def test_csv_export_exposes_two_counts_and_original_link_evidence():
    text = api().csv_export(api().select_report(build(), study(aruba_evidence())))
    assert "vendor_reported_fixed_cve_count" in text and "affected_scope_cve_count" in text
    assert "10.14.0007" in text and "CVE-2024-6387" in text


def test_projection_rebuilds_forged_report_and_removes_private_input():
    from test_static_delivery import dataset

    data = dataset()
    data["research"]["switching_input"] = aruba_evidence()
    data["research"]["release_input"] = [frame()]
    data["switching_release_history"] = {"secret": "TOPSECRET"}
    for fmt in ("v1", "v2"):
        result = publication.public_projection(data, publication_format=fmt)
        assert "release_input" not in result["research"]
        assert "TOPSECRET" not in json.dumps(result["switching_release_history"])
        assert release(result["switching_release_history"], "10.14.0007")["history"]


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_public_history_is_lazy_optional_and_generation_bound(tmp_path, fmt):
    from test_static_delivery import dataset

    data = dataset()
    data["research"]["switching_input"] = aruba_evidence()
    data["research"]["release_input"] = [frame()]
    out = publication.publish(data, tmp_path / fmt, publication_format=fmt)
    index = json.loads((out / "data/index.json").read_text())
    bootstrap = json.loads((out / index["bootstrap"]["path"]).read_text())["data"]
    assert "switching_release_history" not in bootstrap
    if fmt == "v1":
        assert "switching_release_history" not in json.loads((out / "snapshot.json").read_text())
        assert (out / "switching-release-history.json").is_file()
    else:
        reader = PublicationReader(out)
        overview = reader.switching_overview()
        assert "switching_release_history" not in reader.runtime_snapshot()
        selected = reader.switching_release_history(overview)
        assert "switching-evidence.json" not in reader._roots
        assert release(selected, "10.14.0007")["affected_scope_cve_count"] == 1
        old = PublicationReader(out)
        old.catalog["roots"].pop("switching-release-history.json")
        missing = old.switching_release_history(overview)
        assert missing["availability"] == "unavailable"
        assert missing["publication"] == overview["publication"]
        bad = copy.deepcopy(overview)
        bad["generated_at"] = "2026-01-01T00:00:00Z"
        with pytest.raises(ValueError):
            reader.switching_release_history(bad)
        tiny = PublicationReader(out, limits={"selected": 500})
        with pytest.raises(ValueError):
            tiny.switching_release_history(overview)


def test_parser_identity_cannot_be_self_authorized_by_matching_forged_hashes():
    value = frame()
    value["retained"]["document"]["parser_fingerprint"] = "b" * 64
    value = frame(document=value["retained"]["document"])
    with pytest.raises(ValueError, match="parser"):
        build(frames=[value])


@pytest.mark.parametrize("state", ["planned", "unavailable", "no_fix_planned"])
def test_conflicting_fixed_status_and_explicit_negative_availability_is_diagnostic(state):
    ev = aruba_evidence()
    ev["claims"] = [c for c in ev["claims"] if c["status"] == "fixed"]
    for c in ev["claims"]:
        for r in c["remediations"]:
            r["availability"] = state
    reidentify(ev)
    result = build(ev)
    assert not result["releases"]
    assert {d["code"] for d in result["diagnostics"]} == {"fixed_availability_conflicting"}


def test_future_fix_availability_and_draft_claims_cannot_supply_available_facts():
    ev = aruba_evidence()
    for c in ev["claims"]:
        for r in c["remediations"]:
            r["availability_date"] = "2027-01-01"
    reidentify(ev)
    result = build(ev)
    assert not result["releases"]
    assert {d["code"] for d in result["diagnostics"]} == {"future_fix_availability_excluded"}
    ev = aruba_evidence()
    for c in ev["claims"]:
        c["publisher"]["status"] = "draft"
    reidentify(ev)
    result = build(ev)
    assert not result["releases"]
    assert {d["code"] for d in result["diagnostics"]} == {"draft_fixed_context_excluded"}


def test_wrong_family_or_product_does_not_supply_release_facts():
    ev = aruba_evidence()
    ev["claims"] = [c for c in ev["claims"] if c["status"] == "fixed"]
    for c in ev["claims"]:
        c["product"] = "Another publisher product"
    reidentify(ev)
    assert not build(ev)["releases"]
    for c in ev["claims"]:
        c["product"] = "AOS-CX"
        c["family"] = "arista-eos"
        c["scope_level"] = "os_family"
        c["platform_bindings"] = []
        c["named_platforms"] = []
        if "model_binding_unresolved" not in c["issues"]:
            c["issues"].append("model_binding_unresolved")
    reidentify(ev)
    assert not build(ev)["releases"]


def test_support_minima_and_bundle_membership_remain_literal_context():
    from test_software_release_sources import ARISTA, MODELS, bundle

    value = frame(MODELS, sources.parse_aruba_support_10_14(models()))
    bundle_frame = frame(ARISTA, sources.parse_arista_0148(bundle()))
    result = build(frames=[value, bundle_frame])
    assert result["platform_support"][0]["sku"] == "R8S89A"
    assert result["platform_support"][0]["minimum_version"] == "10.10.0002"
    assert not any(n["version"] == "10.10.0002" for n in result["releases"])
    node = result["bundles"][0]
    assert node["initial_published_at"] == "2026-09-02"
    assert node["member_publication_date"] == "2026-09-09"
    assert node["member_advisory_ids"] == [str(i) for i in range(149, 179)]
    source = next(s for s in result["sources"] if s["source_id"] == ARISTA)
    assert len(source["issues"]) == 4
    assert all("Excluded non-EOS member" in issue for issue in source["issues"])


def test_release_date_unknown_and_conflicts_preserve_each_platform_context():
    result = build(frames=[frame()])
    node = release(result, "10.14.0007")
    alternative = copy.deepcopy(node["history"][0])
    alternative.update(platforms=["6400 Switch Series"], reported_release_date="2024-07-15")
    unknown = copy.deepcopy(alternative)
    unknown["reported_release_date"] = None
    node["history"].extend([alternative, unknown])
    node["reported_release_dates"] = ["2024-07-12", "2024-07-15"]
    node["issues"].append("conflicting_release_dates")
    selected = api().select_report(result, study(aruba_evidence()))
    selected_node = release(selected, "10.14.0007")
    assert selected_node["reported_release_dates"] == ["2024-07-12", "2024-07-15"]
    assert len(selected_node["history"]) == 3
    assert any(h["reported_release_date"] is None for h in selected_node["history"])


def test_current_report_rejects_forged_derived_counts_and_wrong_generation():
    result = build()
    result["releases"][0]["vendor_reported_fixed_cve_count"] = 900
    with pytest.raises(ValueError):
        api().select_report(result, study(aruba_evidence()))
    result = build()
    result["generated_at"] = "2025-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        api().select_report(result, study(aruba_evidence()))


def test_publication_writer_rejects_forged_current_claim_references(tmp_path):
    from test_static_delivery import dataset

    data = dataset()
    data["research"]["switching_input"] = aruba_evidence()
    out = publication.publish(data, tmp_path / "good")
    projected = json.loads((out / "snapshot.json").read_text())
    for name in ("switching_comparison", "switching_evidence", "switching_release_history"):
        projected[name] = json.loads((out / (name.replace("_", "-") + ".json")).read_text())
    projected["switching_release_history"]["releases"][0]["references"][0]["claim_id"] = "f" * 64
    with pytest.raises(ValueError, match="reference"):
        publication.write_bundle(tmp_path / "forged", projected)


@pytest.mark.parametrize("fmt", ["v1", "v2"])
def test_native_parity_rebuilds_history_from_independent_source_input(tmp_path, monkeypatch, fmt):
    from io import StringIO

    from test_static_delivery import dataset

    from infrastructure_impact.application import import_candidate, publication_v2, query
    from infrastructure_impact.collection import config
    from infrastructure_impact.storage import repository

    native = dataset()
    native["research"]["switching_input"] = aruba_evidence()
    native["research"]["release_input"] = [frame()]
    out = publication.publish(native, tmp_path / "published", publication_format=fmt)
    monkeypatch.setattr(repository, "connect", lambda *args, **kwargs: StringIO())
    monkeypatch.setattr(query, "state", lambda db: copy.deepcopy(native))
    monkeypatch.setattr(config, "load_config", lambda: {})

    def verify():
        if fmt == "v1":
            import_candidate._parity(
                "synthetic-native-only",
                out,
                tmp_path,
                json.loads((out / "snapshot.json").read_text()),
            )
        else:
            publication_v2.native_parity(
                "synthetic-native-only", out, tmp_path, PublicationReader(out)
            )

    verify()
    native["research"]["release_input"] = []
    with pytest.raises(ValueError, match="parity|mismatch"):
        verify()


def test_unowned_affected_remediation_prose_cannot_supply_a_literal_fix():
    ev = aruba_evidence()
    for c in ev["claims"]:
        if c["status"] != "affected":
            continue
        for rem in c["remediations"]:
            rem.pop("scope_binding", None)
            rem.update(
                product_ids=[],
                version_expressions=["10.14.0007"],
                details="Upgrade to 10.14.0007 and later releases",
            )
        if "remediation_product_scope_unresolved" not in c["issues"]:
            c["issues"].append("remediation_product_scope_unresolved")
    reidentify(ev)
    result = build(ev)
    assert release(result, "10.14.0007")["affected_scope_cve_count"] is None


def test_projection_drops_private_frames_before_any_general_json_clone():
    from test_static_delivery import dataset

    data = dataset()
    data["research"]["switching_input"] = aruba_evidence()
    value = frame()
    value["private"] = object()
    value["retained"]["private"] = object()
    data["research"]["release_input"] = [value]
    result = publication.public_projection(data)
    assert release(result["switching_release_history"], "10.14.0007")["history"]


@pytest.mark.parametrize("path", ["history", "platform_support", "bundle"])
def test_report_validation_rejects_unregistered_public_context_source(path):
    from test_software_release_sources import ARISTA, MODELS, bundle

    result = build(
        frames=[
            frame(),
            frame(MODELS, sources.parse_aruba_support_10_14(models())),
            frame(ARISTA, sources.parse_arista_0148(bundle())),
        ]
    )
    if path == "history":
        context = release(result, "10.14.0007")["history"][0]
    elif path == "platform_support":
        context = result["platform_support"][0]
    else:
        context = result["bundles"][0]
    context["source"]["source_url"] = "https://evil.example/private"
    with pytest.raises(ValueError):
        api().validate_report(result)


def test_shared_compact_selection_vectors():
    from infrastructure_impact.settings import PACKAGE

    fixture = json.loads(
        (PACKAGE.parent / "tests/fixtures/switching-release-history-vectors.json").read_text()
    )
    for vector in fixture["vectors"]:
        selected = api().select_report(
            fixture["histories"][vector["history"]], vector["study_selection"]
        )
        expected = vector["expected"]
        assert selected["availability"] == expected["availability"], vector["name"]
        assert [n["version"] for n in selected["releases"]] == expected["versions"], vector["name"]
        node = next((n for n in selected["releases"] if n["version"] == "10.14.0007"), None)
        if node:
            assert node["vendor_reported_fixed_cve_count"] == expected["fixed_count_10_14_0007"], (
                vector["name"]
            )
            assert node["affected_scope_cve_count"] == expected["affected_count_10_14_0007"], (
                vector["name"]
            )
        assert "claim_ids" not in json.dumps(vector["study_selection"])


def test_selected_fixed_only_claim_keeps_release_context_without_affectedness():
    ev = aruba_evidence()
    ev["claims"] = [c for c in ev["claims"] if c["status"] == "fixed"]
    selected_study = study(ev, vendor="aruba", window="2024")
    assert selected_study["rows"][0]["affected_cve_ids"] == []
    selected = api().select_report(build(ev), selected_study)
    node = release(selected, "10.14.0007")
    assert node["vendor_reported_fixed_cve_count"] == 1
    assert node["affected_scope_cve_count"] is None
    assert not any(
        r["kind"] == "affected_scope_fix" for n in selected["releases"] for r in n["references"]
    )


def test_source_owned_arista_fixed_statement_with_planned_availability_stays_diagnostic():
    ev = arista_evidence(CASES[0])
    ev["claims"] = [c for c in ev["claims"] if c["status"] == "fixed"]
    for c in ev["claims"]:
        for remediation in c["remediations"]:
            remediation["availability"] = "planned"
    reidentify(ev)
    result = build(ev)
    assert result["releases"] == []
    assert {d["code"] for d in result["diagnostics"]} == {"fixed_availability_conflicting"}
