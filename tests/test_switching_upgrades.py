"""Authored immediate-remediation walks, never customer operation observations."""

import copy
import csv
import importlib
import io
import json

import pytest
from test_switching_release_history import cisco_evidence

from infrastructure_impact.application import first_fixed, kev
from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as contracts

AT = "2026-11-13T00:00:00Z"


def api():
    return importlib.import_module("infrastructure_impact.application.switching_upgrades")


def inputs(vectors):
    base = cisco_evidence()["claims"][0]
    claims = []
    for i, (date, versions) in enumerate(vectors):
        c = copy.deepcopy(base)
        c.update(advisory_id=f"authored-{i}", initial_published_at=date)
        c["publisher"]["id"] = c["advisory_id"]
        c["remediations"][0]["version_expressions"] = versions
        claims.append(c)
    ev = contracts.project(
        dict(claims=claims, coverage=[], issues=[]), publication=None, generated_at=AT
    )
    ff = first_fixed.build_report([], api_results=[], publication=None, generated_at=AT)
    k = kev.build_report({}, [], publication=None, generated_at=AT)
    return ev, ff, k


def build(vectors):
    ev, ff, k = inputs(vectors)
    return api().build_report(ev, ff, None, k, publication=None, generated_at=AT)


def row(report, year, scenario="known_fixed_target", policy="all_affected"):
    return next(
        r
        for r in report["rows"]
        if (r["train"], r["year"], r["scenario"], r["policy"]) == ("17.15", year, scenario, policy)
    )


def test_walk_groups_days_chooses_earliest_alternative_and_carries_year():
    out = build(
        [
            ("2024-12-31", ["17.15.1", "17.15.2"]),
            ("2024-12-31", ["17.15.3"]),
            ("2025-01-01", ["17.15.2"]),
            ("2025-02-01", ["17.15.4"]),
        ]
    )
    assert row(out, 2024)["event_count"] == 1
    assert row(out, 2025)["event_count"] == 1
    assert row(out, 2025)["start_version"] == "17.15.3"
    assert row(out, 2025)["events"][0]["target"] == "17.15.4"
    assert row(out, 2024, "publisher_first_fixed")["event_count"] is None
    assert row(out, 2024, policy="high_risk")["event_count"] is None


def test_no_evidence_is_unknown_and_required_trains_exist():
    out = build([])
    assert {r["train"] for r in out["rows"]} >= {
        "17.9",
        "17.12",
        "17.15",
        "10.13",
        "10.14",
        "10.16",
        "4.32",
        "4.33",
        "4.34",
    }
    assert all(r["event_count"] is None for r in out["rows"])


def test_inputs_immutable_and_csv_typed_parity_and_bounds():
    ev, ff, k = inputs([("2024-01-01", ["17.15.1"])])
    before = copy.deepcopy((ev, ff, k))
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert (ev, ff, k) == before
    lines = list(csv.DictReader(io.StringIO(api().csv_export(out))))
    nested = {"events", "unresolved", "affected_claim_ids"}
    numbers = {"year", "event_count", "supported_event_count"}
    nullable = {"event_count", "start_version", "end_version"}
    decoded = []
    for line in lines:
        decoded.append(
            {
                key: json.loads(value)
                if key in nested
                else None
                if key in nullable and value == ""
                else int(value)
                if key in numbers
                else value == "true"
                if key == "partial_year"
                else value
                for key, value in line.items()
            }
        )
    assert decoded == out["rows"]
    with pytest.raises(ValueError):
        api().csv_export(out, max_bytes=10)
    out["unexpected"] = True
    with pytest.raises(ValueError):
        api().validate_report(out)


def test_selection_keeps_pre_window_state_and_rejects_wrong_generation():
    ev, ff, k = inputs([("2024-12-31", ["17.15.3"]), ("2025-02-01", ["17.15.2"])])
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    study = comparison.build_report(
        ev,
        k,
        definition=contracts.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    selected = comparison.select_report(study, vendor="cisco", window="2025", evaluated_at=AT)
    result = api().select_report(out, selected)
    assert row(result, 2025)["event_count"] == 0
    assert row(result, 2025)["start_version"] == "17.15.3"
    selected["generated_at"] = "2026-11-12T00:00:00Z"
    with pytest.raises(ValueError):
        api().select_report(out, selected)


def test_preferred_official_fallback_high_qualifies_and_vendor_low_takes_precedence():
    c = {
        "cve_id": "CVE-2024-6387",
        "product_id": None,
        "scores": [
            dict(
                origin="nvd",
                preferred=True,
                scope="cve_specific",
                cve_id="CVE-2024-6387",
                product_ids=[],
                validation="valid",
                system="CVSS",
                version="3.1",
                value=9.8,
                provider="nvd",
            )
        ],
    }
    assert api()._risk(c, "unknown")[0] is True
    c["scores"].append(dict(c["scores"][0], origin="vendor_advisory", provider="vendor", value=3.1))
    assert api()._risk(c, "not_listed")[0] is False
    assert api()._risk(c, "unknown")[0] is None
    assert api()._risk(c, "listed")[0] is True


def test_unknown_dates_and_unsupported_versions_remain_unresolved():
    out = build([(None, ["17.15.1"]), ("2025-01-01", ["17.15.2w"])])
    assert row(out, 2025)["event_count"] is None
    assert row(out, 2025)["unresolved"]


def test_same_utc_day_groups_timezone_dates_and_duplicate_cve_advisories():
    out = build([("2024-12-31T23:00:00Z", ["17.15.1"]), ("2025-01-01T00:30:00+02:00", ["17.15.2"])])
    assert row(out, 2024)["event_count"] == 1
    assert row(out, 2024)["events"][0]["target"] == "17.15.2"
    assert len(row(out, 2024)["events"][0]["claim_ids"]) == 2


def test_validation_rejects_target_tampering_even_if_rows_recomputed():
    out = build([("2025-01-01", ["17.15.1"])])
    c = next(c for c in out["constraints"] if c["target"])
    c["target"] = "17.15.99"
    out["rows"] = api()._rows(
        out["constraints"], end=out["observation_end"], vendors=list(api().TRAINS)
    )
    with pytest.raises(ValueError):
        api().validate_report(out)


def test_first_fixed_exact_receipt_binding_and_conflicts():
    from test_first_fixed import record

    ev, _, k = inputs([("2025-01-01", ["17.15.3"])])
    claim = ev["claims"][0]
    r = record(claim["advisory_id"], ["17.15.1"], ["17.15.2"])
    r.update(
        source_url=claim["source"]["source_url"],
        sha256=claim["source"]["source_sha256"],
        source_observed_at=claim["source"]["retrieved_at"],
    )
    r["first_fixed"][0].update(train="17.15", train_expression="17.15", cve_ids=[claim["cve_id"]])
    ff = first_fixed.build_report([r], api_results=[], publication=None, generated_at=AT)
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert row(out, 2025, "publisher_first_fixed")["events"][0]["target"] == "17.15.2"
    r["sha256"] = "f" * 64
    ff = first_fixed.build_report([r], api_results=[], publication=None, generated_at=AT)
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert row(out, 2025, "publisher_first_fixed")["event_count"] is None


def test_api_only_requires_current_affected_query_and_exposes_api_proof():
    from test_first_fixed import api_frame, record

    ev, _, k = inputs([("2025-01-01", ["17.15.3"])])
    raw = copy.deepcopy(ev)
    raw["claims"][0]["version_expressions"] = ["17.15.1"]
    ev = contracts.project(raw, publication=None, generated_at=AT)
    c = ev["claims"][0]
    r = record(c["advisory_id"], ["17.15.1"])
    r["assessments"][0]["cve_id"] = c["cve_id"]
    ff = first_fixed.build_report(
        [r],
        api_results=[api_frame(c["advisory_id"], "17.15.1", ["17.15.2"], [c["cve_id"]])],
        publication=None,
        generated_at=AT,
    )
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert row(out, 2025, "publisher_first_fixed")["events"][0]["target"] == "17.15.2"
    assert any(
        p["kind"] == "publisher_api_first_fixed" for c in out["constraints"] for p in c["proof"]
    )


def test_selected_cve_walk_recomputes_previously_redundant_requirement():
    ev, ff, k = inputs([("2025-01-01", ["17.15.3"]), ("2025-02-01", ["17.15.2"])])
    raw = copy.deepcopy(ev)
    c = raw["claims"][1]
    c["cve_id"] = "CVE-2025-99999"
    c["remediations"][0]["scope_binding"]["cve_id"] = c["cve_id"]
    ev = contracts.project(raw, publication=None, generated_at=AT)
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    study = comparison.build_report(
        ev,
        k,
        definition=contracts.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    selected = comparison.select_report(study, cve_ids=["CVE-2025-99999"], evaluated_at=AT)
    result = api().select_report(out, selected)
    assert row(result, 2025)["event_count"] == 1
    assert row(result, 2025)["events"][0]["target"] == "17.15.2"
    assert row(result, 2025)["events"][0]["previous"] is None


@pytest.mark.parametrize("left,right", [("4.32.1F", "4.32.1M"), ("4.32.1F", "4.32.1.0F")])
def test_eos_incomparable_alternatives_never_form_target(left, right):
    assert api()._minimum("arista", [left, right], "4.32") is None


def test_cisco_inference_is_only_inclusive_and_keeps_heldout_source():
    from test_first_fixed import record

    ev, _, k = inputs([("2025-01-01", [])])
    raw = copy.deepcopy(ev)
    raw["claims"][0]["version_expressions"] = ["17.15.1"]
    ev = contracts.project(raw, publication=None, generated_at=AT)
    c = ev["claims"][0]
    r = record(c["advisory_id"], ["17.15.1"])
    r.update(
        source_url=c["source"]["source_url"],
        sha256=c["source"]["source_sha256"],
        source_observed_at=c["source"]["retrieved_at"],
    )
    other = record("heldout", ["17.15.2"])
    ff = first_fixed.build_report([r, other], api_results=[], publication=None, generated_at=AT)
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert row(out, 2025, "inferred_inclusive")["events"][0]["target"] == "17.15.2"
    assert row(out, 2025, "known_fixed_target")["event_count"] is None
    assert any(
        p["source"]["source_url"] == other["source_url"]
        for c in out["constraints"]
        for p in c["proof"]
    )


def test_future_capture_is_visible_not_a_usable_target():
    ev, ff, k = inputs([("2025-01-01", ["17.15.3"])])
    raw = copy.deepcopy(ev)
    for c in raw["claims"]:
        c["source"]["retrieved_at"] = "2027-01-01T00:00:00Z"
        for rem in c["remediations"]:
            rem["source"]["retrieved_at"] = "2027-01-01T00:00:00Z"
            rem["scope_binding"]["source"]["retrieved_at"] = "2027-01-01T00:00:00Z"
    ev = contracts.project(raw, publication=None, generated_at=AT)
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert row(out, 2025)["event_count"] is None
    assert any("future_source_receipt" in u["issues"] for u in row(out, 2025)["unresolved"])
    assert out["kev_context"]["evaluated_at"] == AT


def test_inference_groups_all_affected_leaf_versions_before_predicting():
    from test_first_fixed import record

    ev, _, k = inputs([("2025-01-01", []), ("2025-01-01", [])])
    raw = copy.deepcopy(ev)
    for c, v in zip(raw["claims"], ["17.15.1", "17.15.9"], strict=True):
        c["advisory_id"] = "same-advisory"
        c["publisher"]["id"] = "same-advisory"
        c["version_expressions"] = [v]
    ev = contracts.project(raw, publication=None, generated_at=AT)
    ff = first_fixed.build_report(
        [record("heldout", ["17.15.2", "17.15.10"])],
        api_results=[],
        publication=None,
        generated_at=AT,
    )
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    inferred = [
        c for c in out["constraints"] if c["scenario"] == "inferred_inclusive" and c["target"]
    ]
    assert {c["target"] for c in inferred} == {"17.15.10"}
    assert all(c["inference"]["maximum_affected"] == "17.15.9" for c in inferred)
    assert len(out["inference_groups"]) == 1
    assert len(out["inference_groups"][0]["affected_claim_ids"]) == 2
    assert {c["inference"]["group_id"] for c in inferred} == {
        out["inference_groups"][0]["group_id"]
    }


def test_pre_window_does_not_leak_later_same_year_target_or_unknown():
    ev, ff, k = inputs([("2026-01-01", ["17.15.1"]), ("2026-09-01", ["17.15.4"])])
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    study = comparison.build_report(
        ev,
        k,
        definition=contracts.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    selected = comparison.select_report(study, window="pre", evaluated_at=AT)
    result = api().select_report(out, selected)
    assert row(result, 2026)["end_version"] == "17.15.1"
    assert row(result, 2026)["event_count"] == 1


def test_explicit_same_train_bounds_bind_without_inferring_a_fixed_version():
    c = {"vendor": "aruba", "version_expressions": ["vers:semver/>=10.13.0000|<=10.13.1005"]}
    trains, binding = api()._affected_trains(c)
    assert trains == {"10.13"}
    assert binding["basis"] == "same_train_bounded_range"
    assert binding["expressions"] == c["version_expressions"]
    c["version_expressions"] = ["vers:semver/>=10.13.0000|<=10.14.1005"]
    assert api()._affected_trains(c)[0] == set()
    c.update(vendor="arista", version_expressions=["EOS version 4.32.2"])
    assert api()._affected_trains(c)[0] == {"4.32"}


def test_native_preferred_fallback_survives_unpreferred_vendor_context():
    score = dict(
        origin="nvd",
        preferred=True,
        scope="cve_specific",
        cve_id="CVE-2024-6387",
        product_ids=[],
        validation="valid",
        system="CVSS",
        version="3.1",
        value=9.8,
        provider="nvd",
    )
    c = dict(
        cve_id="CVE-2024-6387",
        product_id=None,
        scores=[score, dict(score, origin="vendor_advisory", preferred=False, value=3.1)],
    )
    assert api()._risk(c, "not_listed")[0] is True


def test_unassigned_migration_cannot_veto_explicit_fixed_train():
    from test_first_fixed import record

    ev, _, k = inputs([("2025-01-01", ["17.15.3"])])
    raw = copy.deepcopy(ev)
    raw["claims"][0]["version_expressions"] = ["17.15", "17.15.1"]
    ev = contracts.project(raw, publication=None, generated_at=AT)
    c = ev["claims"][0]
    r = record(c["advisory_id"], ["17.15.1"], ["17.15.2"])
    r.update(
        source_url=c["source"]["source_url"],
        sha256=c["source"]["source_sha256"],
        source_observed_at=c["source"]["retrieved_at"],
    )
    r["first_fixed"][0].update(train="17.15", train_expression="17.15", cve_ids=[c["cve_id"]])
    r["first_fixed"].append(
        dict(
            r["first_fixed"][0],
            train=None,
            train_expression="17.8 and earlier",
            disposition="migrate",
            fixed_versions=[],
        )
    )
    ff = first_fixed.build_report([r], api_results=[], publication=None, generated_at=AT)
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert row(out, 2025, "publisher_first_fixed")["event_count"] == 1
    assert row(out, 2025, "publisher_first_fixed")["events"][0]["target"] == "17.15.2"
    trains, binding = api()._affected_trains(
        dict(vendor="cisco", version_expressions=["3.2SG", "3.2.0SG"])
    )
    assert trains == {"3.2"}
    assert binding["unsupported"] is True


def test_earlier_train_migration_does_not_apply_to_unlisted_later_train():
    from test_first_fixed import record

    ev, _, k = inputs([("2025-01-01", [])])
    raw = copy.deepcopy(ev)
    raw["claims"][0]["version_expressions"] = ["17.10.1"]
    ev = contracts.project(raw, publication=None, generated_at=AT)
    c = ev["claims"][0]
    r = record(c["advisory_id"], ["17.10.1"], ["17.9.2"])
    r.update(
        source_url=c["source"]["source_url"],
        sha256=c["source"]["source_sha256"],
        source_observed_at=c["source"]["retrieved_at"],
    )
    r["first_fixed"][0].update(
        train=None,
        train_expression="17.8 and earlier",
        cve_ids=[c["cve_id"]],
        disposition="migrate",
        fixed_versions=[],
    )
    ff = first_fixed.build_report([r], api_results=[], publication=None, generated_at=AT)
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert all("first_fixed_migration" not in c["issues"] for c in out["constraints"])
    assert out["source_groups"][0]["train_expression"] == "17.8 and earlier"
    assert all(c["target"] is None for c in out["constraints"])


def test_shared_bundle_high_metric_does_not_leak_to_selected_low_cve():
    from infrastructure_impact.adapters.cvss import public_metrics

    ev, ff, k = inputs([("2025-01-01", ["17.15.3"]), ("2025-01-01", ["17.15.2"])])
    raw = copy.deepcopy(ev)
    ids = [c["advisory_id"] for c in raw["claims"]]
    for index, c in enumerate(raw["claims"]):
        c["cve_id"] = f"CVE-2025-{10000 + index}"
        c["remediations"][0]["scope_binding"]["cve_id"] = c["cve_id"]
        c["bundle"] = dict(
            publisher_id="authored-bundle",
            title="Shared bulletin",
            member_advisory_ids=ids,
            published_at="2025-01-01",
            source=copy.deepcopy(c["source"]),
        )
        c["scores"] = public_metrics(
            [
                dict(
                    system="CVSS",
                    version="3.1",
                    value=7.5 if index == 0 else 3.1,
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cve_id=c["cve_id"],
                    product_ids=[],
                    scope="cve_specific",
                    source=copy.deepcopy(c["source"]),
                    origin="vendor_advisory",
                    validation="valid",
                    provider="Cisco",
                )
            ]
        )
    ev = contracts.project(raw, publication=None, generated_at=AT)
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    study = comparison.build_report(
        ev,
        k,
        definition=contracts.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    selected = comparison.select_report(study, cve_ids=["CVE-2025-10001"], evaluated_at=AT)
    result = api().select_report(out, selected)
    assert row(result, 2025)["events"][0]["target"] == "17.15.2"
    assert row(result, 2025, policy="high_risk")["supported_event_count"] == 0
    assert row(result, 2025, policy="high_risk")["event_count"] is None


def test_stated_fixed_target_does_not_require_ordering_affected_leaf():
    from test_first_fixed import record

    ev, _, k = inputs([("2025-01-01", [])])
    raw = copy.deepcopy(ev)
    raw["claims"][0]["version_expressions"] = ["17.15.1w"]
    ev = contracts.project(raw, publication=None, generated_at=AT)
    c = ev["claims"][0]
    r = record(c["advisory_id"], [], ["17.15.2"])
    r.update(
        source_url=c["source"]["source_url"],
        sha256=c["source"]["source_sha256"],
        source_observed_at=c["source"]["retrieved_at"],
    )
    r["first_fixed"][0].update(train="17.15", train_expression="17.15", cve_ids=[c["cve_id"]])
    ff = first_fixed.build_report([r], api_results=[], publication=None, generated_at=AT)
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    assert row(out, 2025, "publisher_first_fixed")["event_count"] == 1
    assert row(out, 2025, "publisher_first_fixed")["events"][0]["target"] == "17.15.2"
    assert all(c["train_binding"]["unsupported"] for c in out["constraints"])


@pytest.mark.parametrize(
    "shape", ["same_leaf_range", "separate_range", "separate_variant", "unassigned_leaf"]
)
def test_inference_abstains_when_complete_owned_maximum_is_unprovable(shape):
    from test_first_fixed import record

    expressions = ["17.15.1", "vers:semver/>=17.15.1|<=17.15.9"]
    if shape == "separate_variant":
        expressions[1] = "17.15.9w"
    elif shape == "unassigned_leaf":
        expressions[1] = "affected versions unspecified"
    ev, _, k = inputs([("2025-01-01", [])] * (1 if shape == "same_leaf_range" else 2))
    raw = copy.deepcopy(ev)
    for index, claim in enumerate(raw["claims"]):
        claim["advisory_id"] = "complete-owned-group"
        claim["publisher"]["id"] = claim["advisory_id"]
        claim["version_expressions"] = (
            expressions if shape == "same_leaf_range" else [expressions[index]]
        )
    ev = contracts.project(raw, publication=None, generated_at=AT)
    ff = first_fixed.build_report(
        [record("heldout", ["17.15.2", "17.15.10"])],
        api_results=[],
        publication=None,
        generated_at=AT,
    )
    out = api().build_report(ev, ff, None, k, publication=None, generated_at=AT)
    inferred = [c for c in out["constraints"] if c["scenario"] == "inferred_inclusive"]
    assert all(c["target"] is None for c in inferred)
    assert any("inference_group_incomplete" in c["issues"] for c in inferred)
    assert out["inference_groups"] == []


def test_csv_scalar_missing_boolean_and_escaped_nested_values():
    out = build([("2025-01-01", [])])
    c = out["constraints"][0]
    c["train"] = '=1+1,"typed train"\nnext line'
    c["issues"] = ['literal comma, quote " and newline\nvalue', ""]
    out["rows"] = api()._rows(
        out["constraints"], end=out["observation_end"], vendors=list(api().TRAINS)
    )
    lines = list(csv.DictReader(io.StringIO(api().csv_export(out))))
    escaped = next(r for r in lines if "typed train" in r["train"])
    assert escaped["vendor"] == "cisco"
    assert escaped["train"] == "'" + c["train"]
    assert escaped["event_count"] == ""
    assert escaped["start_version"] == ""
    assert escaped["partial_year"] in ("true", "false")
    annual = next(r for r in lines if "typed train" in r["train"] and r["year"] == "2025")
    assert json.loads(annual["unresolved"])[0]["issues"] == sorted(c["issues"])
