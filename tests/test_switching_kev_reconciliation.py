"""Candidate membership cannot supply vendor affectedness or study chronology."""

import copy
import json
from pathlib import Path

import pytest

from infrastructure_impact.application import kev
from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.application import switching_kev_reconciliation as reconciliation
from infrastructure_impact.references.kev import parse

AT = "2026-11-13T12:00:00Z"
CID = "CVE-2026-7473"
BASE = json.loads((Path(__file__).parent / "fixtures/switching-cases.json").read_text())[
    "evidence"
]["claims"][0]


def claim(**changes):
    c = copy.deepcopy(BASE)
    c.update(cve_id=CID, initial_published_at="2026-05-05", bundle=None, scores=[])
    c.update(changes)
    return c


def inputs(claims=(), retained=(), records=(), scope="os_family", raw=None):
    if raw is None:
        raw = json.dumps(
            dict(
                catalogVersion="2026.11.13",
                dateReleased=AT,
                count=1,
                vulnerabilities=[
                    dict(
                        cveID=CID,
                        vendorProject="Arista",
                        product="Extensible Operating System",
                        vulnerabilityName="Example",
                        dateAdded="2026-11-12",
                        shortDescription="Example",
                        requiredAction="Review",
                        dueDate="2026-12-01",
                    )
                ],
            )
        ).encode()
    catalogue = parse(raw)
    k = kev.build_report(
        dict(
            configured=True,
            enabled=True,
            checked_at=AT,
            latest_attempt=dict(checked_at=AT, outcome="ok", error_code=None),
            retained=dict(
                catalogue=catalogue,
                sha256="a" * 64,
                revision_id="1",
                source_observed_at=AT,
                parsed_at=AT,
            ),
        ),
        list(catalogue["entries"]),
        publication=None,
        generated_at=AT,
    )
    e = evidence.project(
        dict(claims=list(claims), coverage=[], issues=[]), publication=None, generated_at=AT
    )
    selected = comparison.select_report(
        comparison.build_report(
            e,
            k,
            definition=evidence.definition(),
            publication=None,
            generated_at=AT,
            observation_end="2026-11-13",
        ),
        scope_level=scope,
        evaluated_at=AT,
    )
    inventory = dict(
        publication=None,
        generated_at=AT,
        definition_sha256=e["definition_sha256"],
        current_records=list(records),
        retained_records=list(retained),
    )
    return k, e, inventory, selected


def record(disposition="current", status="published"):
    return dict(
        vendor="arista",
        advisory_id="record-SA137",
        cve_ids=[CID],
        document_status=status,
        disposition=disposition,
        source=copy.deepcopy(BASE["source"]),
    )


def run(args, **changes):
    k, e, inventory, selected = args
    return reconciliation.build_report(
        k,
        evidence.definition(),
        e,
        inventory,
        publication=None,
        generated_at=AT,
        evaluated_at=changes.get("evaluated_at", AT),
        selection=selected,
    )


@pytest.mark.parametrize(
    "claims,records,retained,scope,state",
    [
        ([], [], [], "os_family", "no_observed_vendor_record"),
        ([], [], [record("excluded")], "os_family", "retained_only"),
        ([], [record()], [], "os_family", "observed_no_study_claim"),
        (
            [claim(publisher=dict(id="draft", sequence="1", status="draft"))],
            [],
            [],
            "os_family",
            "draft_only",
        ),
        (
            [claim(status="unaffected")],
            [],
            [],
            "model_qualified",
            "documented_unaffected_for_selected_scope",
        ),
        ([claim()], [], [], "os_family", "documented_affected"),
        (
            [claim(scope_level="os_family", platform_bindings=[], named_platforms=[])],
            [],
            [],
            "model_qualified",
            "affected_scope_unresolved",
        ),
        ([claim(status="conflicting")], [], [], "os_family", "conflicting_representations"),
        ([claim(initial_published_at="2020-01-01")], [], [], "os_family", "outside_study_window"),
        ([claim(initial_published_at=None)], [], [], "os_family", "unknown"),
    ],
)
def test_states(claims, records, retained, scope, state):
    result = run(inputs(claims, retained, records, scope))
    assert result["entries"][0]["claim_state"] == state
    assert result["summary"]["candidate_cves"] == 1
    assert result["summary"]["completeness"] == "not_established"


def test_stale_and_missing_catalogue_are_unknown_not_negative():
    args = inputs([claim()])
    result = run(args, evaluated_at="2026-11-16T12:00:00Z")
    assert result["entries"][0]["membership"] == "unknown"
    assert result["entries"][0]["historically_listed"] is True
    args[0].update(kev.build_report({}, [], publication=None, generated_at=AT))
    args[3]["inputs"]["kev"] = copy.deepcopy(args[0])
    # Rebuild selection rather than accepting forged selection inputs.
    args = inputs()
    k = kev.build_report({}, [], publication=None, generated_at=AT)
    selected = comparison.build_report(
        args[1],
        k,
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-13",
    )
    result = run((k, args[1], args[2], selected))
    assert result["availability"] == "not_configured"
    assert result["entries"] == []


def test_identity_closed_shape_and_no_mutation():
    args = inputs([claim(), claim(advisory_id="other")], retained=[record("excluded")])
    before = copy.deepcopy(args)
    r = run(args)
    assert args == before
    assert r["summary"]["candidate_cves"] == 1
    assert len(r["entries"][0]["current_claims"]) == 2
    assert r["entries"][0]["retained_records"][0]["advisory_id"] == "record-SA137"
    r["surprise"] = 1
    with pytest.raises(ValueError):
        reconciliation.validate_report(r)
    args[2]["generated_at"] = "2026-11-12T12:00:00Z"
    with pytest.raises(ValueError, match="generation"):
        run(args)


def test_no_fuzzy_mapping_and_no_aoscx_absence_inference():
    args = list(inputs())
    args[0]["entries"][CID]["product"] = "Extensible Operating System appliance"
    args[3] = comparison.build_report(
        args[1],
        args[0],
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-13",
    )
    r = run(args)
    assert r["entries"][0]["mapping"]["status"] == "unmapped"
    assert r["summary"]["candidate_cves"] == 0
    assert r["family_observations"]["aruba-aoscx"] == "no_matching_catalogue_pair_observed"


def test_default_discovery_and_explicit_filter_never_expand_affected_totals():
    args = list(inputs())
    original = copy.deepcopy(args[3]["rows"])
    r = run(args)
    assert r["entries"][0]["in_requested_cve_filter"] is True
    assert r["entries"][0]["in_effective_study_cohort"] is False
    assert r["entries"][0]["claim_state"] == "no_observed_vendor_record"
    args[3] = comparison.select_report(args[3], cve_ids=["CVE-2025-99999"], evaluated_at=AT)
    r = run(args)
    assert r["entries"][0]["in_requested_cve_filter"] is False
    assert "outside_explicit_cve_filter" in r["entries"][0]["reason_codes"]
    assert args[3]["rows"] == original


def test_unresolved_binding_and_inventory_factory_preserve_capture_ids():
    args = list(
        inputs(
            [
                claim(
                    scope_level="os_family",
                    named_platforms=["750X"],
                    platform_bindings=[
                        dict(platform="750X", model=None, basis="unresolved", source=BASE["source"])
                    ],
                )
            ]
        )
    )
    raw = dict(
        vendor="arista",
        advisory_id="SA137",
        cves=[CID],
        document_status="draft",
        source_url=BASE["source"]["source_url"],
        sha256="b" * 64,
        source_observed_at=AT,
        revision_id=123,
        evidence_id=456,
    )
    args[2] = reconciliation.build_inventory(
        [], [raw], publication=None, generated_at=AT, study_definition=evidence.definition()
    )
    result = run(args)
    assert result["entries"][0]["retained_records"][0]["evidence_id"] == 456
    assert result["entries"][0]["current_claims"][0]["models"] == []


@pytest.mark.parametrize("mutation", ["definition", "selection", "summary", "mapping", "cohort"])
def test_mismatched_inputs_and_tampered_report_rejected(mutation):
    args = list(inputs())
    if mutation == "definition":
        args[2]["definition_sha256"] = "0" * 64
        with pytest.raises(ValueError):
            run(args)
    elif mutation == "selection":
        args[3]["selection"]["effective_cve_ids"] = [CID]
        with pytest.raises(ValueError):
            run(args)
    else:
        result = run(args)
        if mutation == "summary":
            result["summary"]["candidate_cves"] += 1
        elif mutation == "mapping":
            result["entries"][0]["mapping"]["family"] = "aruba-aoscx"
        else:
            result["entries"][0]["in_effective_study_cohort"] = True
        with pytest.raises(ValueError):
            reconciliation.validate_report(result)


@pytest.mark.parametrize(
    "label",
    [
        "IOS Software",
        "IOS XR Software",
        "IOS XE",
        "ios xe software",
        "IOS XE Software and Other Products",
        "VeloCloud Orchestrator",
    ],
)
def test_unreviewed_and_ambiguous_labels_remain_unmapped(label):
    args = list(inputs())
    args[0]["entries"][CID].update(vendorProject="Cisco", product=label)
    args[3] = comparison.build_report(
        args[1],
        args[0],
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-13",
    )
    assert run(args)["entries"][0]["mapping"]["status"] == "unmapped"


@pytest.mark.parametrize(
    "source_change,availability",
    [
        (
            {
                "latest_attempt": {
                    "checked_at": AT,
                    "outcome": "error",
                    "error_code": "fetch_failed",
                }
            },
            "failed",
        ),
        ({"enabled": False}, "disabled"),
        ({"checked_at": "2026-11-14T12:00:00Z"}, "future"),
    ],
)
def test_nonfresh_retained_catalogue_membership_is_unknown(source_change, availability):
    args = list(inputs())
    args[0]["source"].update(source_change)
    # select_report owns reevaluation and schema supplies bounded attempt codes.
    args[0] = kev.select_report(args[0], [CID], evaluated_at=AT)
    args[3] = comparison.build_report(
        args[1],
        args[0],
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-13",
    )
    r = run(args)
    assert r["availability"] == availability
    assert r["entries"][0]["membership"] == "unknown"
    assert r["summary"]["candidate_cves"] == 1


def test_selected_vendor_does_not_relabel_other_family_catalogue_observations():
    args = list(inputs())
    args[3] = comparison.select_report(args[3], vendor="cisco", evaluated_at=AT)
    r = run(args)
    assert r["entries"] == []
    assert r["family_observations"]["arista-eos"] == "matching_catalogue_pair_observed"


def test_partial_detailed_catalogue_cannot_claim_no_matching_pair():
    args = list(inputs())
    args[0]["entries"] = {}
    args[3] = comparison.build_report(
        args[1],
        args[0],
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-13",
    )
    r = run(args)
    assert set(r["family_observations"].values()) == {"catalogue_details_incomplete"}


def test_unaffected_unresolved_scope_is_unknown_not_an_affected_claim():
    r = run(
        inputs(
            [
                claim(
                    status="unaffected",
                    scope_level="os_family",
                    platform_bindings=[],
                    named_platforms=[],
                )
            ],
            scope="model_qualified",
        )
    )
    assert r["entries"][0]["claim_state"] == "unknown"
    assert "selected_model_binding_unresolved" in r["entries"][0]["reason_codes"]


def test_opposing_current_statements_for_same_literal_scope_are_conflicting():
    r = run(inputs([claim(), claim(status="unaffected", advisory_id="other")]))
    assert r["entries"][0]["claim_state"] == "conflicting_representations"
