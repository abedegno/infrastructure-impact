"""Scope and public contracts for source-bound CVE research dossiers."""

import json
from contextlib import closing
from copy import deepcopy
from hashlib import sha256

import pytest
from jsonschema.exceptions import ValidationError

from infrastructure_impact.adapters.common import assessment, base
from infrastructure_impact.application.publication import public_projection
from infrastructure_impact.application.query import state
from infrastructure_impact.application.research_dossiers import (
    definition,
    fingerprint,
    research_dossiers,
    select_research_dossiers,
    validate_report,
)
from infrastructure_impact.settings import PACKAGE
from infrastructure_impact.storage.repository import connect


@pytest.fixture
def writer_seed():
    with closing(connect(":memory:")) as db:
        data = state(db)
    targets = json.loads((PACKAGE / "resources/build-pilot.json").read_text())["targets"]
    for index, target in enumerate(targets, 1):
        record = base(
            target["vendor"],
            target["source_url"],
            f"synthetic-dossier-{index}",
            "Synthetic source-bound build statement",
            "2024-07-08",
        )
        claim = assessment(
            "CVE-2024-6387",
            target["product_literal"],
            "fixed",
            f"Synthetic exact target row {index}",
            versions=[{"expression": target["expression"]}] if target["expression"] else [],
        )
        if target["vendor"] == "aruba":
            claim["product_context"] = [["product_version", "10.13.1031"]]
        claim["exposure"] = [
            {
                "category": "publisher_applicability",
                "details": "Synthetic statement applies only with SSH management enabled.",
                "source_locator": f"Synthetic prerequisite row {index}",
            }
        ]
        record.update(
            document_status="published",
            cves=["CVE-2024-6387"],
            assessments=[claim],
            evidence_id=index,
            revision_id=index,
            sha256=str(index) * 64,
            source_observed_at="2026-10-27T00:00:00Z",
            observed_at="2026-10-27T00:00:00Z",
        )
        data["records"].append(record)
    return data


@pytest.fixture
def seed(writer_seed):
    return public_projection(writer_seed)


def test_definition_binds_only_declared_cves_targets_and_cases():
    spec = definition()
    assert spec == {
        "schema_version": 1,
        "version": "2026-10-27.1",
        "entries": [
            {
                "id": "openssh-switching-6387",
                "cve_id": "CVE-2024-6387",
                "build_target_ids": ["arista-eos-4-32-2f", "aruba-aoscx-10-13-1031"],
                "case_ids": ["aruba-cx-release-date-gap", "hpe-cray-openssh-timing"],
            },
            {
                "id": "fortiproxy-curl-38545",
                "cve_id": "CVE-2023-38545",
                "build_target_ids": [],
                "case_ids": ["fortiproxy-curl-documented-fix"],
            },
            {
                "id": "fortiproxy-curl-38546",
                "cve_id": "CVE-2023-38546",
                "build_target_ids": [],
                "case_ids": ["fortiproxy-curl-documented-fix"],
            },
        ],
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s.update(schema_version=2),
        lambda s: s.update(schema_version=True),
        lambda s: s.update(version=""),
        lambda s: s.update(private_note="hidden"),
        lambda s: s["entries"][1].update(id=s["entries"][0]["id"]),
        lambda s: s["entries"][1].update(cve_id="CVE-2024-6387"),
        lambda s: s["entries"][0]["build_target_ids"].append("arista-eos-4-32-2f"),
        lambda s: s["entries"][0]["case_ids"].append("aruba-cx-release-date-gap"),
        lambda s: s["entries"][0].update(build_target_ids=["unknown-target"]),
        lambda s: s["entries"][0].update(case_ids=["unknown-case"]),
        lambda s: s["entries"][1].update(build_target_ids=["arista-eos-4-32-2f"]),
        lambda s: s["entries"][1].update(case_ids=["hpe-cray-openssh-timing"]),
        lambda s: s["entries"][0].update(cve_id="cve-2024-6387"),
        lambda s: s["entries"][0].update(extra="not part of scope"),
    ],
)
def test_invalid_definitions_fail_without_current_evidence(mutation):
    spec = definition()
    mutation(spec)
    with pytest.raises((ValueError, ValidationError)):
        definition(spec)


def test_definition_and_derivation_do_not_mutate_supplied_inputs(seed):
    spec = definition()
    before = deepcopy(spec)
    result = definition(spec)
    result["entries"][0]["case_ids"].clear()
    assert spec == before
    original_data = deepcopy(seed)
    report = research_dossiers(seed, spec)
    assert spec == before and seed == original_data
    report["dossiers"][0]["scope"]["case_ids"].clear()
    assert spec == before


def test_fingerprint_is_canonical_finite_json_and_includes_every_field():
    value = {"z": [2, 1], "a": "é"}
    # json.dumps default Unicode escaping is part of the existing canonical convention.
    expected = sha256(b'{"a":"\\u00e9","z":[2,1]}').hexdigest()
    assert fingerprint(value) == expected
    assert fingerprint({"a": "é", "z": [2, 1]}) == expected
    assert fingerprint({**value, "definition_sha256": "included"}) != expected
    with pytest.raises(ValueError):
        fingerprint({"value": float("nan")})
    with pytest.raises(ValueError):
        fingerprint({"value": float("inf")})


def test_scoped_contract_is_valid_without_evidence():
    report = research_dossiers({"records": [], "vendors": {}})
    validate_report(report)
    assert report["definition_version"] == "2026-10-27.1"
    assert report["definition_sha256"] == fingerprint(definition())
    assert [d["cve_id"] for d in report["dossiers"]] == [
        "CVE-2024-6387",
        "CVE-2023-38545",
        "CVE-2023-38546",
    ]
    assert all(d["sources"] == [] for d in report["dossiers"])
    assert all(d["scope"]["selected_vendor"] is None for d in report["dossiers"])
    assert report["dossiers"][0]["scope"]["comparison_role"] == (
        "SSH management on switching platforms"
    )
    assert report["dossiers"][1]["scope"]["comparison_role"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("inventory_verified", True),
        ("independent_human_review_completed", True),
        ("independent_release_availability_verified", True),
        ("earliest_disclosure_established", True),
        ("vendor_rate", 0),
        ("verified_fix_delay_days", 70),
        ("concealment_established", True),
    ],
)
def test_policy_limits_cannot_be_unlocked(seed, field, value):
    report = research_dossiers(seed)
    report["limits"][field] = value
    with pytest.raises(ValidationError):
        validate_report(report)


@pytest.mark.parametrize(
    "path",
    [(), ("limits",), ("dossiers", 0), ("dossiers", 0, "scope"), ("dossiers", 0, "chronology")],
)
def test_report_objects_reject_unexpected_fields(seed, path):
    report = research_dossiers(seed)
    obj = report
    for key in path:
        obj = obj[key]
    obj["private_note"] = "must not be published"
    with pytest.raises(ValidationError):
        validate_report(report)


def test_report_allows_existing_publication_envelope(seed):
    report = research_dossiers(seed)
    report.update(
        publication={"id": "synthetic-generation", "advisory_schema_version": 2},
        generated_at="2026-10-27T00:00:00Z",
    )
    validate_report(report)
    report["generated_at"] = "2026-10-27T00:00:00"
    with pytest.raises(ValidationError):
        validate_report(report)


def test_absent_old_generation_report_stays_absent():
    assert select_research_dossiers(None, ["CVE-2024-6387"]) is None


@pytest.fixture
def populated_contract(seed):
    """Handwritten public projection exercising the otherwise-empty contract sections."""
    report = research_dossiers(seed)
    dossier = report["dossiers"][0]
    source_id = "a" * 64
    dossier["sources"] = [
        {
            "id": source_id,
            "vendor": "arista",
            "source_url": "https://www.arista.com/example",
            "source_sha256": "b" * 64,
            "locators": [None, "Synthetic row"],
            "observations": ["2026-10-27T00:00:00Z"],
            "adapter_version": "synthetic-parser",
            "revision_id": 1,
            "evidence_id": 1,
        }
    ]
    dossier["comparison_targets"] = [
        {
            "target_id": "arista-eos-4-32-2f",
            "vendor": "arista",
            "product": "Arista EOS",
            "firmware_build": "4.32.2F",
            "statements": [
                {
                    "source_id": source_id,
                    "product_id": "original-product-id",
                    "product": "Arista EOS",
                    "product_family": None,
                    "product_context": [["product_version", "4.32.2F"]],
                    "status": "fixed",
                    "scope": "cve_specific",
                    "source_statuses": ["fixed"],
                    "versions": [{"expression": "4.32.2F and later releases in the 4.32.x train"}],
                    "remediations": [
                        {
                            "category": "vendor_fix",
                            "details": "Synthetic fix",
                            "availability": "vendor_reports_fixed",
                            "source_locator": None,
                        }
                    ],
                    "exposure": [
                        {
                            "category": "publisher_applicability",
                            "details": "Only with SSH",
                            "source_locator": "Synthetic prerequisite",
                        }
                    ],
                    "platforms": ["Synthetic platform"],
                    "evidence_locator": "Synthetic row",
                }
            ],
            "fields": [
                {"field": "component_version", "state": "unknown", "value": None, "evidence": []}
            ],
            "source_check": {"outcome": "not_checked", "checked_at": None, "error_code": None},
        }
    ]
    dossier["chronology"] = {
        "publisher_claims": [
            {
                "source_id": source_id,
                "field": "published_at",
                "value": "2024-07-08",
                "precision": "date",
                "locator": None,
            }
        ],
        "local_observations": [
            {
                "source_id": source_id,
                "value": "2026-10-27T00:00:00Z",
                "precision": "instant",
                "kind": "parser_reinterpretation",
                "locator": None,
                "event_id": "revision-1-CVE-2024-6387",
                "revision_id": 1,
                "evidence_id": 1,
                "history_truncated": False,
                "events_truncated": False,
            }
        ],
        "documentation_claims": [
            {
                "source_id": source_id,
                "value": "2024-07-08",
                "precision": "date",
                "kind": "initial_document_release",
                "locator": "Synthetic changelog",
            }
        ],
    }
    dossier["disclosure_context"] = [
        {
            "case_id": "hpe-cray-openssh-timing",
            "vendor": "hpe",
            "status": "incomplete_evidence",
            "product_scope": "Synthetic Cray scope",
            "question": "What evidence remains?",
            "source_ids": [],
            "investigation": None,
            "earlier_documents": [],
            "source_checks": [],
            "missing_evidence": ["Independent availability"],
            "alternative_explanations": ["An earlier notice may exist"],
            "release_source_state": "leads_only_not_verified",
        }
    ]
    dossier["evidence_gaps"] = [
        {
            "owner_kind": "case",
            "owner_id": "hpe-cray-openssh-timing",
            "field_or_question": "Historical availability",
            "evidence_sought": "Retained release listing",
            "access_state": "uncollected_lead",
        }
    ]
    return report


def test_populated_public_contract_is_valid(populated_contract):
    validate_report(populated_contract)


@pytest.mark.parametrize(
    "section",
    [
        "sources",
        "comparison_targets",
        "disclosure_context",
        "evidence_gaps",
        "publisher_claims",
        "local_observations",
        "documentation_claims",
    ],
)
def test_populated_nested_records_reject_private_fields(populated_contract, section):
    dossier = populated_contract["dossiers"][0]
    container = (
        dossier["chronology"]
        if section.endswith("claims") or section == "local_observations"
        else dossier
    )
    container[section][0]["private_note"] = "forbidden"
    with pytest.raises(ValidationError):
        validate_report(populated_contract)


@pytest.mark.parametrize(
    "section", ["statements", "fields", "source_check", "versions", "remediations", "exposure"]
)
def test_target_nested_records_are_closed(populated_contract, section):
    target = populated_contract["dossiers"][0]["comparison_targets"][0]
    if section in ("versions", "remediations", "exposure"):
        obj = target["statements"][0][section][0]
    elif section == "source_check":
        obj = target[section]
    else:
        obj = target[section][0]
    obj["private_note"] = "forbidden"
    with pytest.raises(ValidationError):
        validate_report(populated_contract)


def test_local_observations_require_offset_qualified_time(populated_contract):
    row = populated_contract["dossiers"][0]["chronology"]["local_observations"][0]
    row["value"] = "2026-10-27T00:00:00"
    with pytest.raises(ValidationError):
        validate_report(populated_contract)


@pytest.mark.parametrize(
    "precision,value",
    [
        ("date", "2024-07-08T00:00:00Z"),
        ("instant", "2024-07-08"),
        ("local_datetime", "2024-07-08T00:00:00Z"),
        ("unsupplied", "2024-07-08"),
    ],
)
def test_publisher_precision_cannot_mislabel_original_value(populated_contract, precision, value):
    claim = populated_contract["dossiers"][0]["chronology"]["publisher_claims"][0]
    claim.update(precision=precision, value=value)
    with pytest.raises(ValidationError):
        validate_report(populated_contract)


def test_unknown_target_field_cannot_become_a_value(populated_contract):
    field = populated_contract["dossiers"][0]["comparison_targets"][0]["fields"][0]
    field["value"] = "0"
    with pytest.raises(ValidationError):
        validate_report(populated_contract)


def test_registered_vendor_map_accepts_plugin_ids_and_rejects_arbitrary_nested_data(seed):
    report = research_dossiers(seed)
    report["vendors"]["synthetic_plugin-1"] = "Synthetic plugin"
    validate_report(report)
    report["vendors"]["synthetic_plugin-1"] = {"private_note": "forbidden"}
    with pytest.raises(ValidationError):
        validate_report(report)


def test_qualified_remediation_preserves_scoped_publisher_branch(populated_contract):
    remediation = populated_contract["dossiers"][0]["comparison_targets"][0]["statements"][0][
        "remediations"
    ][0]
    remediation["source_scope"] = "explicit_product_or_group"
    validate_report(populated_contract)
