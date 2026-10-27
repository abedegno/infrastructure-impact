"""Scope and public contracts for source-bound CVE research dossiers."""

import json
from contextlib import closing
from copy import deepcopy
from hashlib import sha256

import pytest
from jsonschema.exceptions import ValidationError

from infrastructure_impact.adapters.common import assessment, base
from infrastructure_impact.application.build_pilot import build_pilot
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
@pytest.mark.parametrize("collection", ["publisher_claims", "documentation_claims"])
def test_publisher_precision_cannot_mislabel_original_value(
    populated_contract, collection, precision, value
):
    claim = populated_contract["dossiers"][0]["chronology"][collection][0]
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


@pytest.mark.parametrize("collection", ["publisher_claims", "documentation_claims"])
@pytest.mark.parametrize(
    "precision,value",
    [
        ("date", "2024-07-08"),
        ("instant", "2024-07-08T00:00:00Z"),
        ("local_datetime", "2024-07-08T00:00:00"),
        ("unparsed", "Original publisher date label"),
        ("unsupplied", None),
    ],
)
def test_both_claim_collections_retain_original_precision(
    populated_contract, collection, precision, value
):
    claim = populated_contract["dossiers"][0]["chronology"][collection][0]
    claim.update(precision=precision, value=value)
    validate_report(populated_contract)


def _openssh(data):
    return research_dossiers(data)["dossiers"][0]


def test_cray_context_cannot_become_a_switching_target(seed):
    report = research_dossiers(seed)
    dossier = report["dossiers"][0]
    assert [t["vendor"] for t in dossier["comparison_targets"]] == ["arista", "aruba"]
    assert "hpe-cray-openssh-timing" in dossier["scope"]["case_ids"]
    assert [c["vendor"] for c in dossier["disclosure_context"]] == ["aruba", "hpe"]
    assert report["limits"]["inventory_verified"] is False


def test_exact_target_statement_and_source_identity_preserve_qualifications(seed):
    record = seed["records"][0]
    claim = record["assessments"][0]
    claim.update(product_id="original-branch-id", product_family="EOS", platforms=["Switch"])
    claim["remediations"] = [
        {
            "category": "vendor_fix",
            "details": "Conditional fix",
            "source_scope": "explicit_product_or_group",
        }
    ]
    branch = deepcopy(claim)
    branch.update(
        status="conflicting", scope="bulletin_shared", source_statuses=["fixed", "affected"]
    )
    record["assessments"].append(branch)
    dossier = _openssh(seed)
    target = dossier["comparison_targets"][0]
    assert [s["status"] for s in target["statements"]] == ["fixed", "conflicting"]
    first = target["statements"][0]
    assert first["product_id"] == "original-branch-id"
    assert first["exposure"][0]["details"].endswith("SSH management enabled.")
    assert first["remediations"][0]["source_scope"] == "explicit_product_or_group"
    identity = sha256(
        json.dumps(["arista", record["source_url"], "1" * 64], separators=(",", ":")).encode()
    ).hexdigest()
    assert first["source_id"] == identity
    source = next(s for s in dossier["sources"] if s["id"] == identity)
    assert source["observations"] == ["2026-10-27T00:00:00Z"]
    assert claim["evidence_locator"] in source["locators"]
    assert target["statements"][1]["scope"] == "bulletin_shared"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(vendor="hpe"),
        lambda r: r["assessments"][0].update(versions=[{"expression": "4.32.3F"}]),
        lambda r: r["assessments"][0].update(cve_id="CVE-2023-38545"),
        lambda r: r["assessments"][0].update(evidence_locator="Different locator"),
    ],
)
def test_exact_reference_rejects_other_vendor_build_cve_and_locator(seed, mutation):
    # The locator mutation changes the record after the reviewed pilot reference;
    # rebuilding all other inputs exercises the pilot's existing exact selector.
    pilot = deepcopy(seed["product_cohorts"]["build_pilot"])
    mutation(seed["records"][0])
    seed["product_cohorts"]["build_pilot"] = build_pilot(seed)
    if seed["records"][0]["assessments"][0]["evidence_locator"] == "Different locator":
        seed["product_cohorts"]["build_pilot"] = pilot
    row = _openssh(seed)["comparison_targets"][0]
    assert row["statements"] == []
    assert row["fields"][0]["state"] == "unknown"


def test_missing_source_preserves_target_as_unknown(seed):
    seed["records"] = []
    seed["product_cohorts"]["build_pilot"] = build_pilot(seed)
    row = _openssh(seed)["comparison_targets"][0]
    assert row["statements"] == []
    assert any(f["state"] == "unknown" for f in row["fields"])
    assert _openssh(seed)["evidence_gaps"]


def test_stale_source_hash_cannot_supply_target_evidence(seed):
    seed["records"][0]["sha256"] = "a" * 64
    row = _openssh(seed)["comparison_targets"][0]
    assert row["statements"] == []
    assert row["fields"][0]["value"] is None


def _timeline_event(record, **changes):
    return dict(
        event_id="revision-9-CVE-2024-6387",
        revision_id=9,
        evidence_id=9,
        vendor=record["vendor"],
        cve_id="CVE-2024-6387",
        observed_at="2026-10-26T12:30:00+01:00",
        kind="parser_reinterpretation",
        source_url=record["source_url"],
        source_sha256="a" * 64,
        publisher_published_at="2024-07-08",
        **changes,
    )


def test_date_claim_is_not_capture_or_first_disclosure(seed):
    seed["timeline"].update(
        history_truncated=True, events_truncated=True, events=[_timeline_event(seed["records"][0])]
    )
    dossier = _openssh(seed)
    assert any(
        c["field"] == "published_at" and c["value"] == "2024-07-08" and c["precision"] == "date"
        for c in dossier["chronology"]["publisher_claims"]
    )
    observations = dossier["chronology"]["local_observations"]
    assert any(
        o["value"] == "2026-10-27T00:00:00Z" and o["kind"] == "source_capture" for o in observations
    )
    historical = next(o for o in observations if o["kind"] == "parser_reinterpretation")
    assert historical["value"] == "2026-10-26T12:30:00+01:00"
    assert historical["history_truncated"] is historical["events_truncated"] is True
    source = next(s for s in dossier["sources"] if s["id"] == historical["source_id"])
    assert source["source_sha256"] == "a" * 64
    assert source["source_sha256"] != seed["records"][0]["sha256"]


@pytest.mark.parametrize(
    "value,precision",
    [
        ("2024-07-08", "date"),
        ("2024-07-08T09:15:00Z", "instant"),
        ("2024-07-08T09:15:00", "local_datetime"),
        ("Publisher's original date label", "unparsed"),
        (None, "unsupplied"),
    ],
)
def test_derived_publisher_date_precision_preserves_original(seed, value, precision):
    seed["records"][0]["published_at"] = value
    dossier = _openssh(seed)
    sid = dossier["comparison_targets"][0]["statements"][0]["source_id"]
    row = next(
        c
        for c in dossier["chronology"]["publisher_claims"]
        if c["source_id"] == sid and c["field"] == "published_at"
    )
    assert (row["value"], row["precision"]) == (value, precision)


def test_timeline_excludes_wrong_vendor_cve_and_unbound_sources(seed):
    good = _timeline_event(seed["records"][0])
    seed["timeline"]["events"] = [
        good,
        {**good, "vendor": "hpe"},
        {**good, "cve_id": "CVE-2023-38545"},
        {**good, "source_url": "https://www.arista.com/unbound"},
    ]
    observations = _openssh(seed)["chronology"]["local_observations"]
    assert sum(o["kind"] == "parser_reinterpretation" for o in observations) == 1


def _curl_context(seed):
    case = next(
        c for c in seed["casefiles"]["cases"] if c["id"] == "fortiproxy-curl-documented-fix"
    )
    url = case["advisory_urls"][1]
    case["earlier_dated_vendor_documents"] = [
        dict(
            source_url=url,
            source_sha256="b" * 64,
            publisher_published_at="2023-10-11",
            date_basis="publisher_calendar_claim_timezone_unspecified",
            cve_ids=["CVE-2023-38545"],
            product_labels=["FortiProxy"],
            interpretation="Earlier advisory counter-evidence; availability remains unverified.",
        )
    ]
    case["publisher_document_histories"] = [
        dict(
            vendor="fortinet",
            source_url=case["release_source_leads"][0],
            source_sha256="c" * 64,
            observed_at="2026-10-27T00:00:00Z",
            events=[
                dict(
                    publisher_date="2023-12-01",
                    kind="initial_document_release",
                    cve_ids=[],
                    source_locator="Initial history row",
                ),
                dict(
                    publisher_date="2023-12-05",
                    kind="cve_references_added",
                    cve_ids=["CVE-2023-38545"],
                    source_locator="Selected CVE row",
                ),
                dict(
                    publisher_date="2023-12-06",
                    kind="cve_references_added",
                    cve_ids=["CVE-2023-38546"],
                    source_locator="Other CVE detail",
                ),
            ],
        )
    ]
    return case


def test_curl_counter_evidence_and_documentation_stay_cve_scoped(seed):
    _curl_context(seed)
    report = research_dossiers(seed)
    curl, other = report["dossiers"][1:]
    context = curl["disclosure_context"][0]
    assert context["earlier_documents"][0]["product_labels"] == ["FortiProxy"]
    assert context["earlier_documents"][0]["publisher_published_at"] == "2023-10-11"
    claims = curl["chronology"]["documentation_claims"]
    assert [c["kind"] for c in claims] == ["initial_document_release", "cve_references_added"]
    assert "Other CVE detail" not in json.dumps(curl)
    assert other["disclosure_context"][0]["earlier_documents"] == []
    assert "Selected CVE row" not in json.dumps(other)
    assert report["limits"]["independent_release_availability_verified"] is False
    assert report["limits"]["concealment_established"] is False


def test_changed_source_set_recomputes_disposition_and_rejects_unrelated_reviews(seed):
    case = next(c for c in seed["casefiles"]["cases"] if c["vendor"] == "hpe")
    url = case["advisory_urls"][0]
    ref = dict(source_url=url, source_sha256="d" * 64, observed_at="2026-10-27T00:00:00Z")
    case["evidence"] = [ref]
    review = dict(
        vendor="hpe",
        cve_ids=["CVE-2024-6387"],
        related_case_ids=[case["id"]],
        kind="publisher_reported_chronology",
        details="Synthetic chronology",
        evidence=[ref],
        alternative_explanations=[],
        investigation={"disposition": "release_availability_unresolved"},
    )
    seed["disclosure_review"]["cases"] = [review]
    context = _openssh(seed)["disclosure_context"][1]
    assert context["investigation"]["source_state"] == "source_changed_review_required"
    assert context["investigation"]["disposition"] == "source_changed_review_required"
    assert context["investigation"]["source_ids"] == context["source_ids"]
    for key, value in [
        ("vendor", "aruba"),
        ("related_case_ids", ["unrelated"]),
        ("cve_ids", ["CVE-2023-38546"]),
    ]:
        bad = deepcopy(review)
        bad[key] = value
        seed["disclosure_review"]["cases"] = [bad]
        assert _openssh(seed)["disclosure_context"][1]["investigation"] is None


def test_uncollected_leads_and_http_failures_are_gaps_not_sources(seed):
    case = seed["casefiles"]["cases"][0]
    url = case["release_source_leads"][0]
    case["source_checks"] = [
        dict(
            source_url=url,
            outcome="http_error",
            error_code="HTTP_403",
            checked_at="2026-10-27T00:00:00Z",
        )
    ]
    dossier = _openssh(seed)
    assert url not in {s["source_url"] for s in dossier["sources"]}
    assert any(
        g["evidence_sought"] == url and g["access_state"] == "http_error"
        for g in dossier["evidence_gaps"]
    )
    assert any(g["access_state"] == "uncollected_lead" for g in dossier["evidence_gaps"])
    assert (
        next(c for c in dossier["disclosure_context"] if c["case_id"] == case["id"])[
            "source_checks"
        ][0]["error_code"]
        == "HTTP_403"
    )


def test_projection_allowlists_every_nested_input_and_is_pure(seed):
    _curl_context(seed)
    seed["records"][0]["PRIVATE_SENTINEL"] = "PRIVATE_SENTINEL"
    seed["records"][0]["assessments"][0]["PRIVATE_SENTINEL"] = "PRIVATE_SENTINEL"
    seed["records"][0]["assessments"][0]["exposure"][0]["private"] = "PRIVATE_SENTINEL"
    target = seed["product_cohorts"]["build_pilot"]["targets"][0]
    target["private"] = "PRIVATE_SENTINEL"
    target["fields"][0]["evidence"][0]["private"] = "PRIVATE_SENTINEL"
    for case in seed["casefiles"]["cases"]:
        case["private"] = "PRIVATE_SENTINEL"
        for doc in case.get("earlier_dated_vendor_documents", []):
            doc["private"] = "PRIVATE_SENTINEL"
    original = deepcopy(seed)
    report = research_dossiers(seed)
    assert seed == original
    assert "PRIVATE_SENTINEL" not in json.dumps(report)
    assert report == research_dossiers(seed)
    report["dossiers"][0]["comparison_targets"][0]["statements"][0]["exposure"].clear()
    assert seed == original


def test_definition_entry_and_target_order_are_preserved(seed):
    spec = definition()
    spec["entries"].reverse()
    spec["entries"][-1]["build_target_ids"].reverse()
    report = research_dossiers(seed, spec)
    assert [d["cve_id"] for d in report["dossiers"]] == [
        "CVE-2023-38546",
        "CVE-2023-38545",
        "CVE-2024-6387",
    ]
    assert [t["vendor"] for t in report["dossiers"][-1]["comparison_targets"]] == [
        "aruba",
        "arista",
    ]


def test_source_unions_exact_observations_and_sorted_locators(seed):
    seed["records"][0]["assessments"][0]["exposure"].extend(
        [
            dict(
                category="publisher_platform_scope", details="Z scope", source_locator="Z locator"
            ),
            dict(
                category="publisher_platform_scope", details="A scope", source_locator="A locator"
            ),
        ]
    )
    seed["product_cohorts"]["build_pilot"] = build_pilot(seed)
    ref = seed["product_cohorts"]["build_pilot"]["targets"][0]["fields"][0]["evidence"][0]
    ref["observed_at"] = "2026-10-26T23:00:00+00:00"
    dossier = _openssh(seed)
    sid = dossier["comparison_targets"][0]["statements"][0]["source_id"]
    source = next(s for s in dossier["sources"] if s["id"] == sid)
    assert source["observations"] == ["2026-10-26T23:00:00+00:00", "2026-10-27T00:00:00Z"]
    assert [s["id"] for s in dossier["sources"]] == sorted(s["id"] for s in dossier["sources"])
    assert source["locators"] == ["A locator", "Synthetic exact target row 1", "Z locator"]


def test_rejected_firmware_reference_cannot_leave_known_context_fields(seed):
    claim = seed["records"][0]["assessments"][0]
    claim["exposure"].append(
        dict(
            category="publisher_platform_scope",
            details="Synthetic switch",
            source_locator="Exact platform row",
        )
    )
    seed["product_cohorts"]["build_pilot"] = build_pilot(seed)
    claim["evidence_locator"] = "Changed normalization locator"
    target = _openssh(seed)["comparison_targets"][0]
    assert target["statements"] == []
    assert all(f["state"] == "unknown" for f in target["fields"])


def test_disposition_checks_current_retained_bytes_instead_of_stale_review(seed):
    item = next(
        i
        for i in json.loads((PACKAGE / "resources/disclosure-investigations.json").read_text())[
            "investigations"
        ]
        if i["id"] == "hpe-cray-openssh-timing"
    )
    case = next(c for c in seed["casefiles"]["cases"] if c["vendor"] == "hpe")
    case["evidence"] = deepcopy(item["source_bindings"])
    review = dict(
        vendor="hpe",
        cve_ids=["CVE-2024-6387"],
        related_case_ids=[case["id"]],
        kind="publisher_reported_chronology",
        details="Synthetic chronology",
        evidence=deepcopy(item["source_bindings"]),
        alternative_explanations=[],
    )
    seed["disclosure_review"]["cases"] = [review]
    assert _openssh(seed)["disclosure_context"][1]["investigation"]["disposition"] == (
        "release_availability_unresolved"
    )
    case["evidence"][0]["source_sha256"] = "e" * 64
    current = _openssh(seed)["disclosure_context"][1]["investigation"]
    assert current is not None
    assert current["disposition"] == "source_changed_review_required"
    assert current["source_state"] == "source_changed_review_required"


def test_unqualified_capture_is_rejected_without_inventing_timezone(seed):
    seed["records"][0]["source_observed_at"] = "2026-10-27T00:00:00"
    with pytest.raises(ValidationError):
        research_dossiers(seed)


@pytest.mark.parametrize("record_index", [0, 1], ids=["version-expression", "product-context"])
def test_same_locator_cannot_transfer_another_build_branch(seed, record_index):
    record = seed["records"][record_index]
    exact = record["assessments"][0]
    other = deepcopy(exact)
    other["product_id"] = "unrelated-build-branch"
    if record_index == 0:
        other["versions"] = [{"expression": "4.32.3F"}]
    else:
        other["product_context"] = [["product_version", "10.13.1040"]]
    record["assessments"].append(other)
    seed["product_cohorts"]["build_pilot"] = build_pilot(seed)
    firmware = seed["product_cohorts"]["build_pilot"]["targets"][record_index]["fields"][0]
    assert len(firmware["evidence"]) == 1
    statements = _openssh(seed)["comparison_targets"][record_index]["statements"]
    assert [claim["product_id"] for claim in statements] == [exact["product_id"]]
    assert statements[0]["versions"] == exact["versions"]
    assert statements[0]["product_context"] == exact["product_context"]


def test_partially_missing_aggregate_provenance_cannot_retain_unsupported_text(seed):
    retained = seed["records"][0]
    retained["assessments"][0]["exposure"].append(
        dict(
            category="publisher_platform_scope",
            details="Retained platform A",
            source_locator="Platform section",
        )
    )
    missing = deepcopy(retained)
    missing["sha256"] = "f" * 64
    missing["assessments"][0]["exposure"][-1]["details"] = "Missing source platform B"
    seed["records"].append(missing)
    seed["product_cohorts"]["build_pilot"] = build_pilot(seed)
    pilot_fields = seed["product_cohorts"]["build_pilot"]["targets"][0]["fields"]
    aggregate = next(f for f in pilot_fields if f["field"] == "platform_applicability_context")
    assert aggregate["value"] == "Retained platform A Missing source platform B"
    assert len(aggregate["evidence"]) == 2
    seed["records"].remove(missing)
    dossier = _openssh(seed)
    target = dossier["comparison_targets"][0]
    field = next(f for f in target["fields"] if f["field"] == "platform_applicability_context")
    assert field == dict(
        field="platform_applicability_context", state="unknown", value=None, evidence=[]
    )
    assert "Missing source platform B" not in json.dumps(dossier)
    assert len(target["statements"]) == 1
    assert any(
        g["owner_id"] == target["target_id"]
        and g["field_or_question"] == "platform_applicability_context"
        for g in dossier["evidence_gaps"]
    )


def test_projection_ignores_injected_dossier(writer_seed):
    writer_seed["research_dossiers"] = {"PRIVATE_SENTINEL": "private review"}
    projected = public_projection(writer_seed)
    assert "PRIVATE_SENTINEL" not in json.dumps(projected["research_dossiers"])
    assert len(projected["research_dossiers"]["dossiers"]) == 3
    assert projected["research_dossiers"] == research_dossiers(projected)


def test_empty_selection_does_not_become_default_cohort(seed):
    report = research_dossiers(seed)
    assert select_research_dossiers(report, [])["dossiers"] == []
    assert select_research_dossiers(None, []) is None
    assert select_research_dossiers(report, ["CVE-1999-999999"])["dossiers"] == []


def test_vendor_selection_preserves_declared_scope_and_prunes_nested_evidence(seed):
    report = research_dossiers(seed)
    before = deepcopy(report)
    selected = select_research_dossiers(report, ["CVE-2024-6387"], "hpe")
    validate_report(selected)
    dossier = selected["dossiers"][0]
    assert dossier["comparison_targets"] == []
    assert [c["vendor"] for c in dossier["disclosure_context"]] == ["hpe"]
    assert dossier["scope"]["build_target_ids"] == ["arista-eos-4-32-2f", "aruba-aoscx-10-13-1031"]
    assert dossier["scope"]["case_ids"] == ["aruba-cx-release-date-gap", "hpe-cray-openssh-timing"]
    assert dossier["scope"]["selected_vendor"] == "hpe"
    assert selected["vendors"] == {"hpe": report["vendors"]["hpe"]}
    assert dossier["sources"] == []
    assert all(not rows for rows in dossier["chronology"].values())
    assert {g["owner_id"] for g in dossier["evidence_gaps"]} == {"hpe-cray-openssh-timing"}
    assert "Synthetic exact target row" not in json.dumps(dossier)
    assert selected["definition_sha256"] == report["definition_sha256"]
    assert selected["limits"] == report["limits"]
    dossier["disclosure_context"][0]["missing_evidence"].clear()
    assert report == before


def test_selection_retains_shared_literal_urls_and_only_referenced_sources(seed):
    _curl_context(seed)
    report = research_dossiers(seed)
    # A retained-looking row without any projected reference must not survive selection.
    report["dossiers"][1]["sources"].append(
        dict(
            id="f" * 64,
            vendor="fortinet",
            source_url="https://www.fortiguard.com/orphan",
            source_sha256="f" * 64,
            locators=[],
            observations=[],
        )
    )
    selected = select_research_dossiers(report, ["CVE-2023-38545"], "fortinet")
    validate_report(selected)
    assert [d["cve_id"] for d in selected["dossiers"]] == ["CVE-2023-38545"]
    dossier = selected["dossiers"][0]
    assert len(dossier["sources"]) == 2
    assert "Other CVE detail" not in json.dumps(dossier)
    assert "Selected CVE row" in json.dumps(dossier)
    assert any("cve-2023-38545-and-cve-2023-38546" in s["source_url"] for s in dossier["sources"])
    assert "https://www.fortiguard.com/orphan" not in json.dumps(dossier)
    references = {c["source_id"] for rows in dossier["chronology"].values() for c in rows}
    assert {s["id"] for s in dossier["sources"]} == references
    assert selected["vendors"] == {"fortinet": report["vendors"]["fortinet"]}


def _request(app, path, query=""):
    replies = []
    body = b"".join(
        app(
            dict(REQUEST_METHOD="GET", PATH_INFO=path, QUERY_STRING=query),
            lambda status, headers: replies.append(status),
        )
    )
    return replies[0], json.loads(body)


def test_publication_exports_generation_bound_dossiers_schemas_and_openapi(writer_seed, tmp_path):
    from infrastructure_impact.application.publication import publish
    from infrastructure_impact.http import Application

    generation = publish(writer_seed, tmp_path / "publications")
    app = Application(tmp_path / "publications")
    status, report = _request(app, "/api/v1/research-dossiers")
    assert status == "200 OK"
    assert report == json.loads((generation / "research-dossiers.json").read_text())
    validate_report(report)
    snapshot = json.loads((generation / "snapshot.json").read_text())
    assert report["publication"] == snapshot["publication"]
    assert report["generated_at"] == snapshot["generated_at"]
    manifest = json.loads((generation / "manifest.json").read_text())
    for path in [
        "research-dossiers.json",
        "schemas/research-dossiers-v1.json",
        "schemas/research-dossier-definition-v1.json",
    ]:
        assert manifest["sha256"][path] == sha256((generation / path).read_bytes()).hexdigest()
        code, _, body = app.route(dict(REQUEST_METHOD="GET", PATH_INFO="/" + path))
        assert code == 200
        assert body == (generation / path).read_bytes()
    api = json.loads((generation / "openapi.json").read_text())["paths"]
    route = api["/api/v1/research-dossiers"]["get"]
    assert {p["name"] for p in route["parameters"]} >= {"cves", "vendor"}
    assert {"200", "400", "404", "503"} <= route["responses"].keys()
    assert "/research-dossiers.json" in api
    assert "/schemas/research-dossiers-v1.json" in api
    assert "/schemas/research-dossier-definition-v1.json" in api


def test_api_filters_cves_and_vendor_with_original_vendor_catalogue(writer_seed, tmp_path):
    from infrastructure_impact.application.publication import publish
    from infrastructure_impact.http import Application

    publish(writer_seed, tmp_path)
    app = Application(tmp_path)
    status, report = _request(
        app, "/api/v1/research-dossiers", "cves=CVE-2023-38545&vendor=fortinet"
    )
    assert status == "200 OK"
    assert [d["cve_id"] for d in report["dossiers"]] == ["CVE-2023-38545"]
    assert [c["vendor"] for c in report["dossiers"][0]["disclosure_context"]] == ["fortinet"]
    assert report["vendors"] == {"fortinet": writer_seed["vendors"]["fortinet"]}
    _, hpe = _request(app, "/api/v1/research-dossiers", "cves=CVE-2024-6387&vendor=hpe")
    assert hpe["dossiers"][0]["comparison_targets"] == []
    assert [c["vendor"] for c in hpe["dossiers"][0]["disclosure_context"]] == ["hpe"]
    _, empty = _request(app, "/api/v1/research-dossiers", "cves=CVE-1999-999999&vendor=hpe")
    assert empty["dossiers"] == []


@pytest.mark.parametrize(
    "query",
    [
        "vendor=unknown",
        "vendor=hpe&vendor=hpe",
        "vendor=hpe&vendor=aruba",
        "vendor=",
        "cves=not-a-cve",
        "cves=",
    ],
)
def test_api_rejects_invalid_dossier_controls(writer_seed, tmp_path, query):
    from infrastructure_impact.application.publication import publish
    from infrastructure_impact.http import Application

    publish(writer_seed, tmp_path)
    status, body = _request(Application(tmp_path), "/api/v1/research-dossiers", query)
    assert status == "400 Bad Request"
    assert body == {"error": "Invalid request"}


def test_exports_select_dossiers_without_fabricating_old_generation_reports(seed):
    from infrastructure_impact.exports import select

    seed["research_dossiers"] = research_dossiers(seed)
    selected = select(seed, ["CVE-2023-38546"], vendor="fortinet")
    assert [d["cve_id"] for d in selected["research_dossiers"]["dossiers"]] == ["CVE-2023-38546"]
    assert selected["research_dossiers"]["vendors"] == {"fortinet": seed["vendors"]["fortinet"]}
    seed.pop("research_dossiers")
    assert "research_dossiers" not in select(seed, ["CVE-2024-6387"])


def test_old_snapshot_keeps_existing_routes_and_dossier_is_unavailable(seed, tmp_path):
    from infrastructure_impact.http import Application

    # Build a standalone old-format fixture, never edit an immutable generation.
    seed.pop("research_dossiers", None)
    seed["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    generation = tmp_path / "generations" / ("a" * 32)
    generation.mkdir(parents=True)
    (generation / "snapshot.json").write_text(json.dumps(seed))
    (tmp_path / "current").symlink_to(generation, target_is_directory=True)
    app = Application(tmp_path)
    assert _request(app, "/api/state")[0] == "200 OK"
    assert "research_dossiers" not in _request(app, "/api/state")[1]
    assert _request(app, "/api/v1/product-cohorts")[0] == "200 OK"
    assert _request(app, "/api/v1/research-dossiers") == (
        "404 Not Found",
        {"error": "Report unavailable for this generation"},
    )


def test_invalid_derived_dossier_cannot_replace_current_generation(
    writer_seed, tmp_path, monkeypatch
):
    import infrastructure_impact.application.research_dossiers as dossiers_module
    from infrastructure_impact.application.publication import publish

    previous = publish(writer_seed, tmp_path)
    invalid = research_dossiers(public_projection(writer_seed))
    invalid["limits"]["inventory_verified"] = True
    monkeypatch.setattr(dossiers_module, "research_dossiers", lambda data: invalid)
    with pytest.raises(ValidationError):
        publish(writer_seed, tmp_path)
    assert (tmp_path / "current").resolve() == previous
    assert not list((tmp_path / "generations").glob(".staging-*"))


def test_publication_retains_evidence_after_latest_source_check_failure(writer_seed, tmp_path):
    from infrastructure_impact.application.publication import publish

    record = writer_seed["records"][0]
    writer_seed["health"].append(
        dict(
            vendor=record["vendor"],
            source_url=record["source_url"],
            outcome="error",
            error_code="HTTP_503",
            checked_at="2026-10-27T01:00:00Z",
        )
    )
    generation = publish(writer_seed, tmp_path)
    report = json.loads((generation / "research-dossiers.json").read_text())
    target = report["dossiers"][0]["comparison_targets"][0]
    assert target["source_check"]["outcome"] == "error"
    assert target["statements"][0]["status"] == "fixed"
    assert any(s["source_sha256"] == record["sha256"] for s in report["dossiers"][0]["sources"])


def test_vendor_outside_declared_dossier_members_has_no_dossier(seed):
    report = research_dossiers(seed)
    assert select_research_dossiers(report, ["CVE-2024-6387"], "fortinet")["dossiers"] == []
    assert select_research_dossiers(report, ["CVE-2023-38545"], "hpe")["dossiers"] == []


@pytest.mark.parametrize("path", ["/api/state", "/api/export.json"])
def test_selected_state_and_download_apply_dossier_vendor_control(writer_seed, tmp_path, path):
    from infrastructure_impact.application.publication import publish
    from infrastructure_impact.http import Application

    publish(writer_seed, tmp_path)
    app = Application(tmp_path)
    status, data = _request(app, path, "cves=CVE-2024-6387&vendor=hpe")
    assert status == "200 OK"
    report = data["research_dossiers"]
    assert report["vendors"] == {"hpe": writer_seed["vendors"]["hpe"]}
    assert report["dossiers"][0]["comparison_targets"] == []
    assert [c["vendor"] for c in report["dossiers"][0]["disclosure_context"]] == ["hpe"]
    # The previous selection must not replace the original cached vendor catalogue.
    status, data = _request(app, path, "cves=CVE-2023-38545&vendor=fortinet")
    assert status == "200 OK"
    assert data["research_dossiers"]["vendors"] == {"fortinet": writer_seed["vendors"]["fortinet"]}
    assert _request(app, path, "vendor=hpe&vendor=hpe")[0] == "400 Bad Request"
    assert _request(app, path, "vendor=unknown")[0] == "400 Bad Request"


def test_registered_dossier_validator_enforces_local_datetime_format(seed):
    from infrastructure_impact.application.research_reports import validator

    report = research_dossiers(seed)
    claim = report["dossiers"][0]["chronology"]["publisher_claims"][0]
    claim.update(precision="local_datetime", value="not-a-date")
    with pytest.raises(ValidationError):
        validator("research_dossiers").validate(report)
