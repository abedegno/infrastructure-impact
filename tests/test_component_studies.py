"""A frozen study must preserve exclusions, unknowns and evidence boundaries."""

import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from infrastructure_impact.application.component_studies import (
    cell,
    component_studies,
    definitions,
    public_inputs,
    reference_status,
)
from infrastructure_impact.application.families import definition as families
from infrastructure_impact.application.publication import public_projection, publish
from infrastructure_impact.application.query import state
from infrastructure_impact.application.research_reports import validator
from infrastructure_impact.http import Application
from infrastructure_impact.references.registry import NVD_OPENSSH_URL
from infrastructure_impact.storage.repository import connect


def minimal():
    return {"vendors": {f["vendor"]: f["vendor"] for f in families()["families"]}, "records": []}


def record(family, cid, status="affected", scope="cve_specific"):
    return {
        "vendor": family["vendor"],
        "advisory_id": "synthetic-study-1",
        "source_url": "https://security.example/advisory",
        "sha256": "a" * 64,
        "published_at": "2020-01-01",
        "observed_at": "2026-10-26T00:00:00Z",
        "cves": [cid],
        "document_status": "final",
        "assessments": [
            {
                "cve_id": cid,
                "product": family["prefixes"][0],
                "platforms": family["platform_prefixes"],
                "status": status,
                "scope": scope,
                "evidence_locator": "Synthetic product row",
                "product_context": [],
                "versions": [
                    {"version": "1.2", "status": status, "private_field": "PRIVATE_SENTINEL"}
                ],
                "exposure": [{"details": "Conditional synthetic prerequisite"}],
                "extensions": {"private": "PRIVATE_SENTINEL"},
            }
        ],
    }


def test_frozen_enrollment_does_not_follow_vendor_outcomes_and_exclusion_is_not_unaffectedness():
    data = minimal()
    report = component_studies(data)
    validator("component_studies").validate(report)
    study = report["studies"][0]
    assert len(study["candidate_reviews"]) == 40 and len(study["included_cves"]) == 21
    assert len(study["cells"]) == 126
    assert all(c["state"] == "unknown_no_retained_family_assessment" for c in study["cells"])
    assert study["rate_comparison"] is None and study["ranking_supported"] is False
    assert study["independent_human_review_completed"] is False
    excluded = next(c for c in study["candidate_reviews"] if c["cve_id"] == "CVE-2023-38408")
    assert excluded["role"] == "agent" and excluded["enrollment"] == "excluded"
    assert excluded["cve_id"] not in {c["cve_id"] for c in study["cells"]}
    downstream = next(c for c in study["candidate_reviews"] if c["cve_id"] == "CVE-2026-3497")
    assert downstream["variant_scope"] == "downstream_gssapi_patch_only"
    family = next(f for f in families()["families"] if f["id"] == study["families"][0])
    data["records"] = [record(family, cid) for cid in study["included_cves"]]
    later = component_studies(data)["studies"][0]
    assert later["candidate_reviews"] == study["candidate_reviews"]
    assert later["cohort_sha256"] == study["cohort_sha256"]


def test_cells_keep_shared_fixed_and_mixed_scope_separate_with_private_fields_removed():
    family = next(f for f in families()["families"] if f["id"] == "cisco-asa-ftd")
    cid = "CVE-2024-6387"
    data = minimal()
    data["records"] = [record(family, cid, "fixed")]
    fixed = cell(data, family, cid)
    assert fixed["state"] == "fixed_statement_without_prior_exposure_inference"
    assert fixed["evidence"][0]["exposure_context_present"]
    assert fixed["evidence"][0]["evidence_locator"] == "Synthetic product row"
    assert fixed["evidence"][0]["publisher_published_at"] == "2020-01-01"
    assert "PRIVATE_SENTINEL" not in json.dumps(fixed)
    data["records"] = [record(family, cid, scope="bulletin_shared")]
    assert cell(data, family, cid)["state"] == "shared_bulletin_only"
    data["records"] = [record(family, cid), record(family, cid, "unaffected")]
    assert cell(data, family, cid)["state"] == "scope_requires_review"
    data["records"][1]["document_status"] = "draft"
    assert cell(data, family, cid)["state"] == "explicit_affected_statement"
    data["records"] *= 20
    bounded = cell(data, family, cid)
    assert bounded["evidence_truncated"] and len(bounded["evidence"]) == 12


def test_frozen_resource_tampering_is_detected():
    real_read = Path.read_text

    def altered(path, *args, **kwargs):
        text = real_read(path, *args, **kwargs)
        if path.name == "openssh-service-2023-2026.json":
            return text.replace('"enrollment": "included"', '"enrollment": "excluded"', 1)
        return text

    import pytest

    with patch.object(Path, "read_text", altered), pytest.raises(ValueError, match="fingerprint"):
        definitions()


def test_current_source_changes_trigger_review_without_silently_reenrolling():
    study = definitions()[0]
    assert reference_status(study, [])["state"] == "not_collected"
    ref = {
        "source_id": study["source_id"],
        "source_url": NVD_OPENSSH_URL,
        "source_sha256": "b" * 64,
        "source_observed_at": "2026-10-26T00:00:00Z",
        "parsed_at": "2026-10-26T00:00:00Z",
        "parser_version": "test/1",
        "private": "PRIVATE_SENTINEL",
        "collection": {
            "outcome": "error",
            "checked_at": "2026-10-27T00:00:00Z",
            "error_code": "network_error",
            "details": "PRIVATE_SENTINEL",
        },
        "records": [
            {
                **r,
                "rejected": False,
                "has_positive_product_mapping": True,
                "descriptions": "PRIVATE_SENTINEL",
            }
            for r in study["candidate_reviews"]
        ],
    }
    clean = public_inputs([ref])
    assert "PRIVATE_SENTINEL" not in json.dumps(clean)
    assert reference_status(study, clean)["state"] == "matches_frozen_candidate_semantics"
    assert reference_status(study, clean)["source"]["collection"]["outcome"] == "error"
    changed = deepcopy(clean)
    removed = changed[0]["records"].pop()["cve_id"]
    changed[0]["records"][0]["record_semantic_sha256"] = "c" * 64
    changed[0]["records"].append({**changed[0]["records"][0], "cve_id": "CVE-2026-9999999"})
    result = reference_status(study, changed)
    assert result["state"] == "review_required"
    assert result["removed_candidates"] == [removed]
    assert result["changed_candidates"] == [changed[0]["records"][0]["cve_id"]]
    assert result["added_candidates"] == ["CVE-2026-9999999"]
    assert not public_inputs([{**ref, "source_url": "https://private.example"}])


def test_report_is_recomputed_at_public_boundary_and_generation_bound_on_api(tmp_path):
    with connect(":memory:") as db:
        data = state(db)
    data["component_studies"] = {"private": "PRIVATE_SENTINEL"}
    data["research"]["study_inputs"] = [{"source_id": "unreviewed", "private": "PRIVATE_SENTINEL"}]
    public = public_projection(data)
    assert "study_inputs" not in public["research"]
    assert "PRIVATE_SENTINEL" not in json.dumps(public)
    root = tmp_path / "publications"
    publish(data, root=root)
    response = []
    body = b"".join(
        Application(root)(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/component-studies", "QUERY_STRING": ""},
            lambda status, headers: response.append(status),
        )
    )
    assert response == ["200 OK"]
    report = json.loads(body)
    validator("component_studies").validate(report)
    saved = json.loads((root / "current/component-studies.json").read_text())
    assert saved == report and report["publication"]["id"]
