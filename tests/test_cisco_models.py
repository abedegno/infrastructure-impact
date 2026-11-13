"""Exact publisher model ownership; numbers and chassis families are not aliases."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from infrastructure_impact.adapters.switching import extract

FIXTURE = Path(__file__).parent / "fixtures/cisco-model-notes.json"


def run(data, url="https://example.test/cisco.json"):
    return extract(json.dumps(data).encode(), url, "cisco", {"advisory_id": "TEST"})["claims"]


def structural(name, relationship=False):
    tree = {
        "branches": [
            {
                "category": "product_family",
                "name": "Cisco IOS XE Software",
                "branches": [
                    {
                        "category": "product_name",
                        "name": name,
                        "product": {"product_id": "p", "name": name},
                    }
                ],
            }
        ]
    }
    if relationship:
        tree = {
            "full_product_names": [
                {"product_id": "os", "name": "Cisco IOS XE Software"},
                {"product_id": "hw", "name": name},
            ],
            "relationships": [
                {
                    "category": "installed_on",
                    "product_reference": "os",
                    "relates_to_product_reference": "hw",
                    "full_product_name": {"product_id": "p", "name": "OS on switch"},
                }
            ],
        }
    return {
        "document": {"tracking": {"id": "TEST"}},
        "product_tree": tree,
        "vulnerabilities": [{"cve": "CVE-2026-12345", "product_status": {"known_affected": ["p"]}}],
    }


@pytest.mark.parametrize("relationship", [False, True])
def test_exact_series_structural_model_and_relationship(relationship):
    c = run(structural("Cisco Catalyst 9300 Series Switches", relationship))[0]
    assert sorted({b["model"] for b in c["platform_bindings"]}) == ["9300"]
    assert c["scope_level"] == "model_qualified"


@pytest.mark.parametrize(
    "name",
    [
        "Firepower 9300",
        "Cisco Catalyst 9500X Series Switches",
        "Cisco Catalyst 9400 Series Switches",
        "Cisco Catalyst 9600 Series Switches",
        "Catalyst 9800 Embedded Wireless Controllers for Catalyst 9300, 9400, and 9500 Series Switches",
    ],
)
def test_structural_near_names_do_not_become_target_models(name):
    assert run(structural(name))[0]["platform_bindings"] == []


def test_reviewed_positive_notes_keep_conditions_status_and_versions():
    from infrastructure_impact.adapters.cisco_models import note_bindings

    cases = json.loads(FIXTURE.read_text())
    for case in cases:
        original = copy.deepcopy(case)
        result = note_bindings(
            case["data"],
            case["source_url"],
            case["source_sha256"],
            case["cve_id"],
            "affected",
            "cisco-iosxe",
            "Cisco IOS XE Software",
        )
        assert sorted(b["model"] for b in result["bindings"]) == case["expected_models"]
        assert result["conditions"] == [case["data"]["document"]["notes"][1]["text"]]
        assert all(
            b["source"]["source_locator"] == "/document/notes/1/text" for b in result["bindings"]
        )
        assert case == original
        for status in ["fixed", "unaffected", "recommended", "conflicting"]:
            assert not note_bindings(
                case["data"],
                case["source_url"],
                case["source_sha256"],
                case["cve_id"],
                status,
                "cisco-iosxe",
                "Cisco IOS XE Software",
            )["bindings"]
        bad = copy.deepcopy(case["data"])
        bad["document"]["notes"][1]["text"] += " Additional unknown qualification."
        assert not note_bindings(
            bad,
            case["source_url"],
            case["source_sha256"],
            case["cve_id"],
            "affected",
            "cisco-iosxe",
            "Cisco IOS XE Software",
        )["bindings"]
        assert not note_bindings(
            case["data"],
            case["source_url"],
            case["source_sha256"],
            "CVE-2026-99999",
            "affected",
            "cisco-iosxe",
            "Cisco IOS XE Software",
        )["bindings"]


def test_cached_public_source_binds_version_descendants_without_changing_os_facts():
    from infrastructure_impact.adapters import switching

    case = next(c for c in json.loads(FIXTURE.read_text()) if c["cve_id"] == "CVE-2023-20029")
    raw = (FIXTURE.parent / "cisco-model-priv-esc.csaf.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == case["source_sha256"]
    result = switching.extract(
        raw,
        case["source_url"],
        "cisco",
        {"advisory_id": case["data"]["document"]["tracking"]["id"]},
    )
    assert len(result["claims"]) == 2
    for c in result["claims"]:
        assert sorted({b["model"] for b in c["platform_bindings"]}) == ["9200", "9300"]
        assert c["status"] == "affected"
        assert c["version_expressions"] in [["17.7", "17.7.1"], ["17.8", "17.8.1"]]
        assert c["scope"] == "cve_specific"


@pytest.mark.parametrize(
    "document", [None, {}, {"notes": None}, {"notes": [None]}, {"tracking": None, "notes": []}]
)
def test_malformed_unknown_notes_abstain_with_reason(document):
    from infrastructure_impact.adapters.cisco_models import note_bindings

    result = note_bindings(
        {"document": document},
        "https://example.test/unknown",
        "a" * 64,
        "CVE-2026-12345",
        "affected",
        "cisco-iosxe",
        "IOS XE Software",
    )
    assert result["bindings"] == []
    assert result["diagnostics"]


def test_explicit_9300l_and_chassis_do_not_alias_other_targets():
    for name, expected in [
        ("Cisco Catalyst 9300L Series Switches", "9300L"),
        ("Cisco Catalyst C9407R", "C9407R"),
        ("Cisco Catalyst C9606R", "C9606R"),
    ]:
        assert {b["model"] for b in run(structural(name))[0]["platform_bindings"]} == {expected}


def test_cached_negative_notes_and_mixed_platform_table_never_assign_models():
    from infrastructure_impact.adapters.cisco_models import note_bindings

    controls = json.loads((FIXTURE.parent / "cisco-model-controls.json").read_text())
    assert len(controls) == 4
    for case in controls:
        r = note_bindings(
            case["data"],
            case["source_url"],
            case["source_sha256"],
            case["cve_id"],
            "affected",
            "cisco-iosxe",
            "IOS XE Software",
        )
        assert r["bindings"] == []
        assert r["conditions"] == []
        assert r["diagnostics"]


def test_source_revision_change_only_abstains_locally_and_keeps_os_claims():
    case = next(c for c in json.loads(FIXTURE.read_text()) if c["cve_id"] == "CVE-2023-20029")
    data = json.loads((FIXTURE.parent / "cisco-model-priv-esc.csaf.json").read_text())
    data["document"]["notes"][1]["text"] += " Unknown new qualification."
    claims = run(data, case["source_url"])
    assert len(claims) == 2
    assert all(c["status"] == "affected" and c["family"] == "cisco-iosxe" for c in claims)
    assert all(c["platform_bindings"] == [] for c in claims)
    assert all("cisco_model_note_rule_mismatch" in c["issues"] for c in claims)


def test_real_cached_model_claims_pass_native_public_evidence_contract():
    from infrastructure_impact.application import switching_evidence as evidence

    case = next(c for c in json.loads(FIXTURE.read_text()) if c["cve_id"] == "CVE-2023-20029")
    raw = (FIXTURE.parent / "cisco-model-priv-esc.csaf.json").read_bytes()
    result = extract(
        raw,
        case["source_url"],
        "cisco",
        {"advisory_id": case["data"]["document"]["tracking"]["id"]},
    )

    def receipt(value):
        if isinstance(value, dict):
            if "source_url" in value and "retrieved_at" in value:
                value["retrieved_at"] = "2026-11-13T20:08:00Z"
            for child in value.values():
                receipt(child)
        elif isinstance(value, list):
            for child in value:
                receipt(child)

    receipt(result)
    public = evidence.project(
        dict(claims=result["claims"], coverage=[], issues=[]),
        publication=None,
        generated_at="2026-11-13T21:00:00Z",
    )
    assert len(public["claims"]) == 2
    assert all(c["scope_level"] == "model_qualified" for c in public["claims"])
    assert all(c["revision"] is None for c in public["claims"])
