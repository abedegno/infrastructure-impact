"""Reviewed per-CVE platform scope must not broaden software branches."""

import copy
import json
from datetime import datetime, timezone
from hashlib import sha256

import pytest

from infrastructure_impact.plugins.registry import default_registry

URL = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fast-Zqr6DD5/csaf/cisco-sa-fast-Zqr6DD5.json"


def document():
    text = (
        "A vulnerability in the fast reload feature of Cisco IOS XE Software running on "
        "Cisco Catalyst 3650, Cisco Catalyst 3850, Cisco Catalyst 9300, and Cisco Catalyst "
        "9300L Series Switches could allow an authenticated, local attacker to execute code."
    )
    return {
        "document": {
            "title": "Synthetic per-CVE scope test",
            "tracking": {"id": "cisco-sa-fast-Zqr6DD5", "initial_release_date": "2021-03-24"},
            "notes": [
                {"title": "Summary", "text": "Synthetic summary."},
                {"title": "Vulnerable Products", "text": text},
                {"title": "Products Confirmed Not Vulnerable", "text": "Other software."},
                {
                    "title": "Details",
                    "text": "A software release that is affected by one of the vulnerabilities "
                    "may not be affected by the other vulnerability.\n\n"
                    f"CVE-2021-1375: Synthetic issue one\n\n{text}\n\n"
                    f"CVE-2021-1376: Synthetic issue two\n\n{text}",
                },
            ],
        },
        "product_tree": {
            "branches": [
                {
                    "category": "product_name",
                    "name": "Cisco IOS XE Software",
                    "branches": [
                        {
                            "category": "product_version",
                            "name": version,
                            "product": {"product_id": pid, "name": version},
                        }
                        for pid, version in [("one", "16.9.1"), ("two", "17.3.1")]
                    ],
                }
            ]
        },
        "vulnerabilities": [
            {"cve": "CVE-2021-1375", "product_status": {"known_affected": ["one"]}},
            {"cve": "CVE-2021-1376", "product_status": {"known_affected": ["two"]}},
        ],
    }


def extract(monkeypatch, data=None, *, trust=True, url=URL):
    # A synthetic capture cannot be a production trust anchor. Substitute only
    # the reviewed digest, leaving the actual parser and source-scope checks live.
    from infrastructure_impact.adapters import cisco_platforms

    raw = json.dumps(data or document()).encode()
    if trust:
        monkeypatch.setattr(cisco_platforms, "REVIEWED_SHA256", sha256(raw).hexdigest())
    registry = default_registry()
    normalized = registry.normalize(raw, url, "cisco")
    return registry.research_evidence(raw, url, "cisco", normalized)


def test_reviewed_platforms_preserve_distinct_cve_and_version_branches(monkeypatch):
    result = extract(monkeypatch)
    claims = result["claims"]
    assert len(claims) == 2
    assert {(c["cve_id"], tuple(c["version_expressions"])) for c in claims} == {
        ("CVE-2021-1375", ("16.9.1",)),
        ("CVE-2021-1376", ("17.3.1",)),
    }
    for c in claims:
        assert c["scope_level"] == "model_qualified"
        assert c["named_platforms"] == ["Cisco Catalyst 9300", "Cisco Catalyst 9300L"]
        assert {b["model"] for b in c["platform_bindings"]} == {"9300", "9300L"}
        assert all(b["basis"] == "publisher_explicit" for b in c["platform_bindings"])
        assert all(c["cve_id"] in b["source"]["source_locator"] for b in c["platform_bindings"])
        assert c["remediations"] == []
        assert any("other vulnerability" in condition for condition in c["conditions"])


def test_unreviewed_source_bytes_do_not_authorize_platform_scope(monkeypatch):
    result = extract(monkeypatch, trust=False)
    assert all(
        c["scope_level"] == "os_family" and not c["platform_bindings"] for c in result["claims"]
    )
    assert "reviewed_platform_scope_changed" in result["issues"]


@pytest.mark.parametrize(
    "mutation",
    ["missing_local_model", "wrong_heading", "missing_warning", "duplicate_cve", "wrong_identity"],
)
def test_hash_review_does_not_replace_per_cve_scope_guards(monkeypatch, mutation):
    d = document()
    if mutation == "missing_local_model":
        # The global Vulnerable Products paragraph still names both models.
        d["document"]["notes"][3]["text"] = d["document"]["notes"][3]["text"].replace(
            "Cisco Catalyst 9300L", "Other platform"
        )
    elif mutation == "wrong_heading":
        d["document"]["notes"][3]["title"] = "Other Details"
    elif mutation == "missing_warning":
        d["document"]["notes"][3]["text"] = d["document"]["notes"][3]["text"].replace(
            "may not be affected by the other vulnerability", "always has identical releases"
        )
    elif mutation == "duplicate_cve":
        d["vulnerabilities"].append(copy.deepcopy(d["vulnerabilities"][0]))
    else:
        d["document"]["tracking"]["id"] = "other-advisory"
    result = extract(monkeypatch, d)
    assert not any(c["platform_bindings"] for c in result["claims"])


def test_another_cisco_route_does_not_reuse_platform_prose(monkeypatch):
    result = extract(monkeypatch, url=URL.replace("fast-Zqr6DD5", "other-advisory"))
    assert not any(c["platform_bindings"] for c in result["claims"])


def test_model_bindings_survive_full_evidence_validation(monkeypatch):
    from infrastructure_impact.adapters import cisco_platforms
    from infrastructure_impact.application import switching_evidence as evidence
    from infrastructure_impact.storage.repository import connect, ingest, latest

    raw = json.dumps(document()).encode()
    monkeypatch.setattr(cisco_platforms, "REVIEWED_SHA256", sha256(raw).hexdigest())
    with connect(":memory:") as db:
        ingest(db, raw, URL, default_registry().normalize, "cisco")
        at = datetime.now(timezone.utc).isoformat()
        report = evidence.project(
            evidence.inputs(db, latest(db)), publication=None, generated_at=at
        )
    evidence.validate_evidence(report, publication=None, generated_at=at)
    assert len(report["claims"]) == 2
    assert all(c["scope_level"] == "model_qualified" for c in report["claims"])


def test_software_exclusion_is_not_promoted_by_affected_platform_context(monkeypatch):
    d = document()
    d["vulnerabilities"][0]["product_status"] = {"known_not_affected": ["one"]}
    result = extract(monkeypatch, d)
    excluded = next(c for c in result["claims"] if c["cve_id"] == "CVE-2021-1375")
    assert excluded["status"] == "unaffected" and not excluded["platform_bindings"]
