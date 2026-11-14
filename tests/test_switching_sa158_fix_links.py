"""Authored SA158 structure; injected digest tests contracts, never source bytes."""

import copy
import json

import pytest
from jsonschema import ValidationError
from test_switching_aruba_fix_links import AT, browser, native_stream, reidentify

from infrastructure_impact.adapters import switching
from infrastructure_impact.application import switching_evidence as evidence

URL = (
    "https://www.arista.com/assets/data/SecurityAdvisories/CSAF/"
    "arista_networks_security_advisory_158_CSAF.json"
)
DIGEST = "0dc70cae7fe0380e01d4872a157c7d97c665da33b9d1fb74996e24c1321a6349"
ADVISORY = "Arista Networks Security Advisory 158"
CVES = ["CVE-2026-73456", "CVE-2026-73457"]


def authored_csaf():
    """Finite structural fixture with literal owned fixes and synthetic context."""
    leaves = [
        dict(
            category="product_version",
            name="EOS version " + version,
            product=dict(name="EOS version " + version, product_id=pid),
        )
        for pid, version in [
            ("CSAFPID-1", "4.35.6"),
            ("CSAFPID-2", "4.34.8"),
            ("CSAFPID-3", "4.36.2"),
            ("CSAFPID-0", "4.34.2"),
        ]
    ]
    return dict(
        document=dict(
            tracking=dict(
                id=ADVISORY,
                version="1",
                status="interim",
                initial_release_date="2026-09-17T11:48:13Z",
                current_release_date="2026-09-17T11:48:13Z",
            )
        ),
        product_tree=dict(
            branches=[
                dict(
                    category="vendor",
                    name="Arista Networks, Inc.",
                    branches=[
                        dict(
                            category="product_family",
                            name="Software Products",
                            branches=[dict(category="product_name", name="EOS", branches=leaves)],
                        )
                    ],
                )
            ]
        ),
        vulnerabilities=[
            dict(
                cve=cve,
                product_status=dict(
                    first_affected=["CSAFPID-0"],
                    fixed=["CSAFPID-1", "CSAFPID-2", "CSAFPID-3"],
                ),
                notes=[dict(category="other", text="Authored configuration prerequisite.")],
                remediations=[
                    dict(
                        category="vendor_fix",
                        details="Fixed in EOS version 4.34.8",
                        product_ids=["CSAFPID-2"],
                    ),
                    dict(
                        category="vendor_fix",
                        details="Fixed in EOS version 4.35.6",
                        product_ids=["CSAFPID-1"],
                    ),
                    dict(
                        category="vendor_fix",
                        details="Fixed in EOS version 4.36.2",
                        product_ids=["CSAFPID-3"],
                    ),
                    dict(
                        category="none_available",
                        details="Not fixed in EOS version 4.34.2",
                        product_ids=["CSAFPID-0"],
                    ),
                    dict(
                        category="mitigation",
                        details="Authored mitigation; separate from software fixes.",
                    ),
                ],
            )
            for cve in CVES
        ],
    )


def extracted(data=None, *, digest=DIGEST, url=URL):
    # Only this typed seam accepts an injected hash. The real-byte operator
    # receipt separately verifies the capture, with no raw vendor fixture here.
    return switching._csaf(
        json.dumps(data or authored_csaf()).encode(),
        url,
        "arista",
        {"advisory_id": ADVISORY},
        digest,
    )


def links(report):
    return [
        (claim, rem)
        for claim in report["claims"]
        for rem in claim["remediations"]
        if rem.get("scope_binding", {}).get("basis") == "reviewed_source_sections"
    ]


def projected():
    result = extracted()

    def stamp(value):
        if isinstance(value, dict):
            if "retrieved_at" in value:
                value["retrieved_at"] = AT
            for child in value.values():
                stamp(child)
        elif isinstance(value, list):
            for child in value:
                stamp(child)

    stamp(result)
    for claim in result["claims"]:
        claim["revision"] = "authored-sa158-revision"
    result.pop("bundles")
    return evidence.project(result, publication=None, generated_at=AT)


def test_two_exact_known_fixed_links_preserve_scope_and_pass_boundaries(monkeypatch):
    report = projected()
    assert len(links(report)) == 2
    assert len(report["claims"]) == 8
    assert sum(c["status"] == "affected" for c in report["claims"]) == 2
    assert sum(c["status"] == "fixed" for c in report["claims"]) == 6
    assert {c["cve_id"] for c, _ in links(report)} == set(CVES)
    for claim, rem in links(report):
        assert claim["product_id"] == "CSAFPID-0"
        assert claim["version_expressions"] == ["EOS version 4.34.2"]
        assert rem["version_expressions"] == ["EOS version 4.34.8"]
        assert rem["scope_binding"]["fixed_product_id"] == "CSAFPID-2"
        assert rem["product_ids"] == []
        assert rem["availability"] == "vendor_reports_fixed"
        assert rem["availability_date"] is None
        assert {r["category"] for r in claim["remediations"]} == {
            "none_available",
            "mitigation",
            "vendor_fix",
        }
    assert all(c["platform_bindings"] == [] for c in report["claims"])
    assert all(
        c["conditions"] == ["Authored configuration prerequisite."] for c in report["claims"]
    )
    assert all(c["publisher"]["status"] == "interim" for c in report["claims"])
    assert all(c["initial_published_at"] == "2026-09-17T11:48:13Z" for c in report["claims"])
    assert authored_csaf()["vulnerabilities"][0]["product_status"] == {
        "first_affected": ["CSAFPID-0"],
        "fixed": ["CSAFPID-1", "CSAFPID-2", "CSAFPID-3"],
    }
    for compiled in (False, True):
        validators = evidence._compiled_validators() if compiled else evidence._validators()
        validators["switching-evidence-v1.json"].validate(report)
        evidence._validate_evidence_semantics(report)
    assert native_stream(report, monkeypatch) == report["claims"]
    assert browser(report) == browser(report, stream=True) == "accepted"


@pytest.mark.parametrize(
    "mutation", ["hash", "url", "parent", "cve", "details", "fixed_version", "future_date"]
)
def test_source_drift_abstains_without_losing_affected_claims(mutation):
    data = authored_csaf()
    digest, url = DIGEST, URL
    if mutation == "hash":
        digest = "f" * 64
    elif mutation == "url":
        url += "?changed"
    elif mutation == "parent":
        data["product_tree"]["branches"][0]["branches"][0]["branches"][0]["name"] = "Other software"
    elif mutation == "cve":
        data["vulnerabilities"][0]["cve"] = "CVE-2026-99999"
    else:
        for vuln in data["vulnerabilities"]:
            if mutation == "details":
                vuln["remediations"][0]["details"] += " (planned)"
            elif mutation == "future_date":
                vuln["remediations"][0]["date"] = "2099-01-01T00:00:00Z"
        if mutation == "fixed_version":
            leaf = data["product_tree"]["branches"][0]["branches"][0]["branches"][0]["branches"][1]
            leaf["name"] = leaf["product"]["name"] = "EOS version 4.34.9"
    result = extracted(data, digest=digest, url=url)
    assert links(result) == []
    assert sum(c["status"] == "affected" for c in result["claims"]) == 2
    assert "reviewed_fix_source_drift" in result["issues"]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "duplicate",
        "cross_cve",
        "joint_details",
        "missing_product_id",
        "unregistered_product",
    ],
)
def test_forged_link_rejected_by_python_native_and_browser(monkeypatch, mutation):
    report = projected()
    claim, rem = links(report)[0]
    fixed = next(
        c
        for c in report["claims"]
        if c["cve_id"] == claim["cve_id"] and c["product_id"] == "CSAFPID-2"
    )
    if mutation == "missing":
        report["claims"].remove(fixed)
    elif mutation == "duplicate":
        duplicate = copy.deepcopy(fixed)
        duplicate["conditions"].append("Conflicting authored sibling.")
        report["claims"].append(duplicate)
    elif mutation == "cross_cve":
        fixed["cve_id"] = CVES[1]
    elif mutation == "missing_product_id":
        del rem["scope_binding"]["fixed_product_id"]
    elif mutation == "unregistered_product":
        rem["scope_binding"]["fixed_product"] = "EOS version 4.35.6"
    else:
        original = next(r for r in fixed["remediations"] if r["category"] == "vendor_fix")
        original["details"] = rem["details"] = "Forged fixed release."
    reidentify(report)
    for compiled in (False, True):
        validators = evidence._compiled_validators() if compiled else evidence._validators()
        with pytest.raises((ValueError, ValidationError)):
            validators["switching-evidence-v1.json"].validate(report)
            evidence._validate_evidence_semantics(report)
    with pytest.raises((ValueError, ValidationError)):
        native_stream(report, monkeypatch)
    assert browser(report) == browser(report, stream=True) == "rejected"
