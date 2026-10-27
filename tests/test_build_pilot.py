"""Build references and backport notes cannot certify an installed inventory."""

import json
from copy import deepcopy
from hashlib import sha256
from unittest.mock import patch

import pytest

from infrastructure_impact.adapters.arista_openssh import SPANS, URL, openssh_scope
from infrastructure_impact.adapters.arista_scoped import article
from infrastructure_impact.application.build_pilot import UNKNOWN_FIELDS, build_pilot
from infrastructure_impact.application.product_cohorts import product_cohorts
from infrastructure_impact.application.research_reports import validator
from infrastructure_impact.settings import PACKAGE


def synthetic():
    raw = b"""<div class="item-page"><h2>Security Advisory 0100</h2>
<table><tr><td>1.0</td><td>July 8, 2024</td><td>Synthetic initial entry</td></tr></table>
<p>The CVE-ID tracking this issue: CVE-2024-6387 CVE-2024-6409</p>
<h3>Vulnerability Assessment</h3><h3>Affected Software</h3>
<p>The following product releases are affected for CVE-2024-6387</p><h4>EOS release versions:</h4><ul><li>4.32.1F and below releases in the 4.32.x train only.</li></ul>
<p>The following product releases are affected for CVE-2024-6409</p><h4>EOS release versions:</h4><ul><li>Synthetic affected build.</li></ul>
<h3>Affected Platforms</h3><p>Arista EOS-based products Synthetic EOS family</p><p>Arista Wireless Access Points Synthetic AP family</p>
<h3>Mitigation</h3><p>For both synthetic issues, restricting SSH can reduce exposure.</p>
<h3>Resolution</h3><p>CVE-2024-6387 synthetic EOS fix 4.32.2F and later releases in the 4.32.x train</p><p>CVE-2024-6409 synthetic EOS fixes 4.34.1F, 4.33.4M, 4.32.6M</p><p>Vulnerability Scanner Advisory: Synthetic backport qualification.</p>
<h3>Hotfix</h3><p>The following hotfix is a separate installation option.</p></div>"""
    text = article(raw, URL, "0100")[0].text()
    spans = {
        k: (start, end, sha256(text[text.index(start) : text.index(end)].encode()).hexdigest())
        for k, (start, end, _) in SPANS.items()
    }
    return raw, spans


def test_scoped_arista_fixes_preserve_affected_claims_and_separate_cves():
    raw, spans = synthetic()
    with patch("infrastructure_impact.adapters.arista_openssh.SPANS", spans):
        result = openssh_scope(raw, URL, "arista")
    fixed = [a for a in result["assessments"] if a["status"] == "fixed"]
    assert len(fixed) == 2 and any(a["status"] == "affected" for a in result["assessments"])
    assert fixed[0]["cve_id"] == "CVE-2024-6387" and len(fixed[0]["versions"]) == 1
    assert fixed[1]["cve_id"] == "CVE-2024-6409" and len(fixed[1]["versions"]) == 3
    assert all(a["product"] == "Arista EOS" for a in fixed)
    assert all("Wireless" not in str(a["platforms"]) for a in fixed)
    assert all(a["exposure"][0]["category"] == "publisher_backport_statement" for a in fixed)
    assert "not an available software fix" in fixed[0]["exposure"][1]["details"]


@pytest.mark.parametrize(
    "before,after",
    [
        (b"Synthetic EOS family", b"Changed model exclusion"),
        (b"4.32.2F", b"4.32.3F"),
        (b"restricting SSH", b"enabling extra access"),
    ],
)
def test_changed_platform_resolution_or_mitigation_requires_source_review(before, after):
    raw, spans = synthetic()
    with (
        patch("infrastructure_impact.adapters.arista_openssh.SPANS", spans),
        pytest.raises(ValueError),
    ):
        openssh_scope(raw.replace(before, after), URL, "arista")


def dataset():
    targets = json.loads((PACKAGE / "resources/build-pilot.json").read_text())["targets"]
    records = []
    for t in targets:
        claim = {
            "product": t["product_literal"],
            "cve_id": t["cve_id"],
            "status": "fixed",
            "scope": "cve_specific",
            "versions": [{"expression": t["expression"]}] if t["expression"] else [],
            "product_context": [["product_version", t["firmware_build"]]],
            "evidence_locator": "Synthetic exact row",
            "exposure": [
                {
                    "category": "publisher_backport_statement",
                    "details": "Synthetic vendor backport context.",
                }
            ]
            if t["vendor"] == "arista"
            else [],
        }
        records.append(
            {
                "vendor": t["vendor"],
                "source_url": t["source_url"],
                "sha256": "a" * 64,
                "source_observed_at": "2026-10-27T00:00:00Z",
                "assessments": [claim],
            }
        )
    return {
        "records": records,
        "vendors": {"arista": "Arista", "aruba": "Aruba"},
        "fix_leads": {"sources": []},
    }


def test_exact_references_leave_all_image_package_hardware_and_runtime_fields_unknown():
    d = dataset()
    report = product_cohorts(d)
    validator("product_cohorts").validate(report)
    p = report["build_pilot"]
    assert len(p["targets"]) == 2 and p["rate_comparison"] is None
    for row in p["targets"]:
        fields = {f["field"]: f for f in row["fields"]}
        assert fields["firmware_reference"]["value"] == row["firmware_build"]
        assert all(
            fields[k]["value"] is None and fields[k]["state"] == "unknown" for k in UNKNOWN_FIELDS
        )
        assert row["verified_inventory"] is False
    assert p["targets"][1]["fields"][-1]["state"] == "unknown"
    changed = deepcopy(d)
    changed["records"][0]["assessments"][0]["versions"][0]["expression"] = (
        "4.32.3F and later releases in the 4.32.x train"
    )
    assert build_pilot(changed)["targets"][0]["fields"][0]["state"] == "unknown"


def test_wrong_product_vendor_cve_scope_and_draft_cannot_fill_pilot():
    for field, value in [
        ("product", "Another appliance"),
        ("cve_id", "CVE-2024-6409"),
        ("scope", "bulletin_shared"),
        ("status", "affected"),
    ]:
        d = dataset()
        d["records"][0]["assessments"][0][field] = value
        assert build_pilot(d)["targets"][0]["fields"][0]["state"] == "unknown"
    d = dataset()
    d["records"][0]["document_status"] = "draft"
    assert build_pilot(d)["targets"][0]["fields"][0]["state"] == "unknown"


def test_another_vendor_or_source_cannot_supply_exact_build_reference():
    for key, value in [("vendor", "juniper"), ("source_url", URL + "?different=scope")]:
        d = dataset()
        d["records"][0][key] = value
        assert build_pilot(d)["targets"][0]["fields"][0]["state"] == "unknown"


def test_context_fields_use_their_own_source_section_locators():
    d = dataset()
    claim = d["records"][0]["assessments"][0]
    claim["exposure"][0]["source_locator"] = "Resolution / Scanner advisory"
    claim["exposure"].append(
        {
            "category": "publisher_platform_scope",
            "details": "Synthetic platform applicability",
            "source_locator": "Affected Platforms",
        }
    )
    fields = {f["field"]: f for f in build_pilot(d)["targets"][0]["fields"]}
    assert fields["backport_statement"]["evidence"][0]["locator"] == "Resolution / Scanner advisory"
    assert (
        fields["platform_applicability_context"]["evidence"][0]["locator"] == "Affected Platforms"
    )
    assert fields["hardware_model"]["value"] is None
