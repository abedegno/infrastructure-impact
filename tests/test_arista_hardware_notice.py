"""Authored reduction of SA-0226's reviewed hardware/exclusion boundaries."""

import hashlib
import json

import pytest

from infrastructure_impact.plugins.registry import default_registry

URL = "https://www.arista.com/en/support/advisories-notices/security-advisory/25048-security-advisory-0226"
IDS = [
    "CVE-2024-38798",
    "CVE-2024-42446",
    "CVE-2025-11187",
    "CVE-2025-15467",
    "CVE-2025-15468",
    "CVE-2025-15469",
    "CVE-2025-31648",
    "CVE-2025-66199",
    "CVE-2025-68160",
    "CVE-2025-69418",
    "CVE-2025-69419",
    "CVE-2025-69420",
    "CVE-2025-69421",
    "CVE-2026-22795",
    "CVE-2026-22796",
]
PLATFORMS = [
    "720XP/722XPM Series",
    "7050X3/X4 Series",
    "750X Series",
    "CloudEOS",
    "CloudVision eXchange, virtual or physical appliance",
]
MARKER = (
    "The following product versions and platforms <b>are not</b> affected by this vulnerability:"
)
FORMAT = "Arista reviewed hardware notice HTML"


def table(headers, rows):
    return (
        '<table class="data-table"><tbody><tr>'
        + "".join(f"<td><b>{h}</b></td>" for h in headers)
        + "</tr>"
        + "".join("<tr>" + "".join(f"<td>{v}</td>" for v in row) + "</tr>" for row in rows)
        + "</tbody></table>"
    )


def source(edit=lambda s: s):
    cva = table(["CVE", "DCA-250-CV"], [[IDS[0], "X"]])
    cva += '<div class="clear20"> </div>' + table(
        ["CVE", "DCA-300-CV,<br>DCA-350E-CV"], [[cid, "X"] for cid in IDS]
    )
    html = f"""<nav>Arista EOS CVE-2099-99999</nav>
    <div class="item-page"><div class="page-header"><h2>Security Advisory 0226 <a>PDF</a></h2></div>
    <p>Date: November 10, 2026</p>
    {table(["Revision", "Date", "Changes"], [["1.0", "November 10, 2026", "Initial release"]])}
    <h2>Description</h2><p>Synthetic Dell OEM server hardware context, reference CVE-2099-22222.</p>
    <h2>Vulnerability Assessment</h2><h3>Affected Platforms</h3>
    <p>Arista SKUs utilize Dell server hardware, depending on server model and configuration.</p>
    <h4>CloudVision Appliance (CVA)</h4><p>Resolved CVEs apply to the specified hardware SKUs.</p>
    <ul><li>DCA-250-CV</li><li>DCA-300-CV</li><li>DCA-350E-CV</li></ul>
    <p>In the table, an X indicates the CVE can be resolved by following the steps detailed in the Resolution section.</p>
    <h4 id="pageLink-1">CVEs Resolved by upgrading to CVA 7.2.0</h4>{cva}
    <h4>Danz Monitoring Fabric (DMF) Appliances</h4><p>Customers monitor the OEM vendor advisory page.</p>
    {table(["DMF SKU", "OEM Product Name"], [["DCA-DM-AN450", "PowerEdge R450"]])}
    <h4>Arista Guardian for Network Identity (AGNI) Appliance</h4><p>Customers monitor the OEM vendor advisory page.</p>
    {table(["AGNI SKU", "OEM Product Name"], [["DCA-AGNI-100", "PowerEdge R450"]])}
    <div>{MARKER}</div><div class="clear10"> </div>
    <ul><li>Arista EOS-based products:</li><ul>{"".join(f"<li>{p}</li>" for p in PLATFORMS)}</ul>
    <li>Wi-Fi Access Points</li><li>CloudVision Appliance</li><ul><li>DCA-400-CV</li><li>DCA-450-CV</li></ul>
    <li>CloudVision Appliance Software</li></ul>
    <h2>Required Configuration for Exploitation</h2><p>No configuration exists.</p>
    <h2>Indicators of Compromise</h2><p>Refer to appropriate Dell advisory.</p>
    <h2>Mitigation</h2><p>No mitigation exists.</p>
    <h2 id="pageLink-2">Resolution</h2><h3>CloudVision Appliance (CVA)</h3>
    <ol><li>Option A: Fresh Installation of CVA 7.2.0</li><li>Option B: Manually update firmware.</li></ol>
    <h4>Recommended Firmware Versions</h4>
    {table(["SKU", "BIOS", "iDRAC"], [["DCA-350-CV", "1.20.2", "7.30.10.50"]])}
    <h3>DANZ Monitoring Fabric (DMF) Appliances</h3><p>Monitor Dell advisory page.</p>
    <h3>Arista Guardian for Network Identity (AGNI) Appliance</h3><p>Monitor Dell advisory page.</p>
    <h3>Hotfix</h3><p>There are no hotfixes available for this issue.</p>
    <h3>For More Information</h3><p>PRIVATE_RAW_SENTINEL CVE-2099-33333</p></div>"""
    return edit(html).encode()


def normalize(raw=None, url=URL, vendor="arista"):
    return default_registry().normalize(source() if raw is None else raw, url, vendor)


def test_notice_owns_only_shared_unaffected_eos_not_hardware_fixes():
    doc = normalize()
    assert doc["source_format"] == FORMAT
    assert doc["cves"] == IDS
    assert (doc["published_at"], doc["updated_at"]) == ("2026-11-10", "2026-11-10")
    assert doc["timeline"] == [dict(number="1.0", date="2026-11-10", summary="Initial release")]
    assert len(doc["assessments"]) == 15
    assert {a["cve_id"] for a in doc["assessments"]} == set(IDS)
    for a in doc["assessments"]:
        assert (a["product"], a["status"], a["scope"]) == (
            "Arista EOS",
            "unaffected",
            "bulletin_shared",
        )
        assert a["platforms"] == PLATFORMS
        assert not a["versions"] and not a["remediations"] and not a["exposure"]
    assert "DCA-350E-CV" in json.dumps(doc["notes"])
    assert "DCA-350-CV" in json.dumps(doc["notes"])
    assert "discrepancy" in " ".join(doc["warnings"])
    assert "PRIVATE_RAW_SENTINEL" not in json.dumps(doc)


def test_bridge_keeps_history_provenance_literal_unresolved_platforms():
    raw = source()
    doc = normalize(raw)
    result = default_registry().research_evidence(raw, URL, "arista", doc)
    assert result["issues"] == result["bundles"] == []
    assert len(result["claims"]) == 15
    for c in result["claims"]:
        assert (c["family"], c["status"], c["scope"], c["product_id"]) == (
            "arista-eos",
            "unaffected",
            "bulletin_shared",
            None,
        )
        assert c["named_platforms"] == PLATFORMS
        assert all(
            b["model"] is None and b["basis"] == "unresolved" for b in c["platform_bindings"]
        )
        assert not c["remediations"] and not c["conditions"] and not c["version_expressions"]
        assert c["publisher"]["id"] == "Security Advisory 0226"
        assert c["publisher"]["sequence"] == "1.0"
        assert c["source"]["source_url"] == URL
        assert c["source"]["source_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "old,new",
    [
        (MARKER, "The following products are affected:"),
        (f"<div>{MARKER}</div>", ""),
        (f"<div>{MARKER}</div>", f"<div>{MARKER}</div><div>{MARKER}</div>"),
        (f"<div>{MARKER}</div>", "<h2>Other Section</h2>" + f"<div>{MARKER}</div>"),
        ("Arista EOS-based products:", "Unknown family:"),
        ("<li>750X Series</li>", "<li>750X Series<ul><li>Except some hardware</li></ul></li>"),
        ("<li>750X Series</li>", "<li>750X Series"),
        ("<li>750X Series</li>", "<li hidden>750X Series</li>"),
        ("<li>750X Series</li>", '<li style="display:none">750X Series</li>'),
        ("<li>750X Series</li>", "<li><script>alert(1)</script>750X Series</li>"),
        ("<li>750X Series</li>", "<li>750X Series</li> except some deployments"),
        ("<ul><li>Arista EOS-based", "<ul hidden><li>Arista EOS-based"),
        ("<ul><li>Arista EOS-based", "<ul>Except some deployments:<li>Arista EOS-based"),
        ("DCA-300-CV,<br>DCA-350E-CV", "Arista EOS"),
        ("CVEs Resolved by upgrading to CVA 7.2.0", "Other CVEs"),
        ("<h4>CloudVision Appliance (CVA)</h4>", "<h4>Other product</h4>"),
        ("<td>CVE-2026-22796</td>", "<td>not-a-CVE</td>"),
        ("<td>CVE-2026-22796</td><td>X</td>", "<td>CVE-2026-22796</td><td>Y</td>"),
        ("<td>CVE-2026-22796</td>", '<td rowspan="2">CVE-2026-22796</td>'),
        ("<td>CVE-2026-22796</td>", "<td><table><tr><td>CVE-2026-22796</td></tr></table></td>"),
        ("Security Advisory 0226 <a>", "Security Advisory 0225 <a>"),
        ("<td>1.0</td>", "<td>1.1</td>"),
        ("<td>November 10, 2026</td>", "<td>November 11, 2026</td>"),
        ("<td>Initial release</td>", "<td>Changed scope</td>"),
        ('class="item-page"', 'class="item-page" hidden'),
        ("<h3>Affected Platforms</h3>", "<h3>Affected Platforms</h3><h3>Affected Platforms</h3>"),
    ],
)
def test_changed_ownership_or_unsupported_markup_fails_visibly(old, new):
    with pytest.raises(ValueError):
        normalize(source(lambda s: s.replace(old, new)))


def test_cve_bait_outside_owned_tables_does_not_create_claims():
    raw = source(
        lambda s: s.replace(
            "<h4>CloudVision Appliance (CVA)",
            "<p>CVA reference CVE-2099-55555; Arista EOS</p><h4>CloudVision Appliance (CVA)",
        )
    )
    assert normalize(raw)["cves"] == IDS


def test_missing_or_duplicated_owned_tables_cannot_be_rescued_by_navigation():
    original = table(["CVE", "DCA-250-CV"], [[IDS[0], "X"]])
    for edit in [
        lambda s: s.replace(original, ""),
        lambda s: s.replace(original, original + original),
        lambda s: "<nav>" + original + "</nav>" + s.replace(original, ""),
    ]:
        with pytest.raises(ValueError):
            normalize(source(edit))


@pytest.mark.parametrize(
    "url,vendor",
    [
        (URL + "/", "arista"),
        (URL + "?x=1", "arista"),
        (URL.replace("www.arista.com", "foreign.example"), "arista"),
        (URL, "cisco"),
    ],
)
def test_reviewed_parser_rejects_non_exact_route_or_vendor(url, vendor):
    from infrastructure_impact.adapters.arista_hardware_notice import parse

    with pytest.raises(ValueError):
        parse(source(), url, vendor)


def test_public_projection_does_not_add_affected_cves_events_or_model_qualification(tmp_path):
    from infrastructure_impact.application import switching_comparison as comparison
    from infrastructure_impact.application import switching_evidence as evidence
    from infrastructure_impact.application.publication import public_projection
    from infrastructure_impact.application.query import state
    from infrastructure_impact.storage.repository import connect, ingest

    with connect(tmp_path / "notice.sqlite") as db:
        ingest(db, source(), URL, default_registry().normalize, "arista")
        public = public_projection(state(db))
    evidence.validate_evidence(public["switching_evidence"])
    selected = comparison.select_report(public["switching_comparison"], vendor="arista")
    evidence.validate_comparison(selected)
    counts = selected["rows"][0]["counts"]
    assert counts["cves"] == 15
    assert (
        counts["affected_cves"] == counts["remediation_events"] == counts["planned_fix_claims"] == 0
    )
    model = comparison.select_report(
        public["switching_comparison"], vendor="arista", scope_level="model_qualified"
    )
    assert model["rows"][0]["counts"]["cves"] == 0
    assert "PRIVATE_RAW_SENTINEL" not in json.dumps(public)


@pytest.mark.parametrize(
    "old,new",
    [
        ("<td>DCA-350-CV</td>", "<td>DCA-350E-CV</td>"),
        ("<h4>Recommended Firmware Versions</h4>", "<h4>Other Firmware Versions</h4>"),
        ("<tbody><tr><td><b>CVE</b>", "<tbody>Except these CVEs:<tr><td><b>CVE</b>"),
    ],
)
def test_context_discrepancy_and_unbound_table_text_cannot_be_silently_discarded(old, new):
    with pytest.raises(ValueError):
        normalize(source(lambda s: s.replace(old, new)))


def test_owned_valid_row_update_is_read_from_table_instead_of_hardcoded_ids():
    raw = source(lambda s: s.replace("<td>CVE-2026-22796</td>", "<td>CVE-2026-99999</td>"))
    doc = normalize(raw)
    assert doc["cves"] == IDS[:-1] + ["CVE-2026-99999"]
    assert {a["cve_id"] for a in doc["assessments"]} == set(IDS[:-1] + ["CVE-2026-99999"])
    assert all(
        a["status"] == "unaffected" and a["scope"] == "bulletin_shared" for a in doc["assessments"]
    )


def test_literal_publisher_nesting_keeps_exchange_but_not_outer_product_peers():
    doc = normalize()
    for a in doc["assessments"]:
        assert "CloudVision eXchange, virtual or physical appliance" in a["platforms"]
        assert not {
            "Wi-Fi Access Points",
            "CloudVision Appliance",
            "DCA-400-CV",
            "DCA-450-CV",
        } & set(a["platforms"])


def test_bare_article_qualifier_between_exclusion_marker_and_list_requires_review():
    raw = source(
        lambda s: s.replace(
            f"<div>{MARKER}</div>",
            f"<div>{MARKER}</div> Except EOS platforms with option X enabled.",
        )
    )
    with pytest.raises(ValueError):
        normalize(raw)


def test_article_whitespace_between_exclusion_marker_and_list_is_preserved_as_boundary():
    raw = source(lambda s: s.replace(f"<div>{MARKER}</div>", f"<div>{MARKER}</div> \n\t \n"))
    doc = normalize(raw)
    assert len(doc["assessments"]) == 15
    assert all(a["platforms"] == PLATFORMS for a in doc["assessments"])
