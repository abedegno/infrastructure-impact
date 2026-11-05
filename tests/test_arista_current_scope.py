"""Synthetic current applicability groups; publisher captures stay private."""

import json

import pytest

from infrastructure_impact.adapters import cvss
from infrastructure_impact.plugins.registry import default_registry

PREFIX = "https://www.arista.com/en/support/advisories-notices/security-advisory/"
URLS = {
    "0202": PREFIX + "24853-security-advisory-0202",
    "0203": PREFIX + "25023-security-advisory-0203",
}
PRODUCTS = {
    "0202": "VeloCloud Orchestrator",
    "0203": "Arista Network Detection and Response (NDR) Security Platform",
}
IDS = {"0202": "CVE-2026-111497", "0203": "CVE-2026-98432"}
UNAFFECTED = {
    "0202": "The following product versions and platforms are not affected by this vulnerability:",
    "0203": "The following product versions and platforms are not affected by this vulnerability. Please note, at this point this is an assessment of required configuration for exploitation, ie MPTCP being enabled, not of the vulnerable ipv4 code being present. Products with vulnerable ipv4 code will have fixed releases over time:",
}
TRIAGE = {
    "0202": "The following product versions and platforms are undergoing triage to determine if they are affected by this vulnerability:",
    "0203": "The following product versions and platforms are under triage to determine if they are by this vulnerability:",
}


def source(number="0203", edit=lambda s: s):
    product = PRODUCTS[number]
    platform = product + (
        " (Formerly VeloCloud Orchestrator by Broadcom)"
        if number == "0202"
        else " (Formerly Awake NDR)"
    )
    software = (
        "<div><b>VeloCloud Orchestrator</b></div><ul><li>1.2.3.4 and below releases in the 1.2.3 train</li><li>2.3.4.5 and below releases in the 2.3.4 train</li></ul>"
        if number == "0202"
        else f"<p>As of the publication of this advisory that means that MPTCP must be enabled at the kernel level.</p><h4>{product}</h4><ul><li>All versions prior to and including 7.8.9</li></ul>"
    )
    config = (
        "Synthetic outbound HTTP client that supports automatic decompression and Brotli-compressed response context."
        if number == "0202"
        else "Configuration changes that disable MPTCP on NDR appliances are not user-operable. Synthetic offline assistance context."
    )
    resolution = (
        "<div>The issue is fixed in the following product releases:</div><div><b>VeloCloud Orchestrator</b></div><ul><li>1.2.3.5 and later releases in the 1.2.3 train</li></ul>"
        if number == "0202"
        else "<p>This section will be updated once fixed releases are available for the underlying kernel issue or to disable MPTCP.</p>"
    )
    html = f"""<div class="item-page"><div class="page-header"><h2>Security Advisory {number} <a>PDF</a></h2></div>
    <p>Date: November 2, 2026</p><table><tr><th>Revision</th><th>Date</th><th>Changes</th></tr><tr><td>1.0</td><td>November 2, 2026</td><td>Synthetic publication</td></tr><tr><td>1.1</td><td>November 3, 2026</td><td>Synthetic revision</td></tr></table>
    <p>The CVE-ID tracking this issue: {IDS[number]}<br>CVSSv3.1 Base Score: 9.8</p>
    <h2>Description</h2><p>Synthetic description. MPTCP prerequisite; underlying issue and defense in depth are separate. Another prose reference CVE-2099-12345.</p>
    <h2>Vulnerability Assessment</h2><h3>Platform and Software Applicability Note</h3><p>Synthetic applicability context.</p>
    <h3>Affected Software</h3>{software}<h3>Affected Platforms</h3>
    <div>The following products <b>are</b> affected by this vulnerability:</div><ul><li>{platform}</li></ul>
    <div>{UNAFFECTED[number]}</div><div class="clear10"></div><ul><li>Arista EOS-based products:</li><ul><li>7050X3</li><li>720XP/722XPM</li><li>750X</li><li>7500R</li><li>Synthetic unknown model</li></ul><li>Synthetic independent product</li></ul>
    <div>{TRIAGE[number]}</div><ul><li>Synthetic triage product</li></ul>
    <h3>Required Configuration for Exploitation</h3><h4>{product}</h4><p>{config}</p>
    <h2>Mitigation</h2><h4>{product}</h4><p>Synthetic mitigation only; no availability established.</p>
    <h2>Resolution</h2>{resolution}<h4>For More Information:</h4><p>PRIVATE_RAW_SENTINEL CVE-2099-99999</p></div>"""
    return edit(html).encode()


def normalize(number="0203", edit=lambda s: s):
    return default_registry().normalize(source(number, edit), URLS[number], "arista")


@pytest.mark.parametrize("number", ["0202", "0203"])
def test_current_lists_keep_local_status_versions_and_configuration(number):
    doc = normalize(number)
    assert doc["source_format"] == "Arista reviewed current applicability HTML"
    assert doc["cves"] == [IDS[number]]
    assert (doc["published_at"], doc["updated_at"]) == ("2026-11-02", "2026-11-03")
    affected, eos, other, triage = doc["assessments"]
    assert affected["product"] == PRODUCTS[number] and affected["status"] == "affected"
    assert affected["versions"] == (
        [
            {"expression": "1.2.3.4 and below releases in the 1.2.3 train"},
            {"expression": "2.3.4.5 and below releases in the 2.3.4 train"},
        ]
        if number == "0202"
        else [{"expression": "All versions prior to and including 7.8.9"}]
    )
    assert eos["product"] == "Arista EOS" and eos["status"] == "unaffected"
    assert eos["platforms"] == [
        "7050X3",
        "720XP/722XPM",
        "750X",
        "7500R",
        "Synthetic unknown model",
    ]
    assert other["product"] == "Synthetic independent product" and other["status"] == "unaffected"
    assert triage["product"] == "Synthetic triage product" and triage["status"] == "investigating"
    assert all(not a["versions"] and not a["remediations"] for a in [eos, other, triage])
    if number == "0203":
        assert "MPTCP being enabled" in json.dumps(eos["exposure"])
        assert not affected["remediations"]
        assert "fixed releases are available" in json.dumps(doc["notes"])
    else:
        assert "automatic decompression" in json.dumps(affected["exposure"])
        assert "automatic decompression" not in json.dumps(eos["exposure"])
        assert affected["remediations"][0]["availability"] == "vendor_reports_fixed"
    assert not default_registry().get("arista").non_cve_notice(doc)
    assert "PRIVATE_RAW_SENTINEL" not in json.dumps(doc)


@pytest.mark.parametrize(
    "old,new",
    [
        ("<li>7050X3</li>", "<li>7050X3<ul><li>Hidden exception</li></ul></li>"),
        ("<li>7050X3</li>", "<li><script>hidden</script>7050X3</li>"),
        ("<li>7050X3</li>", "<li><span hidden>7050X3</span></li>"),
        ("<li>7050X3</li>", "<li>7050X3"),
        ("Arista EOS-based products:", "Unknown family:"),
        ("<li>Synthetic triage product</li>", ""),
        ("are under triage", "are affected"),
        ("<li>All versions prior to and including 7.8.9</li>", "<li>Other product 1.2.3</li>"),
        (
            "<h4>Arista Network Detection and Response (NDR) Security Platform</h4>",
            "<h4>Unknown software</h4>",
        ),
        ("MPTCP", "OTHER"),
        (
            "The CVE-ID tracking this issue: CVE-2026-98432",
            "The CVE-ID tracking this issue: CVE-2026-98432 CVE-2099-22222",
        ),
        ("<h3>Affected Platforms</h3>", "<h3>Changed applicability</h3>"),
    ],
)
def test_changed_or_ambiguous_scope_fails_visibly(old, new):
    with pytest.raises(ValueError):
        normalize(edit=lambda s: s.replace(old, new))


def test_removed_platform_is_unknown_instead_of_blanket_unaffected():
    raw = source(edit=lambda s: s.replace("<li>7050X3</li>", ""))
    doc = default_registry().normalize(raw, URLS["0203"], "arista")
    evidence = default_registry().research_evidence(raw, URLS["0203"], "arista", doc)
    eos = next(c for c in evidence["claims"] if c["family"] == "arista-eos")
    assert "7050X3" not in eos["named_platforms"]
    assert eos["named_platforms"] and eos["status"] == "unaffected"


def test_current_bridge_preserves_literals_and_source_wide_score_diagnostics():
    raw, url = source(), URLS["0203"]
    doc = normalize()
    result = default_registry().research_evidence(raw, url, "arista", doc)
    assert result["issues"] == result["bundles"] == []
    eos = next(c for c in result["claims"] if c["family"] == "arista-eos")
    assert eos["product_id"] is None
    assert eos["named_platforms"] == [
        "7050X3",
        "720XP/722XPM",
        "750X",
        "7500R",
        "Synthetic unknown model",
    ]
    assert eos["publisher"]["sequence"] == "1.1"
    assert all(c["source"]["source_url"] == url for c in result["claims"])
    assert all(not c["remediations"] for c in result["claims"])
    metrics = cvss.extract(raw, url, "arista", doc)
    assert not metrics["claims"]
    assert {i["code"] for i in metrics["issues"]} == {"score_format_unsupported"}


@pytest.mark.parametrize(
    "old,new",
    [
        ("<li>7050X3</li>", "<li hidden>7050X3</li>"),
        ("<li>7050X3</li>", "<li>7050X3</li> except some deployments"),
        ("<li>7050X3</li>", '<li style="display:none">7050X3</li>'),
    ],
)
def test_hidden_or_unbound_platform_qualifications_require_review(old, new):
    with pytest.raises(ValueError):
        normalize(edit=lambda s: s.replace(old, new))


def test_strict_public_projection_and_json_csv_selection_keep_exclusions(tmp_path):
    import csv
    from io import StringIO

    from infrastructure_impact.application import switching_comparison as comparison
    from infrastructure_impact.application import switching_evidence as evidence
    from infrastructure_impact.application.publication import public_projection
    from infrastructure_impact.application.query import state
    from infrastructure_impact.exports import switching_csv
    from infrastructure_impact.storage.repository import connect, ingest

    with connect(tmp_path / "synthetic.sqlite") as db:
        ingest(db, source(), URLS["0203"], default_registry().normalize, "arista")
        private = state(db)
        private["research"]["switching_input"]["private_path"] = "PRIVATE_FIELD_SENTINEL"
        public = public_projection(private)
    assert "PRIVATE_RAW_SENTINEL" not in json.dumps(public)
    assert "PRIVATE_FIELD_SENTINEL" not in json.dumps(public)
    evidence.validate_evidence(public["switching_evidence"])
    selected = comparison.select_report(
        public["switching_comparison"], vendor="arista", cve_ids=["CVE-2026-98432"]
    )
    evidence.validate_comparison(selected)
    assert selected["rows"][0]["counts"]["cves"] == 1
    assert selected["rows"][0]["counts"]["affected_cves"] == 0
    assert selected["rows"][0]["counts"]["remediation_events"] == 0
    assert selected["rows"][0]["counts"]["planned_fix_claims"] == 0
    csv_rows = list(csv.DictReader(StringIO(switching_csv(selected))))
    assert {r["vendor"] for r in csv_rows} == {"arista"}
    assert {r["affected_cves"] for r in csv_rows} == {"0"}
    assert {r["remediation_events"] for r in csv_rows} == {"0"}
    model = comparison.select_report(
        public["switching_comparison"], vendor="arista", scope_level="model_qualified"
    )
    assert model["rows"][0]["counts"]["cves"] == 0
    eos = next(c for c in public["switching_evidence"]["claims"] if c["family"] == "arista-eos")
    assert {b["platform"]: b["model"] for b in eos["platform_bindings"]} == {
        "7050X3": None,
        "720XP/722XPM": None,
        "750X": None,
        "7500R": None,
        "Synthetic unknown model": None,
    }


@pytest.mark.parametrize("encoding", ["utf-8", None])
def test_current_html_routes_preserve_existing_json_dispatch(encoding):
    from pathlib import Path

    text = Path("tests/fixtures/arista120.json").read_text()
    raw = text.encode(encoding) if encoding else text
    doc = default_registry().normalize(raw, URLS["0203"], "arista")
    assert doc["source_format"] != "Arista reviewed current applicability HTML"
    assert doc["cves"]
