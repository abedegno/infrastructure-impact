"""Synthetic source mutations prove scope preservation and fail-closed repeats."""

import copy
import json

import pytest

from infrastructure_impact.adapters.standards import csaf
from infrastructure_impact.domain import NormalizationError, validate_advisory
from infrastructure_impact.plugins.arista import parse
from infrastructure_impact.storage.repository import connect, ingest

ROOT = "https://www.arista.com/en/support/advisories-notices/security-advisory/"
URLS = {
    "0138": ROOT + "24019-security-advisory-0138",
    "0139": ROOT + "24029-security-advisory-0139",
    "0140": ROOT + "24074-security-advisory-0140",
    "0141": ROOT + "24108-security-advisory-0141",
}
A, B = "CVE-2026-12345", "CVE-2026-54321"


def article(number, body):
    return f'<div class="item-page"><h2>Security Advisory {number}</h2><table><tr><td>1.0</td><td>May 8, 2026</td><td>Initial release</td></tr></table>{body}</div>'


def nested():
    return article(
        "0138",
        f"<p>The CVE-ID’s tracking this issue: {A}, {B}.</p><h3>Description</h3><p>Local code execution required.</p><h3>Vulnerability Assessment</h3><h4>Affected Software</h4><ul><li>VeloCloud Orchestrator (Formerly VeloCloud Orchestrator by Broadcom)<ul><li>Release 6.4.2.0 and below</li></ul></li><li>VeloCloud Gateway (Formerly VeloCloud Gateway by Broadcom)<ul><li>Release 6.4.2.0 (GA builds before BUILD-228)</li></ul></li></ul><h4>Affected Platforms</h4><div>The following platforms are undergoing triage:</div><ul><li>Other appliance</li></ul><h2>Resolution</h2><ul><li>Release 5.2.7.0 (next release)</li></ul>",
    )


def siblings(number="0139"):
    software = (
        "<h4>EOS Versions</h4><div>Only MCS on CVX is affected</div><ul><li>4.34.1F and below in 4.34.x</li></ul><h4>DMF Versions</h4><ul><li>8.8.0</li></ul>"
        if number == "0139"
        else "<h4>EOS Versions</h4><ul><li>4.35.1 and below in 4.35.x</li></ul>"
    )
    return article(
        number,
        f"<p>The CVE-ID tracking this issue: {A}</p><h2>Description</h2><p>DMF is not affected by default. Local administrator required for EOS.</p><h2>Vulnerability Assessment</h2><h3>Affected Software</h3>{software}<h3>Affected Platforms</h3><div>Only listed hardware is affected.</div><ul><li>MODEL-A</li></ul><div>These models are not affected:</div><ul><li>MODEL-B</li></ul><h3>Required Configuration for Exploitation</h3><p>Secure Boot must be supported and enabled.</p><pre>Secure boot: enabled</pre><h2>Resolution</h2><ul><li>4.35.2 and later in 4.35.x</li></ul>",
    )


def test_nested_products_keep_build_conditions_and_shared_scope():
    r = validate_advisory(parse(nested(), URLS["0138"], "arista"))
    assert len(r["assessments"]) == 4
    for c in r["assessments"]:
        assert (
            c["scope"] == "bulletin_shared" and c["status"] == "affected" and not c["remediations"]
        )
        assert "undergoing triage" in json.dumps(c["exposure"])
    gateway = [c for c in r["assessments"] if c["product"] == "VeloCloud Gateway"]
    assert all("GA builds before BUILD-228" in c["versions"][0]["expression"] for c in gateway)
    assert "next release" in json.dumps(r["notes"]) and all(
        c["product"] != "Other appliance" for c in r["assessments"]
    )


@pytest.mark.parametrize("number,count", [("0139", 2), ("0140", 1)])
def test_sibling_headings_preserve_default_exclusions_and_prerequisites(number, count):
    r = validate_advisory(parse(siblings(number), URLS[number], "arista"))
    assert len(r["assessments"]) == count
    for c in r["assessments"]:
        text = json.dumps(c["exposure"])
        for required in (
            "not affected by default",
            "Local administrator",
            "not affected:",
            "MODEL-B",
            "Secure Boot must be supported and enabled",
            "Secure boot: enabled",
        ):
            assert required in text
        assert all(
            "MODEL" not in v["expression"] and "4.35.2" not in v["expression"]
            for v in c["versions"]
        )
    if number == "0139":
        assert (
            r["assessments"][0]["product"]
            == "Media Control Service (MCS) on CloudVision eXchange (CVX)"
        )
        assert "Only MCS" in json.dumps(r["assessments"][0]["exposure"])


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_product",
        "negative_range",
        "repeat_product",
        "missing_header",
        "nested_range",
        "missing_context",
    ],
)
def test_changed_product_or_scope_requires_review(mutation):
    raw = siblings()
    if mutation == "unknown_product":
        raw = raw.replace("DMF Versions", "Unknown Versions")
    if mutation == "negative_range":
        raw = raw.replace("8.8.0", "8.8.0 not impacted")
    if mutation == "repeat_product":
        raw = raw.replace("DMF Versions", "EOS Versions")
    if mutation == "missing_header":
        raw = raw.replace("tracking this issue:", "unbound reference:")
    if mutation == "nested_range":
        raw = raw.replace(
            "<li>8.8.0</li>", "<li>8.8.0<ul><li>except a configuration</li></ul></li>"
        )
    if mutation == "missing_context":
        raw = raw.replace("<h3>Affected Platforms</h3>", "<h3>Unreviewed Platforms</h3>")
    with pytest.raises(ValueError):
        parse(raw, URLS["0139"], "arista")


def test_airsnitch_is_retained_without_cve_claims_or_blanket_unaffectedness(monkeypatch):
    raw = article(
        "0141",
        "<p>BUG 1787021</p><h3>Description</h3><p>AirSnitch risk.</p><h4>Affected Software</h4><ul><li>None</li></ul><p>Note: this is an architectural configuration dependency rather than an issue with the product itself.</p><h4>Affected Platforms</h4><p>APs require recommended configuration.</p><h4>Required Configuration for Exploitation</h4><p>Guest SSID access required.</p><h3>Mitigation</h3><p>Security configuration. Potential service disruption.</p>",
    )
    raw = raw.replace("<h2>Security", '<a href="/assets/reviewed-CSAF.json">CSAF</a><h2>Security')
    from infrastructure_impact.collection import service

    envelope = json.dumps(
        {"document": {"tracking": {"id": "Draft notice"}}, "product_tree": {}}
    ).encode()
    monkeypatch.setattr(
        service,
        "fetch",
        lambda db, url, vendor: envelope if url.endswith(".json") else raw.encode(),
    )
    with connect(":memory:") as db:
        resolved, body = service.resolve_document(db, URLS["0141"], "arista")
        assert resolved == URLS["0141"] and body == raw.encode()
        ingest(db, body, resolved, parse, "arista")
        r = validate_advisory(parse(raw, URLS["0141"], "arista"))
        assert not r["cves"] and not r["assessments"]
        assert "Guest SSID" in json.dumps(r["notes"]) and "service disruption" in json.dumps(
            r["notes"]
        )
    with pytest.raises(ValueError):
        parse(raw.replace("AirSnitch risk", A + " AirSnitch risk"), URLS["0141"], "arista")


def source():
    return {
        "document": {"title": "Synthetic bulletin", "tracking": {"id": "TEST", "status": "final"}},
        "product_tree": {
            "full_product_names": [{"product_id": "router-all", "name": "Example Router All"}]
        },
        "vulnerabilities": [
            {
                "cve": A,
                "product_status": {"known_not_affected": ["router-all"]},
                "notes": [{"category": "description", "text": "Required conditions absent"}],
                "threats": [
                    {"category": "impact", "description": "No exploitable product scenario"}
                ],
            }
        ],
    }


def test_identical_csaf_entries_normalize_once_with_repeat_receipt():
    d = source()
    d["vulnerabilities"].append(copy.deepcopy(d["vulnerabilities"][0]))
    r = validate_advisory(csaf(json.dumps(d), "https://example.test/csaf", "paloalto"))
    assert len(r["assessments"]) == 1 and r["assessments"][0]["status"] == "unaffected"
    assert "Required conditions absent" in json.dumps(
        r["notes"]
    ) and "No exploitable" in json.dumps(r["assessments"][0]["exposure"])
    assert "vulnerabilities[1] equals vulnerabilities[0]" in r["warnings"][0]


@pytest.mark.parametrize("change", ["status", "rationale", "range"])
def test_nonidentical_csaf_repeats_cannot_silently_overwrite_scope(change):
    d = source()
    v = copy.deepcopy(d["vulnerabilities"][0])
    d["vulnerabilities"].append(v)
    if change == "status":
        v["product_status"] = {"known_affected": ["router-all"]}
    if change == "rationale":
        v["notes"][0]["text"] = "Different platform restriction"
    if change == "range":
        v["remediations"] = [
            {"category": "vendor_fix", "details": "Only version 2", "product_ids": ["router-all"]}
        ]
    with pytest.raises(NormalizationError, match="Duplicate CVE/product"):
        validate_advisory(csaf(json.dumps(d), "https://example.test/csaf", "paloalto"))


@pytest.mark.parametrize("number", ["0139", "0140"])
def test_missing_configuration_section_cannot_drop_exploitation_prerequisites(number):
    raw = siblings(number).replace(
        "Required Configuration for Exploitation", "Unreviewed prerequisites"
    )
    with pytest.raises(ValueError, match="prerequisites missing"):
        parse(raw, URLS[number], "arista")


def test_cna_release_branches_preserve_ranges_cpes_and_source_indices():
    from infrastructure_impact.adapters.standards import cna

    rows = [
        dict(
            product="Example App",
            platforms=["Linux"],
            defaultStatus="unaffected",
            cpes=["cpe-a"],
            versions=[
                dict(
                    version="6.3",
                    lessThan="6.3.9",
                    status="affected",
                    changes=[dict(at="6.3.9", status="unaffected")],
                )
            ],
        ),
        dict(
            product="Example App",
            platforms=["Linux"],
            defaultStatus="unaffected",
            cpes=["cpe-b"],
            versions=[dict(version="6.0", lessThan="6.0.4", status="affected")],
        ),
    ]
    document = dict(
        cveMetadata=dict(cveId=A),
        containers=dict(cna=dict(title="Synthetic branch advisory", affected=rows)),
    )
    result = validate_advisory(cna(json.dumps(document), "https://example.test/cve", "paloalto"))
    assert len(result["assessments"]) == 1
    claim = result["assessments"][0]
    assert [v["version"] for v in claim["versions"]] == ["6.3", "6.0"]
    assert claim["versions"][0]["changes"] == rows[0]["versions"][0]["changes"]
    assert claim["identifiers"]["cpe"] == ["cpe-a", "cpe-b"]
    assert "indices=[0, 1]" in claim["evidence_locator"]
    assert "overlap" in result["warnings"][-1]


@pytest.mark.parametrize("change", ["status", "range_start", "default_status", "condition"])
def test_cna_branch_merge_refuses_conflicting_status_or_scope(change):
    from infrastructure_impact.adapters.standards import cna_product_rows

    a = dict(
        product="Router",
        platforms=["Linux"],
        defaultStatus="unaffected",
        versions=[dict(version="1.0", lessThan="1.4", status="affected")],
    )
    b = copy.deepcopy(a)
    b["versions"][0]["version"] = "2.0"
    if change == "status":
        b["versions"][0]["status"] = "unaffected"
    if change == "range_start":
        b["versions"][0].update(version="1.0", lessThan="1.5")
    if change == "default_status":
        b["defaultStatus"] = "affected"
    if change == "condition":
        b["modules"] = ["optional feature"]
    with pytest.raises(ValueError, match="Conflicting repeated CNA"):
        list(cna_product_rows([a, b], []))


def test_republished_arista_notice_does_not_use_resolution_cve_as_tracking_identity():
    raw = article(
        "0131",
        f"<p>NOTICE: Reposted older VMware advisory.</p><p>The CVE-ID tracking this issue: {A}</p><h3>Description</h3><p>Tenant access required.</p><h4>Affected Software</h4><p>VeloCloud Orchestrator</p><div>Versions</div><ul><li>3.x</li></ul><h3>Affected Platforms</h3><p>Orchestrator only; other platforms excluded.</p><h2>Resolution</h2><p>{B} fixed in another version</p>",
    )
    r = validate_advisory(parse(raw, ROOT + "23119-security-advisory-0131", "arista"))
    assert r["cves"] == [A] and len(r["assessments"]) == 1
    assert r["assessments"][0]["product"] == "VeloCloud Orchestrator"
    assert all(not c["remediations"] for c in r["assessments"])
    assert "repost" in " ".join(r["warnings"]).lower()
    assert "inconsistent section" in " ".join(r["warnings"])


def test_runc_scopes_do_not_broaden_to_standard_eos_images():
    raw = article(
        "0135",
        f"<p>The CVE-ID tracking this issue: {A}</p><p>The CVE-ID tracking this issue: {B}</p><h2>Description</h2><p>Core EOS does not ship this component.</p><h3>Affected Software</h3><h4>cEOS Version</h4><ul><li>4.35.2F and below</li></ul><div>Docker SWIX Extension Versions associated with the below EOS versions (Available in the Arista Download portal under Extensions section)</div><ul><li>4.35.2F and below</li></ul><h4>Arista 7130 Systems running MOS</h4><ul><li>MOS-0.39.12 and below</li></ul><h3>Affected Platforms</h3><p>Other EOS platforms unaffected by default, only affected with Docker SWIX installed.</p><h3>Required Configuration for Exploitation</h3><p>Container execution required.</p>",
    )
    r = validate_advisory(parse(raw, ROOT + "23784-security-advisory-0135", "arista"))
    assert len(r["assessments"]) == 6
    assert {c["product"] for c in r["assessments"]} == {
        "Arista cEOS-lab",
        "Arista Docker SWIX extension",
        "Arista 7130 Systems running MOS",
    }
    assert all(
        c["scope"] == "bulletin_shared" and "unaffected by default" in json.dumps(c["exposure"])
        for c in r["assessments"]
    )


def test_fortinet_ranges_keep_negation_lower_bound_markers_and_conditional_solution():
    from infrastructure_impact.plugins.fortinet import parse as fortinet

    raw = f'<h1>Synthetic issue</h1><table><tr><td>IR Number</td><td>FG-IR-23-494</td></tr><tr><td>CVE ID</td><td>{A}</td></tr><tr><td>Published Date</td><td>Jan 14, 2025</td></tr></table><div class="detail-item"><h2>Summary</h2>Conditional interface issue</div><div class="detail-item"><h2>Affected Products</h2>At least<br>FortiSwitch 7.4 all versions are not affected<br>FortiSwitch version 7.0.0 through 7.0.4<br>FortiSOAR on-premise 7.2 all versions</div><div class="detail-item"><h2>Solutions</h2>Upgrade AND configure the hostname</div>'
    r = validate_advisory(
        fortinet(raw, "https://www.fortiguard.com/psirt/FG-IR-23-494", "fortinet")
    )
    assert len(r["assessments"]) == 3
    assert {c["status"] for c in r["assessments"]} == {"affected", "unaffected"}
    assert any(c["product"] == "FortiSOAR on-premise" for c in r["assessments"])
    assert all(
        not c["remediations"]
        and "At least" in json.dumps(c["exposure"])
        and "AND configure" in json.dumps(c["exposure"])
        for c in r["assessments"]
    )
    with pytest.raises(ValueError, match="Unreviewed Fortinet product/version"):
        fortinet(
            raw.replace("7.4 all versions are not affected", "7.4 except some configurations"),
            "https://www.fortiguard.com/psirt/FG-IR-23-494",
            "fortinet",
        )


def test_coverage_matrix_distinguishes_dates_backlog_formats_and_configured_sources():
    from infrastructure_impact.application.vendor_gaps import coverage_matrix_row

    records = [
        dict(published_at="2020-01-01", source_format="CSAF"),
        dict(published_at=None, source_format="HTML"),
    ]
    profile = dict(
        history_scope="Bounded listing",
        sources=[dict(url="https://example.test/feed", role="vendors", kind="rss", limit=4)],
        capabilities=["html"],
    )
    counts = dict(done=2, pending=3, error=1, not_applicable=0)
    archive = dict(
        source_url="https://example.test/archive",
        kind="listing",
        page_limit=2,
        document_limit=8,
        pages=counts,
        documents=counts,
        known_queue_exhausted=False,
        publisher_date_range=dict(earliest="2020-01-01", latest="2020-01-01"),
        PRIVATE_SENTINEL="secret",
    )
    row = coverage_matrix_row(
        profile,
        dict(archives=[archive]),
        records,
        [
            dict(error_code="unsupported_or_invalid_document"),
            dict(error_code="access_verification_required"),
        ],
    )
    assert (
        row["publisher_date_range"]["earliest"] == "2020-01-01"
        and row["documents_without_publisher_date"] == 1
    )
    assert row["configured_sources"][0]["per_pass_limit"] == 4
    assert (
        row["archives"][0]["documents"]["pending"] == 3
        and not row["archives"][0]["known_queue_exhausted"]
    )
    assert row["unsupported_sources"] == row["access_blocked_sources"] == 1
    assert row["observed_formats"] == [
        dict(format="CSAF", advisories=1),
        dict(format="HTML", advisories=1),
    ]
    assert "PRIVATE_SENTINEL" not in json.dumps(row)


def test_copy_fail_agni_scope_stays_bound_to_the_named_physical_appliance():
    raw = article(
        "0136",
        f"<p>The CVE-ID tracking this issue: {A}</p><h3>Description</h3><p>Local code execution required.</p><h4>Affected Software</h4><div>CloudVision Portal</div><ul><li>2026.1.0</li></ul><div>VeloCloud Orchestrator (Formerly VeloCloud Orchestrator by Broadcom)</div><ul><li>Release 6.4.x</li></ul><div>VeloCloud Gateway (Formerly VeloCloud Gateway by Broadcom)</div><ul><li>Release 6.2.0</li></ul><div>VeloCloud Edge (Formerly VeloCloud Edge by Broadcom)</div><ul><li>Release 6.4.0 and 6.4.1</li></ul><div>CloudVision AGNI - Virtual or physical appliance</div><ul><li>AGNI Physical Appliance DCA-AGNI-100<ul><li>Release P-2025.2.X</li></ul></li></ul><div>Netvisor Software</div><ul><li>7.1.0HF7 and below</li></ul><h4>Affected Platforms</h4><p>Only listed appliances.</p><h3>Required Configuration for Exploitation</h3><p>Shell access required.</p>",
    )
    r = validate_advisory(parse(raw, ROOT + "24004-security-advisory-0136", "arista"))
    assert len(r["assessments"]) == 6
    agni = next(c for c in r["assessments"] if "AGNI" in c["product"])
    assert agni["product"] == "CloudVision AGNI physical appliance DCA-AGNI-100"
    assert "Physical Appliance DCA-AGNI-100 Release P-2025.2.X" in agni["versions"][0]["expression"]
    with pytest.raises(ValueError, match="physical appliance qualifier"):
        parse(
            raw.replace("AGNI Physical Appliance DCA-AGNI-100", "AGNI Virtual Appliance"),
            ROOT + "24004-security-advisory-0136",
            "arista",
        )


def test_ngfw_shared_software_list_uses_only_the_six_description_cves():
    ids = ["CVE-2026-" + str(30000 + i) for i in range(6)]
    descriptions = "".join(f"<p>Description {i}; CVE: {cid}</p>" for i, cid in enumerate(ids))
    raw = article(
        "0133",
        f"<h3>Description</h3>{descriptions}<h3>Affected Software</h3><h4>Arista Edge Threat Management - Arista Next Generation Firewall (NGFW) Versions</h4><ul><li>17.4.0 and prior</li></ul><h3>Affected Platforms</h3><p>NGFW only.</p><h3>Required Configuration for Exploitation, Indicators of Compromise and Mitigation Options</h3><h4>{ids[0]}</h4><p>Administrator logged into UI required.</p><h3>Resolution</h3><p>{A} unrelated reference</p>",
    )
    r = validate_advisory(parse(raw, ROOT + "23399-security-advisory-0133", "arista"))
    assert r["cves"] == ids and len(r["assessments"]) == 6
    assert all(
        c["scope"] == "bulletin_shared" and "Administrator logged" in json.dumps(c["exposure"])
        for c in r["assessments"]
    )
    with pytest.raises(ValueError, match="per-CVE descriptions"):
        parse(
            raw.replace("CVE: " + ids[0], "Reference missing"),
            ROOT + "23399-security-advisory-0133",
            "arista",
        )


def test_coverage_matrix_retains_unclassified_legacy_errors():
    from infrastructure_impact.application.vendor_gaps import coverage_matrix_row

    row = coverage_matrix_row(
        {}, {}, [], [dict(error_code=None), dict(error_code="transport_timeout")]
    )
    assert (
        row["other_error_sources"] == 2
        and row["unsupported_sources"] == row["access_blocked_sources"] == 0
    )
