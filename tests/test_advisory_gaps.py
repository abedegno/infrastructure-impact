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
