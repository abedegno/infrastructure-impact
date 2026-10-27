"""Synthetic single-CVE range lists preserve scope and unresolved fix discrepancies."""

import json
from copy import deepcopy
from unittest.mock import patch

import pytest

from infrastructure_impact.adapters.common import HTML
from infrastructure_impact.adapters.fortinet_ranges import (
    ROUTES,
    range_advisory,
    section_sha256,
    sections,
)
from infrastructure_impact.collection.errors import PublisherScopeUnavailable, failure_code
from infrastructure_impact.plugins.fortinet import resolve
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.storage.repository import connect, ingest, latest


def synthetic(identity="FG-IR-23-165"):
    spec = ROUTES[identity]
    products = sorted(spec["products"])
    lines = [product + " version 7.0.1 through 7.0.4" for product in products]
    lines += [product + " 7.6 all versions are not affected" for product in products]
    raw = f"""<h1>Synthetic range-list advisory</h1>
    <div class="detail-item"><h2>Summary</h2><p>Synthetic authentication and service condition.</p></div>
    <div class="detail-item"><h2>Affected Products</h2><p>{"<br>".join(lines)}</p></div>
    <div class="detail-item"><h2>Solutions</h2><p>Synthetic upgrade suggestions and a separate FortiSASE mention.</p><h2>Workaround:</h2><p>Synthetic configuration workaround. <a href="https://docs.fortinet.com/example">Source</a></p></div>
    <div class="detail-item"><h2>Virtual Patch</h2><p>Synthetic signature, not an appliance fix.</p></div>
    <div class="detail-item"><h2>Virtual Patch</h2><p>Yes</p></div>
    <table><tr><td>IR Number</td><td>{identity}</td></tr>
    <tr><td>CVE ID</td><td>{spec["cve"]}</td></tr>
    <tr><td>Published Date</td><td>Feb 11, 2025</td></tr>
    <tr><td>Updated Date</td><td>Feb 12, 2025</td></tr>
    <tr><td>Component</td><td>{spec["component"]}</td></tr>
    <tr><td>Attack Type</td><td>Authenticated</td></tr></table>""".encode()
    return raw


def reviewed(raw, identity="FG-IR-23-165"):
    specs = deepcopy(ROUTES)
    specs[identity]["sections"] = {
        name: section_sha256(node) for name, node in sections(HTML(raw).root).items()
    }
    return patch("infrastructure_impact.adapters.fortinet_ranges.ROUTES", specs)


@pytest.mark.parametrize("identity", list(ROUTES))
def test_literal_ranges_keep_affected_unaffected_and_authentication_scopes_separate(identity):
    raw = synthetic(identity)
    url = "https://www.fortiguard.com/psirt/" + identity
    with reviewed(raw, identity):
        doc = default_registry().normalize(raw, url, "fortinet")
    assert doc["cves"] == [ROUTES[identity]["cve"]]
    assert {a["product"] for a in doc["assessments"]} == ROUTES[identity]["products"]
    assert "FortiSASE" not in {a["product"] for a in doc["assessments"]}
    assert all(a["scope"] == "cve_specific" for a in doc["assessments"])
    for product in ROUTES[identity]["products"]:
        claims = [a for a in doc["assessments"] if a["product"] == product]
        assert {a["status"] for a in claims} == {"affected", "unaffected"}
        assert len({a["product_id"] for a in claims}) == 2
    assert all(a["remediations"] == [] for a in doc["assessments"])
    assert all(a["status"] != "fixed" for a in doc["assessments"])
    assert all(a["exposure"][0]["category"] == "publisher_prerequisite" for a in doc["assessments"])
    disputed = [
        a
        for a in doc["assessments"]
        if any(e["category"] == "publisher_solution_discrepancy" for e in a["exposure"])
    ]
    assert len(disputed) == (1 if identity == "FG-IR-23-165" else 0)
    if disputed:
        assert disputed[0]["product"] == "FortiOS" and disputed[0]["status"] == "affected"


@pytest.mark.parametrize(
    "before,after",
    [
        (b"through 7.0.4", b"through 7.0.5"),
        (b"Synthetic authentication", b"Changed authentication"),
        (b"configuration workaround", b"different workaround"),
        (b"https://docs.fortinet.com/example", b"https://docs.fortinet.com/other"),
        (b"Synthetic range-list advisory", b"Changed article title"),
    ],
)
def test_changed_article_scope_or_link_target_fails_for_review(before, after):
    raw = synthetic()
    with reviewed(raw):
        with pytest.raises(ValueError, match="scope changed"):
            range_advisory(
                raw.replace(before, after),
                "https://www.fortiguard.com/psirt/FG-IR-23-165",
                "fortinet",
            )


def test_navigation_changes_do_not_change_the_reviewed_article_scope():
    raw = synthetic()
    with reviewed(raw):
        before = range_advisory(raw, "https://www.fortiguard.com/psirt/FG-IR-23-165", "fortinet")
        after = range_advisory(
            b"<nav>Changed navigation CVE-2099-99999</nav>" + raw,
            "https://www.fortiguard.com/psirt/FG-IR-23-165",
            "fortinet",
        )
    assert before == after and "CVE-2099-99999" not in before["cves"]


@pytest.mark.parametrize(
    "before,after",
    [
        (b"<td>CVE-2023-37930</td>", b"<td>CVE-2023-40721</td>"),
        (b"<td>Authenticated</td>", b"<td>Remote</td>"),
        (b"<td>SSL-VPN</td>", b"<td>CLI</td>"),
        (b"<td>FG-IR-23-165</td>", b"<td>FG-IR-23-261</td>"),
    ],
)
def test_metadata_cannot_broaden_scope_even_when_article_sections_match(before, after):
    raw = synthetic()
    with reviewed(raw):
        with pytest.raises(ValueError, match="scope"):
            range_advisory(
                raw.replace(before, after),
                "https://www.fortiguard.com/psirt/FG-IR-23-165",
                "fortinet",
            )


def stub(identity="FG-IR-23-165", cve=None):
    value = dict(
        document=dict(
            title="Synthetic publisher envelope", tracking=dict(id=identity, status="final")
        )
    )
    if cve:
        value["vulnerabilities"] = [dict(cve=cve)]
    return json.dumps(value).encode()


def test_only_empty_structured_envelopes_can_resolve_to_reviewed_html():
    raw = synthetic()
    expected = "https://www.fortiguard.com/psirt/FG-IR-23-165"
    calls = []

    def fetch(url):
        calls.append(url)
        return raw

    with reviewed(raw):
        assert resolve(stub(), "https://filestore.fortinet.com/source.json", fetch) == (
            expected,
            raw,
        )
    assert calls == [expected]
    calls.clear()
    structured = stub(cve="CVE-2023-37930")
    assert resolve(structured, "https://filestore.fortinet.com/source.json", fetch) == (
        "https://filestore.fortinet.com/source.json",
        structured,
    )
    assert calls == []
    with reviewed(raw):
        changed = raw.replace(b"through 7.0.4", b"through 7.0.5")
        original = stub()
        assert resolve(
            original, "https://filestore.fortinet.com/source.json", lambda _: changed
        ) == ("https://filestore.fortinet.com/source.json", original)


def test_cve_free_publisher_envelope_remains_a_visible_gap_and_creates_no_advisory():
    raw = stub("FG-IR-26-187")
    with connect(":memory:") as db:
        with pytest.raises(PublisherScopeUnavailable) as error:
            ingest(
                db,
                raw,
                "https://filestore.fortinet.com/synthetic.json",
                default_registry().normalize,
                "fortinet",
            )
        assert failure_code(error.value) == "publisher_scope_unavailable"
        assert latest(db) == []


@pytest.mark.parametrize(
    "url,vendor",
    [
        ("https://www.fortiguard.com/psirt/FG-IR-23-165?other=scope", "fortinet"),
        ("https://www.fortiguard.com/psirt/FG-IR-23-165#other", "fortinet"),
        ("https://attacker.example/psirt/FG-IR-23-165", "fortinet"),
        ("https://www.fortiguard.com/psirt/FG-IR-23-165", "cisco"),
    ],
)
def test_unreviewed_route_and_vendor_are_rejected(url, vendor):
    with pytest.raises(ValueError):
        range_advisory(synthetic(), url, vendor)
