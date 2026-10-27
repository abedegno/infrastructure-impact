"""Synthetic regreSSHion sources preserve explicit lists and disjoint ranges."""

import json
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest

from infrastructure_impact.adapters.fortinet_openssh import CVE, ID, TITLE, openssh_advisory
from infrastructure_impact.application.publication import public_projection
from infrastructure_impact.application.query import state
from infrastructure_impact.collection.service import run
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.storage.repository import connect, health, latest
from infrastructure_impact.storage.source_selections import latest as choices

URL = "https://www.fortiguard.com/psirt/" + ID
MIRROR = "https://fortiguard.fortinet.com/psirt/" + ID
ALT = (
    "https://www.fortiguard.com/psirt/csaf/"
    + ID
    + "?csaf_url=https://filestore.fortinet.com/synthetic.json"
)
ROWS = [
    ["FortiManager Cloud 7.2", "7.2.3 through 7.2.4", "Upgrade to 7.2.7 or above"],
    ["FortiManager Cloud 7.2", "7.2.1", "Upgrade to 7.2.7 or above"],
    ["FortiWLC 8.6", "8.6.0 through 8.6.7", "Upgrade to upcoming 8.6.8 or above"],
    ["FortiExtender 7.2", "7.2 all versions", "Migrate to a fixed release"],
    ["FortiADC 7.0", "Not affected", "Not Applicable"],
    ["FortiMail 7.0", "7.0.0 through 7.0.7", "Upgrade to 7.0.8 or above"],
]


def html(rows=ROWS):
    table = "".join(
        "<tr>" + "".join("<td>" + value + "</td>" for value in row) + "</tr>" for row in rows
    )
    return f'''<h1>{TITLE}</h1><div class="detail-item"><h2>Summary</h2><h2>{CVE}</h2><p>Synthetic server vulnerability.</p></div>
    <div class="detail-item"><div><table><tr><th>Version</th><th>Affected</th><th>Solution</th></tr>{table}</table></div></div>
    <div class="detail-item">
    <p>Fortinet has remediated this issue in FortiDevSec version 24.3; and the customers do not need to perform any action.</p>
    <p>Fortinet has remediated this issue in FortiLANCloud version 24.3; and the customers do not need to perform any action.</p>
    <p>Vulnerable OpenSSH versions:<br>- Upstream references CVE-2006-5051 and CVE-2008-4109</p>
    <p>OpenSSH versions confirmed not vulnerable:<br>- Synthetic upstream range, not appliance scope</p>
    <p>Please note:<br>- Review OpenBSD and glibc-linux qualifiers.<br>- Review 64bits and ASLR exploitability context.</p>
    <p>Products Under Investigation:<br>- FortiNDR</p>
    <p>Products NOT Impacted:<br>- FortiOS<br>- FortiProxy<br>- FortiCASB/FortiCNP</p>
    <p>Workarounds:<br>- Synthetic SSH controls.</p><p>Mitigations:<br>- Synthetic trusted-network controls.</p></div>
    <table class="meta"><tr><td>IR Number</td><td>{ID}</td></tr><tr><td>CVE ID</td><td>{CVE}</td></tr>
    <tr><td>Published Date</td><td>Jul 9, 2024</td></tr><tr><td>Updated Date</td><td>May 13, 2025</td></tr></table>
    <a href="{ALT}">CSAF</a><p>PRIVATE_RAW_SENTINEL</p>'''.encode()


def csaf():
    products = [
        {"product_id": str(i), "name": "Synthetic structured product " + str(i)} for i in range(15)
    ]
    return json.dumps(
        {
            "document": {
                "title": "Synthetic structured counterpart",
                "tracking": {"id": ID, "status": "final"},
            },
            "product_tree": {"full_product_names": products},
            "vulnerabilities": [
                {
                    "cve": CVE,
                    "product_status": {"known_affected": [p["product_id"] for p in products]},
                }
            ],
        }
    ).encode()


def fetcher(db, url, vendor):
    if urlsplit(url).path == urlsplit(ALT).path and parse_qs(urlsplit(url).query) == parse_qs(
        urlsplit(ALT).query
    ):
        return csaf()
    return {URL: html(), MIRROR: html()}[url]


def test_table_ranges_explicit_lists_and_fixed_only_statements_keep_different_meanings():
    record = default_registry().normalize(html(), URL, "fortinet")
    assert record["cves"] == [CVE]
    assert len(record["assessments"]) == 12
    manager = [a for a in record["assessments"] if a["product"] == "FortiManager Cloud"]
    assert len(manager) == 2 and len({a["product_id"] for a in manager}) == 2
    assert {a["versions"][0]["expression"] for a in manager} == {"7.2.3 through 7.2.4", "7.2.1"}
    for product in ["FortiOS", "FortiProxy", "FortiCASB/FortiCNP"]:
        claim = next(a for a in record["assessments"] if a["product"] == product)
        assert claim["status"] == "unaffected" and not claim["versions"]
    assert not any(a["product"] in ["FortiCASB", "FortiCNP"] for a in record["assessments"])
    assert (
        next(a for a in record["assessments"] if a["product"] == "FortiNDR")["status"]
        == "investigating"
    )
    fixed = [a for a in record["assessments"] if a["status"] == "fixed"]
    assert len(fixed) == 2 and all("deployment mode" in a["exposure"][0]["details"] for a in fixed)
    assert "CVE-2006-5051" not in record["cves"] and "PRIVATE_RAW_SENTINEL" not in json.dumps(
        record
    )


def test_upcoming_migration_and_not_applicable_never_become_verified_available_fixes():
    record = openssh_advisory(html(), URL)
    claims = {a["product"]: a for a in record["assessments"]}
    assert claims["FortiWLC"]["remediations"][0]["availability"] == "planned"
    assert claims["FortiExtender"]["remediations"][0]["availability"] == "unknown"
    assert claims["FortiExtender"]["versions"][0]["expression"] == "7.2 all versions"
    assert claims["FortiADC"]["remediations"][0]["availability"] == "not_a_fix"
    assert "not blanket unaffectedness" in claims["FortiOS"]["exposure"][0]["details"]


@pytest.mark.parametrize(
    "before,after",
    [
        (TITLE.encode(), b"Unreviewed advisory"),
        (b"<td>FG-IR-24-258</td>", b"<td>FG-IR-00-000</td>"),
        (("<td>" + CVE + "</td>").encode(), b"<td>CVE-2025-12345</td>"),
        (b"<h2>" + CVE.encode() + b"</h2>", b"<h2>CVE-2025-12345</h2>"),
        (b"<th>Affected</th>", b"<th>Other meaning</th>"),
        (b"<th>Version</th>", b'<th colspan="2">Version</th>'),
        (b"7.2 all versions", b"7.0 all versions"),
        (b"Products NOT Impacted:", b"Products with unspecified status:"),
        (b"<p>Workarounds:", b"<p>Unreviewed qualification</p><p>Workarounds:"),
        (b"glibc-linux", b"unreviewed library"),
        (b"Upgrade to upcoming 8.6.8 or above", b"Upgrade unless an unreviewed condition applies"),
    ],
)
def test_identity_scope_and_condition_changes_require_review(before, after):
    with pytest.raises(ValueError):
        default_registry().normalize(html().replace(before, after), URL, "fortinet")


def test_conflicting_product_scopes_and_duplicate_ranges_are_not_silently_combined():
    with pytest.raises(ValueError):
        openssh_advisory(html().replace(b"- FortiOS", b"- FortiManager Cloud"), URL)
    with pytest.raises(ValueError):
        openssh_advisory(html(ROWS + [ROWS[0]]), URL)
    conflicting = ROWS + [["FortiManager Cloud 7.2", "Not affected", "Not Applicable"]]
    with pytest.raises(ValueError):
        openssh_advisory(html(conflicting), URL)


def test_html_policy_is_not_a_maximum_row_count_rule_and_survives_direct_csaf_collection(tmp_path):
    path = tmp_path / "fortinet.sqlite"
    with patch("infrastructure_impact.collection.service.fetch", side_effect=fetcher):
        assert run(
            {
                "vendors": [],
                "pinned": [
                    {"vendor": "fortinet", "url": MIRROR},
                    {"vendor": "fortinet", "url": ALT},
                ],
            },
            db_path=path,
        ) == (1, 0)
    with connect(path) as db:
        record = latest(db)[0]
        assert record["source_url"] == URL and len(record["assessments"]) == 12
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 1
        assert all(
            [(v["selected"], v["normalized_statements"]) for v in choice["views"]]
            == [(True, 12), (False, 15)]
            for choice in choices(db)
        )
        public = public_projection(state(db))
    study = public["component_studies"]["studies"][0]
    cell = next(c for c in study["cells"] if c["vendor"] == "fortinet" and c["cve_id"] == CVE)
    assert cell["state"] == "explicit_unaffected_statement" and len(cell["evidence"]) == 1
    assert study["rate_comparison"] is None and not study["ranking_supported"]
    assert "PRIVATE_RAW_SENTINEL" not in json.dumps(public)


def test_unavailable_structured_counterpart_keeps_valid_html_with_visible_partial_health(tmp_path):
    path = tmp_path / "partial.sqlite"

    def retrieve(db, url, vendor):
        if url == URL:
            return html()
        raise HTTPError(url, 403, "PRIVATE_ERROR_SENTINEL", {}, None)

    with patch("infrastructure_impact.collection.service.fetch", side_effect=retrieve):
        assert run(
            {"vendors": [], "pinned": [{"vendor": "fortinet", "url": URL}]}, db_path=path
        ) == (1, 1)
    with connect(path) as db:
        assert next(row for row in health(db) if row["source_url"] == URL)["outcome"] == "partial"
        assert choices(db)[0]["unavailable"] == [{"source_url": ALT, "error_code": "access_denied"}]
        assert "PRIVATE_ERROR_SENTINEL" not in json.dumps(choices(db))
        assert (
            next(a for a in latest(db)[0]["assessments"] if a["product"] == "FortiOS")["status"]
            == "unaffected"
        )


def test_contradictory_direct_structured_cve_scope_is_rejected_before_followup_fetch(tmp_path):
    calls = []

    def retrieve(db, url, vendor):
        calls.append(url)
        return csaf().replace(CVE.encode(), b"CVE-2025-12345")

    path = tmp_path / "contradictory.sqlite"
    with patch("infrastructure_impact.collection.service.fetch", side_effect=retrieve):
        assert run(
            {"vendors": [], "pinned": [{"vendor": "fortinet", "url": ALT}]}, db_path=path
        ) == (0, 1)
    assert len(calls) == 1
    with connect(path) as db:
        assert not latest(db) and not choices(db)
