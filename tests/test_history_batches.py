"""Synthetic vendor identity and offline archive batch boundaries."""

import json

import pytest

from infrastructure_impact.adapters.vendor_cna import PROFILES, registry_route, vendor_cna
from infrastructure_impact.collection.archive import enqueue
from infrastructure_impact.collection.triage import review_batch
from infrastructure_impact.domain import validate_advisory
from infrastructure_impact.plugins.arista import parse as arista
from infrastructure_impact.storage.repository import connect, evidence

CID = "CVE-2026-12345"
URL = "https://cveawg.mitre.org/api/cve/" + CID
ARISTA = "https://www.arista.com/en/support/advisories-notices/security-advisory/"


def record(vendor):
    org, vendors, domains = PROFILES[vendor]
    return dict(
        cveMetadata=dict(cveId=CID, state="PUBLISHED", assignerOrgId=org),
        containers=dict(
            cna=dict(
                providerMetadata=dict(orgId=org),
                title="Synthetic title mentioning CVE-2024-99999",
                affected=[
                    dict(
                        vendor=sorted(vendors)[0],
                        product="Example infrastructure product",
                        platforms=["MODEL-A"],
                        defaultStatus="unaffected",
                        versions=[dict(version="1", lessThan="2", status="affected")],
                    )
                ],
                descriptions=[dict(lang="en", value="Only when the optional service is enabled.")],
                configurations=[dict(lang="en", value="Specific configuration required.")],
                solutions=[dict(lang="en", value="Product-specific resolution must be checked.")],
                references=[dict(url="https://support." + domains[0] + "/SYNTHETIC")],
            ),
            adp=[dict(affected=[dict(vendor="Another vendor", product="Unrelated")])],
        ),
    )


@pytest.mark.parametrize("vendor", ["cisco", "hpe", "checkpoint", "juniper"])
def test_verified_vendor_cna_keeps_identity_platform_and_configuration(vendor):
    result = validate_advisory(vendor_cna(json.dumps(record(vendor)), URL, vendor))
    assert result["cves"] == [CID] and len(result["assessments"]) == 1
    claim = result["assessments"][0]
    assert claim["scope"] == "cve_specific" and claim["platforms"] == ["MODEL-A"]
    assert claim["versions"][0]["lessThan"] == "2"
    assert "optional service" in json.dumps(
        claim["exposure"]
    ) and "Specific configuration" in json.dumps(claim["exposure"])
    assert "Unrelated" not in json.dumps(result) and not claim["remediations"]


@pytest.mark.parametrize("change", ["assigner", "provider", "vendor", "id", "state", "reference"])
def test_cna_identity_or_scope_changes_cannot_attribute_an_upstream_record(change):
    data = record("cisco")
    if change == "assigner":
        data["cveMetadata"]["assignerOrgId"] = PROFILES["hpe"][0]
    if change == "provider":
        data["containers"]["cna"]["providerMetadata"]["orgId"] = PROFILES["hpe"][0]
    if change == "vendor":
        data["containers"]["cna"]["affected"][0]["vendor"] = "Upstream component"
    if change == "id":
        data["cveMetadata"]["cveId"] = "CVE-2026-54321"
    if change == "state":
        data["cveMetadata"]["state"] = "REJECTED"
    if change == "reference":
        data["containers"]["cna"]["references"][0]["url"] = (
            "https://cisco.com.example.test/advisory"
        )
    with pytest.raises(ValueError):
        vendor_cna(json.dumps(data), URL, "cisco")


@pytest.mark.parametrize(
    "url",
    [
        URL.replace("https:", "http:"),
        URL + "?query=1",
        URL + "#fragment",
        URL.replace("cveawg.", "user:pass@cveawg."),
        URL.replace("mitre.org", "mitre.org.example.test"),
    ],
)
def test_registry_transport_scope_is_exact(url):
    assert not registry_route(url)


def add_queue(db, vendor, url):
    seed = (
        "https://www.arista.com/en/support/advisories-notices"
        if vendor == "arista"
        else "https://security.paloaltonetworks.com/"
    )
    db.execute(
        "INSERT OR IGNORE INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
        (vendor, seed, "listing", "2026-01-01T00:00:00Z"),
    )
    sid = db.execute("SELECT id FROM archive_sources WHERE vendor=?", (vendor,)).fetchone()[0]
    enqueue(db, sid, "document", url)


def test_offline_triage_follows_retained_csaf_without_fetch_or_queue_mutation(monkeypatch):
    from infrastructure_impact.collection import service

    def no_network(*args):
        raise AssertionError("Offline triage must not fetch")

    monkeypatch.setattr(service, "fetch", no_network)
    original = ARISTA + "synthetic-source"
    target = "https://www.arista.com/assets/SYNTHETIC-csaf.json"
    raw = json.dumps(
        dict(
            document=dict(
                title="Synthetic advisory", tracking=dict(id="SYNTHETIC", status="final")
            ),
            product_tree=dict(full_product_names=[dict(product_id="p", name="Example Switch")]),
            vulnerabilities=[dict(cve=CID, product_status=dict(known_affected=["p"]))],
        )
    ).encode()
    with connect(":memory:") as db:
        add_queue(db, "arista", original)
        evidence(db, f'<a href="{target}">CSAF</a>'.encode(), original)
        before = [tuple(r) for r in db.execute("SELECT * FROM archive_items")]
        missing = review_batch(db, vendor="arista")
        assert missing["dispositions"] == {"not_retained": 1}
        evidence(db, raw, target)
        result = review_batch(db, vendor="arista")
        assert result["dispositions"] == {"normalized": 1}
        assert (
            result["documents"][0]["resolved_url"] == target
            and result["documents"][0]["layout"] == "csaf"
        )
        assert before == [tuple(r) for r in db.execute("SELECT * FROM archive_items")]
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 0
        assert not result["network_retrieval"] and not result["queue_mutated"]


def test_triage_limits_and_vendor_filter_do_not_claim_complete_history():
    with connect(":memory:") as db:
        for n in range(3):
            add_queue(db, "arista", ARISTA + "source-" + str(n))
        add_queue(db, "paloalto", "https://security.paloaltonetworks.com/json/" + CID)
        result = review_batch(db, vendor="arista", limit=2)
        assert (
            result["available_documents"] == 3 and result["selected"] == 2 and result["truncated"]
        )
        assert all(r["vendor"] == "arista" for r in result["documents"])
        with pytest.raises(ValueError):
            review_batch(db, limit=201)


def article(number, body):
    return f'<div class="item-page"><h2>Security Advisory {number}</h2><table><tr><td>1.0</td><td>October 21, 2025</td><td>Initial release</td></tr></table>{body}</div>'


def test_nested_ngfw_mitigation_headings_remain_with_their_cve_context():
    ids = ["CVE-2026-30000", "CVE-2026-30001", "CVE-2026-30002"]
    descriptions = "".join(f"<p>Description {i}; CVE : {cid}</p>" for i, cid in enumerate(ids))
    raw = article(
        "0123",
        f"<h2>Description</h2>{descriptions}<h3>Affected Software</h3><h4>Arista Edge Threat Management - Arista Next Generation Firewall (NGFW) Versions</h4><ul><li>17.3.1 and prior</li></ul><h3>Affected Platforms</h3><p>NGFW only.</p><h3>Required Configuration for Exploitation, Indicators of Compromise and Mitigation Options</h3><h4>{ids[0]}</h4><p>Captive portal enabled.</p><h4>Mitigation</h4><p>First mitigation.</p><h4>{ids[1]}</h4><p>Specific user interaction.</p><h4>Mitigation</h4><p>Second mitigation.</p><h3>Resolution</h3><p>Unrelated solution section.</p>",
    )
    result = validate_advisory(arista(raw, ARISTA + "22535-security-advisory-0123", "arista"))
    assert len(result["assessments"]) == 3
    for claim in result["assessments"]:
        context = json.dumps(claim["exposure"])
        assert (
            "First mitigation" in context
            and "Second mitigation" in context
            and "Specific user interaction" in context
        )
        assert "Unrelated solution" not in context


def test_nested_ngfw_0105_uses_numbered_descriptions_not_acknowledgment_cves():
    ids = ["CVE-2026-" + str(50000 + i) for i in range(9)]
    descriptions = "".join(
        f"<p>{i}) Description: issue; CVE : {cid}</p>" for i, cid in enumerate(ids)
    )
    raw = article(
        "0105",
        f"<h2>Description</h2>{descriptions}<p>Acknowledgment mentions CVE-2026-99999.</p>"
        "<h3>Affected Software</h3><ul><li>Arista Edge Threat Management - Arista NG Firewall Versions<ul><li>17.1.1 and prior</li></ul></li></ul>"
        "<h3>Affected Platforms</h3><p>NGFW only. Other platforms are excluded.</p>"
        "<h3>Required Configuration for Exploitation, Indicators of Compromise and Mitigation Options</h3><h4>Mitigation</h4><p>Captive portal configuration must be reviewed.</p>",
    )
    result = validate_advisory(arista(raw, ARISTA + "20454-security-advisory-0105", "arista"))
    assert set(result["cves"]) == set(ids) and len(result["assessments"]) == 9
    assert all(
        a["scope"] == "bulletin_shared" and a["status"] == "affected" for a in result["assessments"]
    )
    assert all(
        a["versions"] == [dict(expression="17.1.1 and prior")] for a in result["assessments"]
    )
    assert "Captive portal" in json.dumps(result["assessments"][0]["exposure"])
    with pytest.raises(ValueError):
        arista(
            raw.replace("17.1.1 and prior", "17.1.1 except special builds"),
            ARISTA + "20454-security-advisory-0105",
            "arista",
        )


def test_cisco_feed_follows_bounded_author_verified_records_and_keeps_primary_urls():
    from infrastructure_impact.plugins.cisco import parse_feed

    items = "".join(
        f"<item><title>Example {n} CVE-2026-{30000 + n}</title><link>https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/SYNTHETIC-{n}</link></item>"
        for n in range(20)
    )
    result = parse_feed(
        ("<rss><channel>" + items + "</channel></rss>").encode(),
        "https://sec.cloudapps.cisco.com/feed",
        20,
        frozenset(),
    )
    assert len(result.document_urls) == 20
    assert sum("cveawg.mitre.org" in u for u in result.document_urls) == 8
    assert sum("sec.cloudapps.cisco.com" in u for u in result.document_urls) == 12
    assert not result.records


def test_suite_advisory_keeps_appliance_exception_and_shared_software_scope():
    ids = ["CVE-2026-" + str(40000 + i) for i in range(5)]
    header = "<ul>" + "".join(f"<li>{cid} issue</li>" for cid in ids) + "</ul>"
    description = "".join(f"<p>{cid} Description: restricted-user issue</p>" for cid in ids)
    raw = article(
        "0124",
        f"{header}<h3>Description</h3>{description}<h4>Affected Software</h4><div>Danz Monitoring Fabric</div><ul><li>DMF 8.7.0</li></ul><div>Converged Cloud Fabric</div><ul><li>CCF 6.2.4 and below</li></ul><div>CloudVision Appliance software</div><ul><li>All versions of CVA 7.0.x</li></ul><div>Multi-Cloud Director</div><ul><li>MCD 2.4.0 and below</li></ul><h3>Affected Platforms</h3><p>DCA physical appliances only. CloudVision Portal virtual appliance software is not affected.</p><h3>Required Configuration for Exploitation</h3><p>A restricted user must be able to log in.</p>",
    )
    result = validate_advisory(arista(raw, ARISTA + "22538-security-advisory-0124", "arista"))
    assert len(result["assessments"]) == 20
    assert {a["product"] for a in result["assessments"]} == {
        "DANZ Monitoring Fabric (DMF)",
        "Arista Converged Cloud Fabric (CCF)",
        "CloudVision Appliance Software (CVA)",
        "Arista Multi Cloud Director (MCD)",
    }
    assert all(
        a["scope"] == "bulletin_shared"
        and "virtual appliance software is not affected" in json.dumps(a["exposure"])
        for a in result["assessments"]
    )


def test_on_prem_cloudvision_keeps_onboarding_token_prerequisites():
    raw = article(
        "0116",
        f"<p>The CVE-ID tracking this issue: {CID}</p><h3>Description</h3><p>CloudVision Portal on-prem issue.</p><h4>Affected Software</h4><div>CVP Versions</div><ul><li>2024.3.0</li></ul><h4>Affected Platforms</h4><p>CloudVision Portal. Cloud service excluded.</p><h3>Required Configuration for Exploitation</h3><p>No specific configuration required.</p><h3>Mitigation</h3><p>Successful exploit requires a valid onboarding token or a user with device onboarding privileges.</p>",
    )
    result = validate_advisory(arista(raw, ARISTA + "21316-security-advisory-0116", "arista"))
    assert result["assessments"][0]["product"] == "CloudVision Portal (on-premises)"
    assert "valid onboarding token" in json.dumps(result["assessments"][0]["exposure"])


def test_upstream_authored_cve_is_a_recorded_exclusion_without_vendor_ingestion(
    tmp_path, monkeypatch
):
    from infrastructure_impact.collection import service
    from infrastructure_impact.plugins.contracts import SourceNotApplicable

    data = record("hpe")
    with pytest.raises(SourceNotApplicable):
        vendor_cna(json.dumps(data), URL, "cisco")
    monkeypatch.setattr(service, "fetch", lambda *args: json.dumps(data).encode())
    path = tmp_path / "vault.sqlite3"
    assert service.run(dict(vendors=[], pinned=[dict(vendor="cisco", url=URL)]), db_path=path) == (
        0,
        0,
    )
    with connect(path) as db:
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 0
        assert db.execute("SELECT outcome FROM collection_runs").fetchone()[0] == "not_applicable"
