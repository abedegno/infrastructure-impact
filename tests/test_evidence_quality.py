"""Role boundaries, reviewed fallbacks, source drift and research counter-evidence."""

import copy
import json
import subprocess
from urllib.parse import urlencode

import pytest

from infrastructure_impact.adapters.common import assessment, base
from infrastructure_impact.adapters.fortinet import document_history, investigation_advisory
from infrastructure_impact.application.casefiles import casefiles, select_casefiles
from infrastructure_impact.application.eligibility import eligibility
from infrastructure_impact.application.extraction_validation import definition as review_definition
from infrastructure_impact.application.extraction_validation import review_packet, validation_report
from infrastructure_impact.application.product_groups import classify, definition, product_groups
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.http import Application
from infrastructure_impact.plugins.fortinet import resolve
from infrastructure_impact.settings import PACKAGE
from infrastructure_impact.storage.repository import connect, ingest

CID = "CVE-2025-12345"
OTHER = "CVE-2025-54321"
URL = "https://www.fortiguard.com/psirt/FG-IR-25-123"
HISTORY = "https://docs.fortinet.com/document/fortiproxy/7.2.8/release-notes/4/change-log"


def investigation():
    # Original synthetic layout, not captured vendor content.
    return f"""<html><h1>Synthetic component bulletin</h1><div class="detail-item"><h2>Summary</h2><p>{CID} - (high) synthetic</p><p>{OTHER} - (low) synthetic</p></div><div class="detail-item"><h6>Fortinet is currently investigating the impact of these CVEs over Fortinet Products.</h6><h4>Products under investigation:</h4><p>FortiOS</p><h4>Products confirmed NOT impacted:</h4><p>FortiManager<br/>FortiAnalyzer</p></div><table><tr><td>IR Number</td><td>FG-IR-25-123</td></tr><tr><td>Published Date</td><td>Jan 1, 2025</td></tr><tr><td>CVE ID</td><td>{CID}</td></tr></table></html>""".encode()


def history():
    return f"""<html><h1>FortiProxy 7.2.8 Change log</h1><table><tr><th>Date</th><th>Change Description</th></tr><tr><td>2023-12-08</td><td>Initial release.</td></tr><tr><td>2023-12-12</td><td>Added {CID} and {OTHER} to Resolved issues.</td></tr></table></html>""".encode()


def test_empty_export_resolves_only_to_identity_checked_scoped_html():
    envelope = json.dumps({"document": {"tracking": {"id": "FG-IR-25-123"}}}).encode()
    calls = []

    def fetch(url):
        calls.append(url)
        return investigation()

    url, raw = resolve(envelope, "https://filestore.fortinet.com/empty.json", fetch)
    assert calls == [URL]
    record = investigation_advisory(raw, url, "fortinet")
    assert len(record["assessments"]) == 6
    assert {a["scope"] for a in record["assessments"]} == {"bulletin_shared"}
    assert {a["status"] for a in record["assessments"] if a["product"] == "FortiOS"} == {
        "investigating"
    }
    assert all(not a["versions"] and not a["remediations"] for a in record["assessments"])
    assert record["published_at"] == "2025-01-01"
    with pytest.raises(ValueError):
        investigation_advisory(raw.replace(b"FG-IR-25-123", b"FG-IR-25-999"), url, "fortinet")
    with pytest.raises(ValueError):
        investigation_advisory(
            raw.replace(b"FortiManager<br/>FortiAnalyzer", b"FortiOS"), url, "fortinet"
        )
    with pytest.raises(ValueError):
        investigation_advisory(
            raw.replace(b"Products confirmed NOT impacted:", b"Products affected:"), url, "fortinet"
        )
    # A populated structured advisory is not replaced by a weaker HTML view.
    populated = json.dumps(
        {"document": {"tracking": {"id": "FG-IR-25-123"}}, "vulnerabilities": [{"cve": CID}]}
    ).encode()
    assert resolve(populated, URL, lambda _: pytest.fail("Unexpected request")) == (URL, populated)


def test_family_mapping_preserves_management_and_unknown_boundaries():
    assert classify("paloalto", {"product": "PAN-OS (Panorama)"})["group"] == "management"
    assert classify("paloalto", {"product": "PAN-OS (Firewall, WildFire)"})["group"] == "firewalls"
    assert classify("fortinet", {"product": "FortiProxy 7.2.8"})["group"] == "web_gateways"
    assert (
        classify("aruba", {"product": "Aruba EdgeConnect Enterprise Orchestrator"})["group"]
        == "management"
    )
    assert (
        classify("cisco", {"product": "17.12.1", "product_family": "Cisco IOS XE Software"})[
            "group"
        ]
        == "routing_switching"
    )
    assert classify("cisco", {"product": "17.12.1"})["state"] == "unmapped"
    assert classify("acme", {"product": "PAN-OS"})["state"] == "unmapped"
    assert classify("paloalto", {"product": "PAN-OSNotAProduct"})["state"] == "unmapped"
    taxonomy = copy.deepcopy(definition())
    rule = copy.deepcopy(next(r for r in taxonomy["rules"] if r["prefix"] == "PAN-OS"))
    rule.update(id="conflicting-rule", group="management")
    taxonomy["rules"].append(rule)
    assert classify("paloalto", {"product": "PAN-OS"}, taxonomy)["state"] == "ambiguous"


def test_group_filter_does_not_leak_shared_numeric_labels_between_families(tmp_path):
    r = base("cisco", "https://www.cisco.com/synthetic", "SYNTHETIC-1", "Synthetic", "2025-01-01")
    r.update(cves=[CID, OTHER], document_status="final")
    first = assessment(CID, "1.0", "affected", "synthetic")
    first.update(product_id="switch-version", product_family="Cisco NX-OS Software")
    second = assessment(OTHER, "1.0", "unaffected", "synthetic")
    second.update(product_id="router-version", product_family="Cisco IOS XR Software")
    r["assessments"] = [first, second]
    with connect(":memory:") as db:
        ingest(db, b"synthetic source", r["source_url"], lambda *_: r, "cisco")
        data = state(db, [CID, OTHER])
    publish(data, tmp_path)
    app = Application(tmp_path)
    code, _, raw = app.route(
        {
            "PATH_INFO": "/api/v1/comparison-eligibility",
            "REQUEST_METHOD": "GET",
            "QUERY_STRING": urlencode(
                {"start": "2025-01-01", "end": "2025-12-31", "group": "switching"}
            ),
        }
    )
    assert code == 200
    report = json.loads(raw)
    vendor = next(v for v in report["vendors"] if v["vendor"] == "cisco")
    assert vendor["product_scope"]["labels"] == ["1.0"]
    assert vendor["counts"]["cves_with_statement"] == 1
    assert next(c for c in vendor["cases"] if c["cve_id"] == OTHER)["statuses"] == []
    assert vendor["eligibility"]["rate_comparison"] == "suppressed"
    for query in ["group=unknown", "group=switching&group=routing"]:
        with pytest.raises(ValueError):
            app.route(
                {
                    "PATH_INFO": "/api/v1/comparison-eligibility",
                    "REQUEST_METHOD": "GET",
                    "QUERY_STRING": query,
                }
            )
    node = "const fs=require('fs'),vm=require('vm');const c={window:{},Set,Map,URL,Response,Blob};vm.createContext(c);vm.runInContext(fs.readFileSync(require('path').join(require('path').dirname(process.argv[1]),'research-dossiers.js'),'utf8'),c);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),c);const d=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(c.comparisonEligibility(d,[process.argv[2],process.argv[3]],{start:'2025-01-01',end:'2025-12-31',group:'switching'})));"
    output = subprocess.check_output(
        ["node", "-e", node, str(PACKAGE / "web/snapshot.js"), CID, OTHER],
        input=json.dumps(data).encode(),
    )
    js = json.loads(output)
    assert js == {k: v for k, v in report.items() if k not in ("publication", "generated_at")}
    assert (
        sum(
            v["mapped_statements"] + v["unmapped_statements"] + v["ambiguous_statements"]
            for v in product_groups(data)["vendors"]
        )
        == 2
    )


def test_source_drift_never_relabels_or_certifies_human_review():
    review = review_definition()
    case = review["cases"][0]
    r = dict(
        vendor=case["vendor"],
        source_url=case["source_url"],
        sha256="0" * 64,
        assessments=[],
        document_status="final",
    )
    result = validation_report([r])
    assert result["cases"][0]["outcome"] == "source_revision_unreviewed"
    assert result["global_precision"] is None
    assert result["independent_human_review_completed"] is False
    packet = json.dumps(review_packet([r]))
    assert "expected_status" not in packet and "observed_statuses" not in packet
    assert "adjudication" in packet and "awaiting_independent_reviewer" in packet


def test_document_history_is_metadata_and_keeps_earlier_advisory_counter_evidence():
    parsed = document_history(history(), HISTORY, "fortinet")
    assert parsed["events"][0]["kind"] == "initial_document_release"
    assert parsed["events"][1]["cve_ids"] == [CID, OTHER]
    assert "released_at" not in json.dumps(parsed)
    with pytest.raises(ValueError):
        document_history(history().replace(b"2023-12-12", b"2023-02-30"), HISTORY, "fortinet")
    assert document_history(history(), URL, "fortinet") is None
    r = base("fortinet", URL, "SYNTHETIC-PRIOR", "Synthetic", "2023-11-14T00:00:00")
    r.update(
        cves=[CID, OTHER],
        sha256="a" * 64,
        evidence_id=1,
        document_status="final",
        assessments=[assessment(c, "FortiProxy", "affected", "synthetic") for c in [CID, OTHER]],
    )
    case = dict(
        id="synthetic-case",
        vendor="fortinet",
        cve_ids=[CID, OTHER],
        product_pattern="^FortiProxy",
        prior_advisory_product_pattern="^FortiProxy",
        product_scope="synthetic",
        question="Synthetic question",
        advisory_urls=[URL],
        release_source_leads=[HISTORY],
        research_record=None,
        missing_evidence=["Independent availability"],
        alternative_explanations=["Documentation change"],
    )
    document = dict(
        **parsed,
        vendor="fortinet",
        source_url=HISTORY,
        source_sha256="b" * 64,
        observed_at="2026-01-01T00:00:00Z",
        state="parsed",
    )
    result = casefiles(
        dict(records=[r], publisher_history={"documents": [document]}),
        dict(
            schema_version=1,
            reviewed_at="2026-10-26",
            review_method="synthetic automated",
            cases=[case],
        ),
    )
    c = result["cases"][0]
    assert {o["days"] for o in c["reported_documentation_offsets"]} == {4}
    assert (
        c["earlier_dated_vendor_documents"][0]["date_basis"]
        == "publisher_calendar_claim_timezone_unspecified"
    )
    assert c["independent_release_availability_verified"] is False
    assert c["finding"] == "no_concealment_finding"
    selected = select_casefiles(result, [CID])["cases"][0]
    assert [o["cve_id"] for o in selected["reported_documentation_offsets"]] == [CID]
    assert selected["earlier_dated_vendor_documents"][0]["cve_ids"] == [CID]


def test_informational_summary_never_creates_product_impact_claims():
    from infrastructure_impact.adapters.arista import arista_aggregate_notice

    url = "https://www.arista.com/en/support/advisories-notices/security-advisory/24776-security-advisory-0184"
    raw = f"<html><p>Update Type: Informational</p><table><tr><td>1.0</td><td>September 29, 2026</td><td>Initial release</td></tr></table><table><tr><th>Security Advisory #</th><th>Product (Component)</th><th>CVE ID</th><th>Severity</th><th>CVSS 3.1 Score</th></tr><tr><td>185</td><td>Example Platform</td><td>{CID}</td><td>High</td><td>8.4</td></tr></table></html>"
    record = arista_aggregate_notice(raw, url, "arista")
    assert record["cves"] == [CID]
    assert record["assessments"] == []
    with pytest.raises(ValueError):
        arista_aggregate_notice(raw.replace("CVE ID", "Unknown ID"), url, "arista")
    assert (
        classify("cisco", {"product": "Secure Firewall Management Center"})["group"] == "management"
    )
    assert classify("cisco", {"product": "Secure Firewall Threat Defense"})["group"] == "firewalls"


def test_reader_uses_the_taxonomy_pinned_to_its_publication():
    # Simulate a retained generation whose role rules differ from the installed package.
    taxonomy = copy.deepcopy(definition())
    taxonomy["taxonomy_version"] = "synthetic-retained-generation"
    taxonomy["rules"] = [
        dict(
            id="retained-rule",
            vendor="arista",
            group="routing",
            prefix="Synthetic router",
            source_url="https://www.arista.com/synthetic",
            reviewed_at="2026-10-26",
            rationale="Synthetic retained family",
        )
    ]
    claim = assessment(CID, "Synthetic router", "affected", "synthetic")
    data = dict(
        generated_at="2026-10-26T00:00:00Z",
        vendors={"arista": "Arista"},
        all_cves=[CID],
        product_groups=taxonomy,
        records=[
            dict(
                vendor="arista",
                advisory_id="SYNTHETIC",
                source_url="https://www.arista.com/synthetic",
                sha256="a" * 64,
                published_at="2026-01-01",
                document_status="final",
                assessments=[claim],
            )
        ],
    )
    result = eligibility(data, [CID], group="routing")
    assert result["taxonomy_version"] == "synthetic-retained-generation"
    assert result["vendors"][0]["counts"]["explicit_affected"] == 1
    assert classify("arista", claim)["state"] == "unmapped"
    assert result["vendors"][0]["eligibility"]["rate_comparison"] == "suppressed"
    node = "const fs=require('fs'),vm=require('vm');const c={window:{},Set,Map,URL,Response,Blob};vm.createContext(c);vm.runInContext(fs.readFileSync(require('path').join(require('path').dirname(process.argv[1]),'research-dossiers.js'),'utf8'),c);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),c);const d=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(c.comparisonEligibility(d,d.all_cves,{group:'routing'})));"
    js = json.loads(
        subprocess.check_output(
            ["node", "-e", node, str(PACKAGE / "web/snapshot.js")], input=json.dumps(data).encode()
        )
    )
    assert js == result


def test_unreviewed_html_keeps_structured_title_scope_without_product_inference():
    from infrastructure_impact.plugins.shared import structured

    url = "https://filestore.fortinet.com/synthetic-envelope.json"
    raw = json.dumps(
        {
            "document": {
                "title": "Synthetic component " + CID,
                "tracking": {"id": "FG-IR-25-123", "status": "final"},
            }
        }
    ).encode()
    resolved_url, result = resolve(raw, url, lambda _: b"<html>Unreviewed publisher layout</html>")
    assert (resolved_url, result) == (url, raw)
    record = structured(result, resolved_url, "fortinet")
    assert record["cves"] == [CID]
    assert record["assessments"] == []
    assert any("no encoded product assessments" in w.lower() for w in record["warnings"])
