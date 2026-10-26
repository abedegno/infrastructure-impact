"""Synthetic coverage boundaries and private review auditing; no vendor originals."""

import copy
import json
from datetime import datetime, timezone

import pytest

from infrastructure_impact.adapters.hpe import hpe_bulletin
from infrastructure_impact.adapters.vendor_cna import JUNIPER_CNA, juniper_cna
from infrastructure_impact.application.extraction_validation import (
    definition,
    packet_sha256,
    review_packet,
    validation_report,
)
from infrastructure_impact.application.product_groups import classify
from infrastructure_impact.application.review_submission import (
    audit_submission,
    submission_template,
)
from infrastructure_impact.application.source_scope import scope_sha256
from infrastructure_impact.collection.transport import allowed
from infrastructure_impact.plugins.juniper import parse_feed

CID = "CVE-2025-12345"
URL = "https://cveawg.mitre.org/api/cve/" + CID


def cna():
    return {
        "cveMetadata": {
            "cveId": CID,
            "state": "PUBLISHED",
            "assignerOrgId": JUNIPER_CNA,
            "datePublished": "2025-01-01T00:00:00Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {"orgId": JUNIPER_CNA},
                "title": "Synthetic " + CID,
                "affected": [
                    {
                        "vendor": "Juniper Networks",
                        "product": "Junos OS Evolved",
                        "platforms": ["QFX9999"],
                        "defaultStatus": "unaffected",
                        "versions": [
                            {
                                "version": "1",
                                "lessThan": "2",
                                "versionType": "custom",
                                "status": "affected",
                            }
                        ],
                    }
                ],
                "descriptions": [{"lang": "en", "value": "Only configured BGP deployments."}],
                "configurations": [{"lang": "en", "value": "Synthetic configuration prerequisite"}],
                "solutions": [{"lang": "en", "value": "Previously published release rebuilt."}],
            }
        },
    }


def test_vendor_cna_keeps_conditional_scope_and_never_infers_fix_availability():
    d = cna()
    d["containers"]["cna"]["title"] += " referencing CVE-2024-99999"
    r = juniper_cna(json.dumps(d), URL, "juniper")
    assert r["cves"] == [CID]
    assert len(r["assessments"]) == 1
    a = r["assessments"][0]
    assert a["scope"] == "cve_specific" and a["platforms"] == ["QFX9999"]
    assert len(a["exposure"]) == 3 and not a["remediations"]
    assert a["status"] == "affected"


@pytest.mark.parametrize("change", ["assigner", "provider", "vendor", "identity", "state"])
def test_registry_delivery_does_not_make_upstream_or_adp_a_vendor_statement(change):
    d = cna()
    if change == "assigner":
        d["cveMetadata"]["assignerOrgId"] = "upstream"
    if change == "provider":
        d["containers"]["cna"]["providerMetadata"]["orgId"] = "upstream"
    if change == "vendor":
        d["containers"]["cna"]["affected"][0]["vendor"] = "Upstream"
    if change == "identity":
        d["cveMetadata"]["cveId"] = "CVE-2025-99999"
    if change == "state":
        d["cveMetadata"]["state"] = "REJECTED"
    with pytest.raises(ValueError):
        juniper_cna(json.dumps(d), URL, "juniper")


@pytest.mark.parametrize(
    "url",
    [
        URL + "?anything=1",
        URL + "#fragment",
        "http://cveawg.mitre.org/api/cve/" + CID,
        "https://cveawg.mitre.org/other",
        "https://sub.cveawg.mitre.org/api/cve/" + CID,
    ],
)
def test_registry_allowlist_is_exact_route(url):
    assert not allowed(url, "juniper")


def test_feed_followups_are_bounded_and_reference_titles_are_not_impacts():
    entries = [f"<item><title>Reference: {CID}</title></item>"] + [
        f"<item><title>Security Bulletin: CVE-2025-{20000 + i}</title></item>" for i in range(20)
    ]
    b = parse_feed(
        "<rss><channel>" + "".join(entries) + "</channel></rss>",
        "https://supportportal.juniper.net/knowledgerss?type=Security",
        30,
        set(),
    )
    assert len(b.document_urls) == 8 and URL not in b.document_urls
    assert all(not r["assessments"] for r in b.records)


def bulletin(alias="iLO 7"):
    return f"<h1>HPESBHF99999 Synthetic</h1><p>VULNERABILITY SUMMARY {CID} CVE-2025-12346. {CID} - {alias} is not vulnerable</p><p>SUPPORTED SOFTWARE VERSIONS*</p><p>HPE Integrated Lights-Out 7 (iLO 7) - prior to 2.0</p><p>BACKGROUND Synthetic</p><p>RESOLUTION Update firmware</p><p>HISTORY</p>"


def test_hpe_exception_is_cve_specific_and_unknown_exception_fails_closed():
    r = hpe_bulletin(bulletin(), "https://support.hpe.com/synthetic", "hpe")
    a, b = r["assessments"]
    assert a["status"] == "unaffected" and not a["versions"] and not a["remediations"]
    assert (
        a["scope"] == "cve_specific"
        and b["status"] == "affected"
        and b["scope"] == "bulletin_shared"
    )
    with pytest.raises(ValueError):
        hpe_bulletin(bulletin("unknown"), "https://support.hpe.com/synthetic", "hpe")
    with pytest.raises(ValueError):
        hpe_bulletin(
            bulletin().replace("is not vulnerable", "is not affected"),
            "https://support.hpe.com/synthetic",
            "hpe",
        )


@pytest.mark.parametrize(
    "platforms,group",
    [
        (["QFX5240"], "switching"),
        (["SRX5000"], "firewalls"),
        (["MX240"], "routing"),
        ([], "routing_switching"),
        (["SRX5000", "MX240"], "routing_switching"),
    ],
)
def test_platform_mapping_retains_unknown_and_mixed_roles(platforms, group):
    assert (
        classify("juniper", {"product": "Junos OS Evolved", "platforms": platforms})["group"]
        == group
    )


def test_reviewed_section_ignores_only_surroundings_and_random_cloak_id():
    scheme = "arista_advisory_body_v1"
    raw = (
        '<nav>one</nav><div class="item-page"><h1>Advisory</h1><span id="cloak'
        + "a" * 32
        + '">email</span><table><tr><td>Affected</td></tr></table><a href="https://example.com/fix">Fix</a></div>'
    )
    digest = scope_sha256(raw, scheme)
    assert digest == scope_sha256(
        raw.replace("one", "two").replace("cloak" + "a" * 32, "cloak" + "b" * 32), scheme
    )
    for changed in [
        raw.replace("Affected", "Unaffected"),
        raw.replace("/fix", "/other"),
        raw.replace("<td>", "<th>"),
    ]:
        assert digest != scope_sha256(changed, scheme)
    with pytest.raises(ValueError):
        scope_sha256(raw.replace("item-page", "unknown"), scheme)


def test_changed_scope_match_is_separate_and_still_checks_semantics():
    review = definition()
    case = copy.deepcopy(review["cases"][2])
    review["cases"] = [case]
    r = dict(
        vendor=case["vendor"],
        source_url=case["source_url"],
        sha256="0" * 64,
        assessments=[
            dict(
                cve_id=case["cve_id"],
                product="Arista EOS-based products",
                status="affected",
                versions=[{"expression": "4.27.3"}],
                remediations=[],
            )
        ],
    )
    scopes = [
        dict(
            source_url=r["source_url"],
            source_sha256=r["sha256"],
            scheme=case["reviewed_scope"]["scheme"],
            scope_sha256=case["reviewed_scope"]["sha256"],
        )
    ]
    report = validation_report([r], review, scopes)
    assert (
        report["passed"] == 0
        and report["scope_matches"] == 1
        and not report["independent_human_review_completed"]
    )
    r["assessments"][0]["status"] = "unaffected"
    assert validation_report([r], review, scopes)["cases"][0]["outcome"] == "disagreement"


def proposal():
    p = review_packet([])
    s = submission_template(p)
    s["reviewer"] = dict(
        kind="human",
        display_name="PRIVATE_NAME",
        reviewed_at="2025-01-01T00:00:00Z",
        independence_statement="PRIVATE_CONFLICTS",
    )
    a = s["adjudications"][0]
    s["adjudications"] = [a]
    for k in a:
        if k not in ("id", "source_sha256"):
            a[k] = "PRIVATE_RATIONALE"
    a["status"] = "not_adjudicated"
    return p, s


def test_private_proposal_never_certifies_review_or_publishes_identity():
    p, s = proposal()
    r = audit_submission(s, p)
    assert "PRIVATE_" not in json.dumps(r)
    assert (
        not r["independent_human_review_completed"]
        and not r["assessments_changed"]
        and not r["metric_eligibility_changed"]
    )
    p["documents"][0]["source_url"] += "changed"
    with pytest.raises(ValueError):
        audit_submission(s, p)


@pytest.mark.parametrize("change", ["duplicate", "future", "missing_sha", "blank", "packet"])
def test_review_proposal_rejects_unbound_or_invalid_input(change):
    p, s = proposal()
    if change == "duplicate":
        s["adjudications"] *= 2
    if change == "future":
        s["reviewer"]["reviewed_at"] = "2999-01-01T00:00:00Z"
    if change == "missing_sha":
        s["adjudications"][0]["status"] = "affected"
    if change == "blank":
        s["reviewer"]["independence_statement"] = "  "
    if change == "packet":
        s["packet_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        audit_submission(s, p, datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert packet_sha256(p) == p["packet_sha256"]


def test_conditional_platform_rules_match_static_reader():
    import subprocess

    from infrastructure_impact.application.product_groups import definition as groups
    from infrastructure_impact.settings import PACKAGE

    cases = [
        {"product": "Junos OS Evolved", "platforms": p}
        for p in [["QFX5240"], ["SRX5000"], ["MX240"], [], ["SRX5000", "MX240"]]
    ]
    script = "const fs=require('fs'),vm=require('vm');let c={window:{},Set,Map,URL,Response,Blob};vm.createContext(c);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),c);let x=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(x.cases.map(a=>c.classifyProduct('juniper',a,x.taxonomy))));"
    output = subprocess.check_output(
        ["node", "-e", script, str(PACKAGE / "web/snapshot.js")],
        input=json.dumps({"cases": cases, "taxonomy": groups()}).encode(),
    )
    assert json.loads(output) == [classify("juniper", a) for a in cases]


def test_private_submission_cli_can_audit_saved_packet_without_database(
    tmp_path, monkeypatch, capsys
):
    from infrastructure_impact.cli import main

    p, s = proposal()
    packet = tmp_path / "packet.json"
    packet.write_text(json.dumps(p))
    submitted = tmp_path / "private.json"
    submitted.write_text(json.dumps(s))
    monkeypatch.setenv("IMPACT_DATABASE", str(tmp_path / "does-not-exist.sqlite3"))
    main(["validation", "--submission", str(submitted), "--packet-file", str(packet)])
    assert "PRIVATE_" not in capsys.readouterr().out
    assert not (tmp_path / "does-not-exist.sqlite3").exists()
