"""Synthetic Apstra editions must not exchange component, CVE or fix scope."""

import json

import pytest

from infrastructure_impact.adapters import juniper_apstra as apstra
from infrastructure_impact.application.component_studies import cell
from infrastructure_impact.application.families import definition
from infrastructure_impact.application.fix_leads import scoped_document
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.storage.repository import connect, ingest, latest


def document(planned=False):
    title = (
        "Juniper Apstra Version 5.0.0, 5.0.1 Release Notes"
        if planned
        else "Juniper Apstra Version 4.2.0 Release Notes"
    )
    issue = """OpenSSH Vulnerability CVE-2024-6387 in Apstra Server Version 4.2.x (AOS-47640)
    Apstra server version 4.2.x, which is based on Jammy Ubuntu 22.04 includes OpenSSH version
    8.9p1, is exposed to a security vulnerability identified as CVE-2024-6387.
    """
    if planned:
        issue += "Resolution\nApstra Server Version 4.2.2.1 and 5.0.0 will include a fixed OpenSSH package.\n"
        sibling = "USN-6891-1(Python vulnerabilities) from Tenable scan report (AOS-48042)"
    else:
        issue += """Workaround
        We recommend modifying the SSHD configuration according to the Ubuntu Security Team's
        guidance on CVE-2024-6387 to mitigate the risk. Contact Juniper Apstra Support for assistance.
        Set LoginGraceTime to 0 in /etc/ssh/sshd_config
        sudo systemctl restart sshd
        """
        sibling = "SSH Terrapin Vulnerability Workaround Using SSH aes128-gcm or aes256-gcm Ciphers Is Not Supported by Apstra Paramiko SSH Client (AOS-44336)"
    return (
        title
        + "\n04/17/2025 synthetic footer\nUnrelated CVE-2099-12345 issue.\n"
        + issue
        + sibling
        + "\nSynthetic sibling CVE-2023-48795; upgrade to 4.2.1.1; Python 9.9.9."
    )


def parse(monkeypatch, planned=False, edit=lambda value: value):
    monkeypatch.setattr(apstra, "pdf_text", lambda raw, layout=False: edit(document(planned)))
    return default_registry().normalize(
        b"%PDF synthetic Apstra",
        apstra.PLANNED_URL if planned else apstra.WORKAROUND_URL,
        "juniper",
    )


@pytest.mark.parametrize("planned", [False, True])
def test_explicit_server_scope_never_imports_sibling_fixes_or_cves(monkeypatch, planned):
    record = parse(monkeypatch, planned)
    assert record["cves"] == ["CVE-2024-6387"] and len(record["assessments"]) == 1
    claim = record["assessments"][0]
    assert claim["status"] == "affected" and claim["scope"] == "cve_specific"
    assert claim["product"] == "Apstra Server 4.2.x (Ubuntu 22.04)"
    assert claim["remediations"][0]["availability"] == (
        "planned" if planned else "partial_mitigation"
    )
    assert record["published_at"] is record["updated_at"] is None
    assert "4.2.1.1" not in json.dumps(claim) and "CVE-2023-48795" not in json.dumps(record)
    assert "CVE-2099-12345" not in json.dumps(record)
    if planned:
        assert "will include" in claim["remediations"][0]["details"]
        assert record["advisory_id"] == "Apstra-AOS-47640"
    else:
        assert "LoginGraceTime" in claim["remediations"][0]["details"]
        assert "4.2.2.1" not in json.dumps(claim)
        assert record["advisory_id"] == "Apstra-4.2.0-AOS-47640"


@pytest.mark.parametrize("planned", [False, True])
def test_component_reference_is_for_42_server_not_document_title_or_srx(monkeypatch, planned):
    record = parse(monkeypatch, planned)
    url = apstra.PLANNED_URL if planned else apstra.WORKAROUND_URL
    result = scoped_document(b"%PDF synthetic Apstra", url, "juniper")
    assert result["state"] == "scoped" and result["components"] == {"openssh": ["8.9p1"]}
    assert result["blocks"][0]["cves"] == ["CVE-2024-6387"]
    assert "4.2.x" in result["component_scope"] and "sibling issues" in result["component_scope"]
    assert "5.0.0" not in result["blocks"][0]["text"]
    family = next(f for f in definition()["families"] if f["id"] == "juniper-srx")
    result = cell({"records": [record]}, family, "CVE-2024-6387")
    assert result["state"] == "vendor_reference_without_family_assessment"
    assert (
        result["statements"] == 0 and result["explicit_statuses"] == [] and result["evidence"] == []
    )


@pytest.mark.parametrize("reverse", [False, True])
def test_document_editions_cannot_overwrite_each_other(monkeypatch, reverse):
    records = [parse(monkeypatch, False), parse(monkeypatch, True)]
    if reverse:
        records.reverse()
    with connect(":memory:") as db:
        for record in records:
            ingest(
                db,
                b"%PDF synthetic " + record["advisory_id"].encode(),
                record["source_url"],
                lambda *_, r=record: r,
                "juniper",
            )
        retained = latest(db)
    assert len(retained) == 2
    assert {r["assessments"][0]["remediations"][0]["availability"] for r in retained} == {
        "planned",
        "partial_mitigation",
    }


@pytest.mark.parametrize(
    "planned,old,new",
    [
        (False, "Juniper Apstra Version 4.2.0 Release Notes", "Different release notes"),
        (
            True,
            "Juniper Apstra Version 5.0.0, 5.0.1 Release Notes",
            "Juniper Apstra Version 4.2.0 Release Notes",
        ),
        (False, "OpenSSH version\n    8.9p1", "OpenSSH version\n    9.9p1"),
        (False, "Apstra server version 4.2.x", "Apstra server version 5.0.x"),
        (False, "(AOS-47640)", "(AOS-99999)"),
        (False, "(AOS-44336)", "(AOS-99998)"),
        (True, "(AOS-48042)", "(AOS-99997)"),
        (False, "Set LoginGraceTime to 0", "Set another parameter"),
        (True, "will include a fixed OpenSSH package", "include a fixed OpenSSH package"),
        (
            False,
            "sudo systemctl restart sshd",
            "sudo systemctl restart sshd Additional CVE-2099-22222 fix 4.2.1.1.",
        ),
    ],
)
def test_source_identity_scope_and_tense_changes_require_review(monkeypatch, planned, old, new):
    with pytest.raises(ValueError):
        parse(monkeypatch, planned, edit=lambda value: value.replace(old, new))


def test_duplicate_issue_and_alternate_parameters_require_review(monkeypatch):
    with pytest.raises(ValueError):
        parse(monkeypatch, edit=lambda value: value + "\n" + apstra.HEADING)
    monkeypatch.setattr(apstra, "pdf_text", lambda *_, **__: document())
    with pytest.raises(ValueError):
        apstra.apstra_advisory(b"%PDF synthetic", apstra.WORKAROUND_URL + "?other=1", "juniper")
    with pytest.raises(ValueError):
        apstra.apstra_advisory(b"%PDF synthetic", apstra.WORKAROUND_URL, "cisco")
    with pytest.raises(ValueError):
        apstra.apstra_advisory(b"<html>Loading shell</html>", apstra.WORKAROUND_URL, "juniper")
    assert (
        apstra.apstra_advisory(
            b"%PDF synthetic", "https://supportportal.juniper.net/unreviewed.pdf", "juniper"
        )
        is None
    )
