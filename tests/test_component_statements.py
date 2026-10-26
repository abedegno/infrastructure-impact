"""Synthetic boundaries for release-scoped component references and access shells."""

import json

import pytest

from infrastructure_impact.adapters.component_statements import (
    HPE_URL,
    JUNIPER_URL,
    hpe_component_statement,
    juniper_component_statement,
)
from infrastructure_impact.application.disclosure import import_release_note
from infrastructure_impact.application.fix_leads import evidence_inputs, leads, public_inputs
from infrastructure_impact.collection.errors import (
    AccessVerificationRequired,
    check_access_response,
)
from infrastructure_impact.storage.repository import connect


def juniper(target="9.4", announced=None):
    return f"<h1>Authentication and Access Control</h1><ul><li>OpenSSH upgrade to version {announced or target} (ACX-EXAMPLE, PTX-EXAMPLE) —Starting in Junos OS Evolved Release 24.2R1, we've upgraded the version of OpenSSH from 7.5 to {target}. The following SSH changes are a result of this upgrade.</li></ul>".encode()


def hpe(target="3.0.12"):
    return f"<h1>Enhancements</h1><div>The following enhancements are part of iLO 6 1.57 release:<ul><li>Upgradation of OpenSSL from v1.0.2 to v{target}.</li></ul></div>".encode()


def test_destination_versions_are_separate_from_prior_versions_and_other_products():
    j = juniper_component_statement(juniper(), JUNIPER_URL, "juniper")
    h = hpe_component_statement(hpe(), HPE_URL, "hpe")
    assert j["components"] == {"openssh": ["9.4"]}
    assert h["components"] == {"openssl": ["3.0.12"]}
    assert (
        "ACX-EXAMPLE" in j["component_scope"]
        and "Not a Junos OS or SRX-wide" in j["component_scope"]
    )
    assert (
        "not established" in h["component_scope"]
        and "not a complete manifest" in h["component_scope"]
    )


@pytest.mark.parametrize("mutation", ["heading", "release", "mismatch", "duplicate"])
def test_junos_identity_release_and_version_agreement_are_required(mutation):
    raw = juniper()
    if mutation == "heading":
        raw = raw.replace(b"Authentication and Access Control", b"Navigation")
    if mutation == "release":
        raw = raw.replace(b"24.2R1", b"23.4R1")
    if mutation == "mismatch":
        raw = juniper(announced="9.5")
    if mutation == "duplicate":
        raw += juniper().split(b"</h1>", 1)[1]
    with pytest.raises(ValueError):
        juniper_component_statement(raw, JUNIPER_URL, "juniper")


def test_ilo_route_release_and_literal_upgrade_syntax_are_required():
    assert hpe_component_statement(hpe(), "https://support.hpe.com/unrelated", "hpe") is None
    for raw, url in [
        (hpe().replace(b"1.57 release", b"1.78 release"), HPE_URL),
        (hpe().replace(b"Upgradation of", b"Not using"), HPE_URL),
        (hpe(), HPE_URL + "&other=1"),
    ]:
        with pytest.raises(ValueError):
            hpe_component_statement(raw, url, "hpe")


def test_same_source_component_change_keeps_fingerprints_without_a_cve_or_hidden_fix():
    with connect(":memory:") as db:
        for raw in [hpe(), hpe("3.0.13")]:
            import_release_note(db, raw, HPE_URL, "hpe", "iLO 6 1.57 enhancement reference")
        inputs = public_inputs(evidence_inputs(db), [HPE_URL], [])
    report = leads(dict(research=dict(lead_inputs=inputs)))
    assert len(report["leads"]) == 1
    lead = report["leads"][0]
    assert lead["kind"] == "component_version_changed" and lead["component"] == "openssl"
    assert lead["cve_ids"] == [] and lead["concealment"] == "not_established"
    assert len({e["source_sha256"] for e in lead["evidence"]}) == 2
    assert "3.0.12" in lead["details"] and "3.0.13" in lead["details"]


def test_platform_scope_changes_cannot_masquerade_as_component_changes():
    with connect(":memory:") as db:
        import_release_note(db, juniper(), JUNIPER_URL, "juniper", "Evolved reference")
        import_release_note(
            db,
            juniper("9.5").replace(b"ACX-EXAMPLE", b"OTHER-PLATFORM"),
            JUNIPER_URL,
            "juniper",
            "Evolved reference",
        )
        inputs = public_inputs(evidence_inputs(db), [JUNIPER_URL], [])
    report = leads(dict(research=dict(lead_inputs=inputs)))
    assert not report["leads"] and any(
        g["reason"] == "component_scope_changed_requires_review" for g in report["analysis_gaps"]
    )


def test_session_check_shell_is_an_access_gap_not_valid_document_content():
    shell = b'<!DOCTYPE html><html><script>function checkSession(url){} function syncNothing(){} var url="https://auth.hpe.com/api/v1/sessions/me";</script><body onload="main();"></body></html>'
    with pytest.raises(AccessVerificationRequired):
        check_access_response(shell)
    check_access_response(hpe())
    assert "sessions/me" not in json.dumps(hpe_component_statement(hpe(), HPE_URL, "hpe"))
