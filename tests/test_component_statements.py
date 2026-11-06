"""Synthetic boundaries for release-scoped component references and access shells."""

import json
from email.message import Message
from hashlib import sha256
from io import BytesIO
from urllib.request import HTTPSHandler, build_opener
from urllib.response import addinfourl

import pytest

from infrastructure_impact.adapters.component_statements import (
    HPE_URL,
    JUNIPER_URL,
    hpe_component_statement,
    juniper_component_statement,
)
from infrastructure_impact.application.disclosure import import_release_note
from infrastructure_impact.application.fix_leads import evidence_inputs, leads, public_inputs
from infrastructure_impact.collection import transport
from infrastructure_impact.collection.errors import (
    AccessVerificationRequired,
    check_access_response,
)
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.source_policy import allowed
from infrastructure_impact.storage.repository import connect

CANONICAL_JUNIPER_URL = JUNIPER_URL.replace(
    "https://www.juniper.net", "https://networkingdocs.hpe.com"
)


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
        default_registry().normalize_component_inventory(raw, JUNIPER_URL, "juniper")


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


@pytest.mark.parametrize(
    "url",
    [
        CANONICAL_JUNIPER_URL.replace("https:", "http:"),
        CANONICAL_JUNIPER_URL.replace("https://", "https://user@"),
        CANONICAL_JUNIPER_URL.replace("https://", "https://user:password@"),
        CANONICAL_JUNIPER_URL.replace("https://", "https://@"),
        CANONICAL_JUNIPER_URL.replace("hpe.com/", "hpe.com:443/"),
        CANONICAL_JUNIPER_URL.replace("hpe.com/", "hpe.com:444/"),
        CANONICAL_JUNIPER_URL + "?changed=1",
        CANONICAL_JUNIPER_URL + "?",
        CANONICAL_JUNIPER_URL + "#section",
        CANONICAL_JUNIPER_URL + "#",
        CANONICAL_JUNIPER_URL + "/",
        CANONICAL_JUNIPER_URL.replace("24.2r1", "24.2r2"),
        CANONICAL_JUNIPER_URL.replace("authentication-access-control", "other-feature"),
        CANONICAL_JUNIPER_URL.replace(
            "networkingdocs.hpe.com", "networkingdocs.hpe.com.evil.example"
        ),
        CANONICAL_JUNIPER_URL.replace("networkingdocs.hpe.com", "sub.networkingdocs.hpe.com"),
        CANONICAL_JUNIPER_URL.replace("networkingdocs.hpe.com", "networkingdocs-hpe.com"),
        CANONICAL_JUNIPER_URL.replace("networkingdocs.hpe.com", "support.hpe.com"),
        CANONICAL_JUNIPER_URL.replace("networkingdocs.hpe.com", "NETWORKINGDOCS.HPE.COM"),
        CANONICAL_JUNIPER_URL.replace("/documentation/", "/%64ocumentation/"),
        CANONICAL_JUNIPER_URL.replace("/documentation/", "/documentation%2f"),
        CANONICAL_JUNIPER_URL.replace("/documentation/", "/documentation/../documentation/"),
    ],
)
def test_juniper_canonical_transport_rejects_every_nonexact_identity(url):
    assert not allowed(url, "juniper")


def test_juniper_canonical_route_and_existing_routes_remain_allowed():
    assert allowed(CANONICAL_JUNIPER_URL, "juniper")
    assert allowed(JUNIPER_URL, "juniper")
    # HPE and Aruba already allow this host; their existing policies stay unchanged.
    assert allowed(CANONICAL_JUNIPER_URL, "hpe")
    assert allowed(CANONICAL_JUNIPER_URL, "aruba")
    assert allowed("https://supportportal.juniper.net/s/article/synthetic", "juniper")
    assert allowed("https://cveawg.mitre.org/api/cve/CVE-2099-12345", "juniper")
    for vendor in default_registry().names().keys() - {"juniper", "hpe", "aruba"}:
        assert not allowed(CANONICAL_JUNIPER_URL, vendor)
    assert not allowed(CANONICAL_JUNIPER_URL, "upstream")


def install_juniper_https_chain(monkeypatch, routes):
    """Replace only the HTTPS wire; retain urllib and transport redirect policy."""
    requested = []

    class SyntheticHTTPS(HTTPSHandler):
        def https_open(self, request):
            url = request.full_url
            requested.append(url)
            status, fields, raw = routes[url]
            headers = Message()
            for name, value in fields.items():
                headers[name] = value
            response = addinfourl(BytesIO(raw), headers, url, status)
            response.msg = "Synthetic HTTPS response"
            return response

    monkeypatch.setattr(
        transport, "build_opener", lambda *handlers: build_opener(*handlers, SyntheticHTTPS())
    )
    return requested


def test_juniper_canonical_redirect_retains_original_component_binding_and_evidence(monkeypatch):
    raw = juniper()
    requested = install_juniper_https_chain(
        monkeypatch,
        {
            JUNIPER_URL: (301, {"Location": CANONICAL_JUNIPER_URL}, b""),
            CANONICAL_JUNIPER_URL: (200, {"Content-Type": "text/html"}, raw),
        },
    )
    registry = default_registry()
    with connect(":memory:") as db:
        fetched = transport.fetch(db, JUNIPER_URL, "juniper")
        component = registry.normalize_component_inventory(fetched, JUNIPER_URL, "juniper")
        retained = db.execute("SELECT * FROM evidence").fetchall()
        assert len(retained) == 1
        assert retained[0]["source_url"] == JUNIPER_URL
        assert retained[0]["raw"] == raw == fetched
        assert retained[0]["sha256"] == sha256(raw).hexdigest()
        observation = db.execute("SELECT * FROM source_observations").fetchone()
        assert observation["source_url"] == JUNIPER_URL
        assert observation["evidence_id"] == retained[0]["id"]
        assert observation["http_status"] == 200
        cache = db.execute("SELECT * FROM http_cache").fetchone()
        assert cache["url"] == JUNIPER_URL and cache["evidence_id"] == retained[0]["id"]
        assert not db.execute("SELECT 1 FROM revisions").fetchone()
        assert not db.execute("SELECT 1 FROM documents").fetchone()
    assert requested == [JUNIPER_URL, CANONICAL_JUNIPER_URL]
    assert component["state"] == "scoped"
    assert component["components"] == {"openssh": ["9.4"]}
    assert "Junos OS Evolved 24.2R1" in component["component_scope"]
    assert "ACX-EXAMPLE, PTX-EXAMPLE" in component["component_scope"]
    assert component["blocks"][0]["cves"] == []
    assert "assessments" not in component
    assert registry.normalize_component_inventory(raw, CANONICAL_JUNIPER_URL, "juniper") is None
    assert registry.normalize_component_inventory(raw, CANONICAL_JUNIPER_URL, "hpe") is None


@pytest.mark.parametrize(
    "unsafe", ["https://attacker.example/substitute", CANONICAL_JUNIPER_URL + "?changed=1"]
)
def test_juniper_canonical_second_redirect_is_blocked_before_fetch_or_retention(
    monkeypatch, unsafe
):
    requested = install_juniper_https_chain(
        monkeypatch,
        {
            JUNIPER_URL: (301, {"Location": CANONICAL_JUNIPER_URL}, b""),
            CANONICAL_JUNIPER_URL: (302, {"Location": unsafe}, b""),
            unsafe: (200, {"Content-Type": "text/html"}, juniper()),
        },
    )
    with connect(":memory:") as db:
        with pytest.raises(ValueError, match="Cross-domain redirect outside vendor allowlist"):
            transport.fetch(db, JUNIPER_URL, "juniper")
        assert requested == [JUNIPER_URL, CANONICAL_JUNIPER_URL]
        for table in ("evidence", "http_cache", "source_observations", "revisions", "documents"):
            assert not db.execute(f"SELECT 1 FROM {table}").fetchone()
