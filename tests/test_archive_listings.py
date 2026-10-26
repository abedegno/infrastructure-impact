"""Reviewed listing contracts, terminal-page detection and filter boundaries."""

from unittest.mock import patch

import pytest

from infrastructure_impact.collection.archive import progress, run
from infrastructure_impact.collection.config import validate_config
from infrastructure_impact.plugins import ArchivePage
from infrastructure_impact.plugins.archive_listings import arista, fortinet, paloalto
from infrastructure_impact.plugins.cisco import canonicalize
from infrastructure_impact.plugins.paloalto import resolve
from infrastructure_impact.storage.repository import connect, latest

ARISTA = "https://www.arista.com/en/support/advisories-notices"
PAN = "https://security.paloaltonetworks.com/"
FORTI = "https://www.fortiguard.com/psirt"


def arista_page(terminal=False):
    next_control = (
        '<li class="disabled"><a href="javascript:void(0);"><span class="pageNext">Next</span></a></li>'
        if terminal
        else '<li><a title="Next" href="/en/support/advisories-notices/securityadvisory?start=10"><span class="pageNext">Next</span></a></li>'
    )
    return (
        '<h2>Security Advisories</h2><h2><a href="/en/support/advisories-notices/security-advisory/123-security-advisory-0001">Security Advisory 0001</a></h2>'
        '<a href="/en/support/advisories-notices/end-of-sale">Unrelated notice</a>'
        '<div class="pagination"><ul>' + next_control + "</ul></div>"
    ).encode()


def pan_page(page=1, terminal=False):
    button = (
        '<button disabled="true"><div class="ico nsz right"></div></button>'
        if terminal
        else '<button onclick="var p = document.getElementById(\'page\');p.value=Number(p.value)+1.0;formSubmit()"><div class="ico nsz right"></div></button>'
    )
    return (
        f'<form id="chartForm" action="/" method="GET"><input name="page" value="{page}">'
        + button
        + '<table class="tbl salist"><tr><th>Summary</th></tr><tr><td><a href="/CVE-2025-12345">Example CVE</a></td></tr>'
        '<tr><td><a href="/PAN-SA-2025-0001">Example bulletin</a></td></tr></table>'
        + button
        + "</form>"
    ).encode()


def forti_page(page=1, terminal=False, product="FortiOS,FortiSwitch"):
    control = (
        '<li class="page-item"><span><span aria-hidden="true">»</span></span></li>'
        if terminal
        else f'<li class="page-item"><a aria-label="Next" href="/psirt?page={page + 1}&amp;product={product}&amp;date=">»</a></li>'
    )
    return (
        '<form action="/psirt" class="filters"><select name="product"><option selected value="FortiOS">FortiOS</option>'
        '<option selected value="FortiSwitch">FortiSwitch</option></select></form>'
        '<section class="table-body"><div id="fwb_id_1"><b>FG-IR-25-001 Example issue</b><b>CVE-2025-12345</b></div></section>'
        f'<ul class="pagination"><li class="page-item active">{page}</li>{control}</ul>'
    ).encode()


def test_arista_only_enumerates_advisory_headings_and_advertised_continuations():
    found = arista(arista_page(), ARISTA, "arista")
    assert found.entry_count == 1
    assert found.urls == (
        "https://www.arista.com/en/support/advisories-notices/security-advisory/123-security-advisory-0001",
    )
    assert found.next_pages == (
        "https://www.arista.com/en/support/advisories-notices/securityadvisory?start=10",
    )
    assert arista(arista_page(True), ARISTA, "arista").next_pages == ()
    with pytest.raises(ValueError, match="control"):
        arista(arista_page().replace(b"pageNext", b"changed"), ARISTA, "arista")


def test_pan_form_pagination_is_interpreted_without_running_javascript():
    found = paloalto(pan_page(), PAN, "paloalto")
    assert found.entry_count == 2 and len(found.urls) == 2
    assert found.next_pages == (PAN + "?page=2",)
    assert paloalto(pan_page(2, True), PAN + "?page=2", "paloalto").next_pages == ()
    with pytest.raises(ValueError, match="different page"):
        paloalto(pan_page(1), PAN + "?page=2", "paloalto")
    with pytest.raises(ValueError, match="changed"):
        paloalto(pan_page().replace(b"+1.0", b"+2.0"), PAN, "paloalto")
    with pytest.raises(ValueError, match="scope"):
        paloalto(pan_page(), PAN + "?product=PAN-OS", "paloalto")


def test_forti_canonical_ids_preserve_the_published_product_filter():
    found = fortinet(forti_page(), FORTI, "fortinet")
    assert found.urls == (FORTI + "/FG-IR-25-001",)
    assert found.next_pages == (FORTI + "?page=2&product=FortiOS,FortiSwitch&date=",)
    assert found.scope == "Published PSIRT product filter: FortiOS, FortiSwitch"
    assert (
        fortinet(
            forti_page(2, True), FORTI + "?page=2&product=FortiOS,FortiSwitch", "fortinet"
        ).next_pages
        == ()
    )
    with pytest.raises(ValueError, match="product scope"):
        fortinet(forti_page(product="FortiOS"), FORTI, "fortinet")
    with pytest.raises(ValueError, match="different page"):
        fortinet(forti_page(), FORTI + "?page=2", "fortinet")
    with pytest.raises(ValueError, match="control"):
        fortinet(forti_page().replace("»".encode(), b"changed"), FORTI, "fortinet")


@pytest.mark.parametrize("parser,url", [(arista, ARISTA), (paloalto, PAN), (fortinet, FORTI)])
def test_application_shell_or_empty_page_is_not_exhaustion(parser, url):
    with pytest.raises(ValueError):
        parser(b"<html><title>Application shell</title></html>", url, "example")


def test_cisco_archive_urls_remain_exact_instead_of_inventing_mixed_case_api_routes():
    url = "https://www.cisco.com/.well-known/csaf/2025/cisco-sa-example-abc123.json"
    assert canonicalize(url) == url
    assert (
        canonicalize(
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/example"
        )
        == "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/example"
    )


def test_pan_bulletin_uses_advertised_csaf_and_preserves_reviewed_html_tables():
    url = PAN + "PAN-SA-2025-0001"
    raw = b'<a href="/csaf/PAN-SA-2025-0001">CSAF</a>'
    requested = []
    assert resolve(raw, url, lambda u: requested.append(u) or b"{}") == (
        PAN + "csaf/PAN-SA-2025-0001",
        b"{}",
    )
    assert requested == [PAN + "csaf/PAN-SA-2025-0001"]
    special = b"<h1>OSS CVEs Fixed in PAN-OS</h1>" + raw
    assert resolve(
        special, url, lambda _: pytest.fail("HTML qualification table must be retained")
    ) == (url, special)
    with pytest.raises(ValueError):
        resolve(
            b'<a href="https://untrusted.example/csaf/PAN-SA-2025-0001">CSAF</a>',
            url,
            lambda _: pytest.fail("Unreviewed URL"),
        )


def test_listing_hook_keeps_queue_resume_scope_and_discovery_provenance(tmp_path):
    path = tmp_path / "vault.sqlite3"
    config = {
        "vendors": [],
        "archives": [
            {
                "vendor": "arista",
                "kind": "listing",
                "url": ARISTA,
                "page_limit": 1,
                "document_limit": 1,
            }
        ],
    }
    # An interrupted page can resume through the same queue and evidence tables.
    with (
        patch("infrastructure_impact.collection.archive.fetch", return_value=arista_page()),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("synthetic error"),
        ),
    ):
        assert run(config, path) == (0, 1)
    with connect(path) as db:
        status = progress(db, latest(db), config)[0]
        assert status["pages"]["pending"] == 1
        assert status["documents"]["error"] == 1
        assert status["observed_scopes"] == [
            "Public Security Advisories listing; security-advisory headings only"
        ]
        assert db.execute("SELECT count(*) FROM archive_links").fetchone()[0] == 2
        assert not status["known_queue_exhausted"]
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_archivepage_contract_and_plugin_registration_guard_the_extension_boundary():
    with pytest.raises(ValueError):
        ArchivePage(("https://example.test/x",), 0)
    with pytest.raises(ValueError):
        ArchivePage((), True)
    with pytest.raises(ValueError):
        ArchivePage(("https://example.test/x",), 1, scope=123)
    with pytest.raises(ValueError, match="reviewed plugin"):
        validate_config(
            {
                "vendors": [],
                "archives": [
                    {
                        "vendor": "aruba",
                        "kind": "listing",
                        "url": "https://csaf.arubanetworking.hpe.com/",
                    }
                ],
            }
        )


def test_default_two_page_budget_refreshes_root_while_traversing_old_pages(tmp_path):
    path = tmp_path / "vault.sqlite3"
    config = {
        "vendors": [],
        "archives": [
            {
                "vendor": "arista",
                "kind": "listing",
                "url": ARISTA,
                "page_limit": 2,
                "document_limit": 1,
            }
        ],
    }
    requested = []

    def fetch(db, url, vendor):
        requested.append(url)
        if url == ARISTA:
            return arista_page()
        start = int(url.split("start=")[1])
        return arista_page().replace(b"?start=10", ("?start=" + str(start + 10)).encode())

    with (
        patch("infrastructure_impact.collection.archive.fetch", side_effect=fetch),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("synthetic error"),
        ),
    ):
        run(config, path)
        run(config, path)
    assert requested == [
        ARISTA,
        ARISTA + "/securityadvisory?start=10",
        ARISTA,
        ARISTA + "/securityadvisory?start=20",
    ]
