"""Authored fixtures for reviewed SA-0099 grouping and SA-0103 representations."""

import json
from hashlib import sha256
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from infrastructure_impact.application.replay import normalized_record, replay_report
from infrastructure_impact.collection.service import resolve_document, retain_resolution, run
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.storage.repository import connect, evidence, ingest, latest
from infrastructure_impact.storage.source_selections import latest as choices

PREFIX = "https://www.arista.com/en/support/advisories-notices/security-advisory/"
URL99 = PREFIX + "19862-security-advisory-0099"
URL103 = PREFIX + "19917-security-advisory-0103"
CSAF = "https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_103.json"
TRACKING = "Arista Networks Security Advisory 103"
RANGES90 = [f"4.{n}.1M and below releases in the 4.{n}.x train" for n in range(20, 26)]
RANGES92 = [f"4.{n}.2M and below releases in the 4.{n}.x train" for n in range(30, 38)]
RANGES103 = [f"4.{n}.3F and below releases in the 4.{n}.x train." for n in range(40, 44)]


def version_list(values):
    return "<div><b>EOS Versions</b></div><ul>" + "".join(f"<li>{v}</li>" for v in values) + "</ul>"


def html(number="0099", *, reverse=False):
    ids = ["CVE-2024-27892", "CVE-2024-27890"] if number == "0099" else ["CVE-2024-6858"]
    if reverse:
        ids.reverse()
    tracking = "".join(
        f"<p>The CVE-ID tracking this issue: {cid}<br>CVSS score: 6.5</p>" for cid in ids
    )
    software = (
        "<p>The following EOS versions <b>are</b> affected for CVE-2024-27890</p>"
        + version_list(RANGES90)
        + "<p>The following EOS versions <b>are</b> affected for CVE-2024-27892</p>"
        + version_list(RANGES92)
        if number == "0099"
        else version_list(RANGES103)
    )
    link = f'<a title="Download CSAF" href="{CSAF}">CSAF</a>' if number == "0103" else ""
    return f"""<nav>CVE-2099-11111</nav><meta content="CVE-2099-22222">
    <div class="item-page"><div class="page-header"><h2 class="pageTitle">Security Advisory {number} {link} <a>PDF</a></h2></div>
    <table><tr><td>Revision</td><td>Date</td><td>Changes</td></tr><tr><td>1.0</td><td>July 23, 2024</td><td>Initial release</td></tr></table>
    {tracking}<h2>Description</h2><p>Unrelated reference CVE-2099-33333.</p>
    <h2>Vulnerability Assessment</h2><h3>Affected Software</h3>{software}
    <h3>Affected Platforms</h3><p>Only listed platforms with the required configuration.</p>
    <h3>Required Configuration for Exploitation</h3><p>OpenConfig must be enabled; SSL is required for CVE-2024-27892.</p>
    <h2>Resolution</h2><p>Consult the publisher; this fixture supplies no remediation.</p>
    </div><footer>CVE-2099-44444</footer>""".encode()


def csaf(*, cid="CVE-2023-5501", status="draft", tracking=TRACKING):
    return json.dumps(
        {
            "document": {
                "title": "Synthetic representation",
                "tracking": {
                    "id": tracking,
                    "status": status,
                    "initial_release_date": "2024-07-17T18:48:35Z",
                },
            },
            "product_tree": {"full_product_names": [{"product_id": "eos", "name": "Arista EOS"}]},
            "vulnerabilities": [
                {
                    "cve": cid,
                    "product_status": {"known_affected": ["eos"]},
                    "remediations": [
                        {
                            "category": "vendor_fix",
                            "details": "Alternate-only fix",
                            "product_ids": ["eos"],
                        }
                    ],
                }
            ],
        }
    ).encode()


def normalize(raw, url):
    return default_registry().normalize(raw, url, "arista")


@pytest.mark.parametrize("reverse", [False, True])
def test_local_tracking_and_groups_bind_exact_six_and_eight_ranges(reverse):
    document = normalize(html(reverse=reverse), URL99)
    assert document["cves"] == ["CVE-2024-27890", "CVE-2024-27892"]
    claims = {a["cve_id"]: a for a in document["assessments"]}
    assert {cid: [v["expression"] for v in a["versions"]] for cid, a in claims.items()} == {
        "CVE-2024-27890": RANGES90,
        "CVE-2024-27892": RANGES92,
    }
    assert len({a["evidence_locator"] for a in claims.values()}) == 2
    for cid, claim in claims.items():
        assert cid in claim["evidence_locator"]
        assert claim["scope"] == "cve_specific"
        assert "OpenConfig must be enabled" in json.dumps(claim["exposure"])
        assert claim["remediations"] == []


@pytest.mark.parametrize(
    "before,after",
    [
        (
            b"The following EOS versions <b>are</b> affected for CVE-2024-27890",
            b"Unknown EOS group CVE-2024-27890",
        ),
        (b"<p>The following EOS versions <b>are</b> affected for CVE-2024-27890</p>", b""),
        (b"affected for CVE-2024-27890", b"affected for CVE-2099-12345"),
        (
            b"<div><b>EOS Versions</b></div><ul>",
            b"<h4>Unknown subgroup</h4><div><b>EOS Versions</b></div><ul>",
        ),
        (b"<li>4.20.1M", b"<li><ul><li>nested</li></ul>4.20.1M"),
        (b"<p>The CVE-ID tracking this issue: CVE-2024-27890<br>CVSS score: 6.5</p>", b""),
        (b"Security Advisory 0099", b"Security Advisory 0100"),
        (b"</ul><p>The following", b"</ul><h3>Other section</h3><p>The following"),
    ],
)
def test_unknown_missing_foreign_or_cross_heading_grouping_fails_closed(before, after):
    with pytest.raises(ValueError):
        normalize(html().replace(before, after), URL99)


@pytest.mark.parametrize("entry", [URL103, CSAF])
@pytest.mark.parametrize("status", ["draft", "final"])
def test_contradictory_alternate_selects_literal_html_with_bounded_issue(entry, status):
    bodies = {URL103: html("0103"), CSAF: csaf(status=status)}
    with connect(":memory:") as db:
        resolved = resolve_document(
            db, entry, "arista", fetcher=lambda db, url, vendor: bodies[url]
        )
        assert tuple(resolved) == (URL103, bodies[URL103])
        assert resolved.source_failures == 1
        retain_resolution(db, "arista", entry, resolved)
        choice = choices(db)[0]
        assert choice["requested_url"] == entry
        assert [(v["source_url"], v["source_sha256"]) for v in choice["views"]] == [
            (URL103, sha256(bodies[URL103]).hexdigest())
        ]
        assert choice["unavailable"] == [
            {"source_url": CSAF, "error_code": "unsupported_or_invalid_document"}
        ]
        document = normalize(resolved[1], resolved[0])
        assert document["advisory_id"] == "19917-security-advisory-0103"
        assert document["cves"] == ["CVE-2024-6858"]
        assert [v["expression"] for v in document["assessments"][0]["versions"]] == RANGES103
        assert "Alternate-only fix" not in json.dumps(document)
        assert "CVE-2023-5501" not in json.dumps(document)


@pytest.mark.parametrize("entry", [URL103, CSAF])
def test_matching_scope_accepts_explicit_literal_advisory_id_pair(entry):
    bodies = {URL103: html("0103"), CSAF: csaf(cid="CVE-2024-6858", status="final")}
    with connect(":memory:") as db:
        result = resolve_document(db, entry, "arista", fetcher=lambda db, url, vendor: bodies[url])
        assert tuple(result) == (URL103, bodies[URL103])
        assert not result.selection.unavailable
        assert result.selection.alternatives[0].raw == bodies[CSAF]
        assert structured(bodies[CSAF], CSAF, "arista")["advisory_id"] == TRACKING


@pytest.mark.parametrize("failure", ["http", "json", "id"])
def test_alternate_failure_preserves_valid_primary_without_raw_diagnostics(failure):
    def fetch(db, url, vendor):
        if url == URL103:
            return html("0103")
        if failure == "http":
            raise HTTPError(url, 503, "RAW_DIAGNOSTIC", {}, None)
        return (
            b"{RAW_DIAGNOSTIC"
            if failure == "json"
            else csaf(tracking="Arista Networks Security Advisory 104")
        )

    with connect(":memory:") as db:
        result = resolve_document(db, URL103, "arista", fetcher=fetch)
        assert tuple(result) == (URL103, html("0103"))
        assert len(result.selection.unavailable) == 1
        retain_resolution(db, "arista", URL103, result)
        assert "RAW_DIAGNOSTIC" not in json.dumps(choices(db))


@pytest.mark.parametrize(
    "before,after",
    [
        (b"Security Advisory 0103", b"Security Advisory 0104"),
        (b"tracking this issue: CVE-2024-6858", b"tracking this issue: CVE-2023-5501"),
        (CSAF.encode(), CSAF.replace("_103.json", "_104.json").encode()),
        (b"<div><b>EOS Versions</b></div>", b"<div>Other Versions</div>"),
    ],
)
def test_unreviewed_primary_identity_or_pairing_fails_closed(before, after):
    raw = html("0103").replace(before, after)
    with connect(":memory:") as db, pytest.raises(ValueError):
        resolve_document(
            db, URL103, "arista", fetcher=lambda db, url, vendor: raw if url == URL103 else csaf()
        )


def test_other_route_retains_existing_structured_policy():
    url = CSAF.replace("_103.json", "_104.json")
    assert normalize(csaf(tracking="Arista Networks Security Advisory 104"), url)["cves"] == [
        "CVE-2023-5501"
    ]


@pytest.mark.parametrize("cid", ["CVE-2023-5501", "CVE-2024-6858"])
def test_direct_normalization_requires_reviewed_selection_instead_of_new_csaf_identity(cid):
    with pytest.raises(ValueError, match="selection"):
        normalize(csaf(cid=cid), CSAF)


def test_both_collection_entries_retain_one_html_primary_and_selection_provenance(tmp_path):
    path = tmp_path / "collection.sqlite"
    bodies = {URL103: html("0103"), CSAF: csaf()}
    with patch(
        "infrastructure_impact.collection.service.fetch",
        side_effect=lambda db, url, vendor: bodies[url],
    ):
        assert run(
            {"vendors": [], "pinned": [{"vendor": "arista", "url": u} for u in (URL103, CSAF)]},
            db_path=path,
        ) == (1, 2)
    with connect(path) as db:
        records = latest(db)
        assert len(records) == 1
        assert records[0]["cves"] == ["CVE-2024-6858"]
        assert records[0]["source_url"] == URL103
        assert records[0]["sha256"] == sha256(bodies[URL103]).hexdigest()
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 1
        assert len(choices(db)) == 2


def test_replay_rejects_legacy_wrong_csaf_identity_and_preserves_corrected_html(tmp_path):
    path = tmp_path / "replay.sqlite"
    registry = default_registry()
    with connect(path) as db:
        old = registry.finalize(structured(csaf(), CSAF, "arista"), CSAF, "arista")
        old["adapter_version"] = "old-synthetic-parser"
        ingest(db, csaf(), CSAF, lambda *_: old, "arista")
        ingest(db, html("0103"), URL103, lambda *_: normalize(html("0103"), URL103), "arista")
        evidence(db, csaf(), CSAF)
        record = next(r for r in latest(db) if r["source_url"] == CSAF)
        with pytest.raises(ValueError, match="selection"):
            normalized_record(registry, record, csaf())
    report = replay_report(dry_run=True, db_path=path, vendor="arista", force=True)
    assert report["failed"] == 1
    assert report["failures"][0]["advisory_id"] == TRACKING
    assert report["failures"][0]["error_code"] == "unsupported_or_invalid_document"
    with connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 2
        assert next(r for r in latest(db) if r["source_url"] == URL103)["cves"] == ["CVE-2024-6858"]


def test_legacy_research_bypass_cannot_make_fresh_wrong_csaf_claims():
    from infrastructure_impact.application.switching_evidence import inputs

    registry = default_registry()
    with connect(":memory:") as db:
        old = registry.finalize(structured(csaf(), CSAF, "arista"), CSAF, "arista")
        ingest(db, csaf(), CSAF, lambda *_: old, "arista")
        result = inputs(db, latest(db))
        assert result["claims"] == []
        assert "reviewed_html_selection_required" in result["issues"]


@pytest.mark.parametrize(
    "number,url,expected",
    [
        ("0099", URL99, {"CVE-2024-27890": RANGES90, "CVE-2024-27892": RANGES92}),
        ("0103", URL103, {"CVE-2024-6858": RANGES103}),
    ],
)
def test_corrected_html_research_claims_preserve_local_cve_ranges(number, url, expected):
    registry = default_registry()
    raw = html(number)
    result = registry.research_evidence(raw, url, "arista", normalize(raw, url))
    assert {c["cve_id"]: c["version_expressions"] for c in result["claims"]} == expected
    assert all(c["family"] == "arista-eos" and c["named_platforms"] == [] for c in result["claims"])


def test_single_header_paragraph_can_explicitly_track_both_local_groups():
    raw = (
        html()
        .replace(
            b"<p>The CVE-ID tracking this issue: CVE-2024-27892<br>CVSS score: 6.5</p>",
            b"<p>The CVE-ID tracking this issue: CVE-2024-27892 and CVE-2024-27890</p>",
        )
        .replace(b"<p>The CVE-ID tracking this issue: CVE-2024-27890<br>CVSS score: 6.5</p>", b"")
    )
    document = normalize(raw, URL99)
    assert {
        a["cve_id"]: [v["expression"] for v in a["versions"]] for a in document["assessments"]
    } == {
        "CVE-2024-27890": RANGES90,
        "CVE-2024-27892": RANGES92,
    }


def test_generic_product_releases_groups_and_single_cve_remain_compatible():
    raw = html().replace(b"EOS versions <b>are</b>", b"product releases are")
    grouped = normalize(raw, PREFIX + "synthetic-security-advisory-9998")
    assert {
        a["cve_id"]: [v["expression"] for v in a["versions"]] for a in grouped["assessments"]
    } == {
        "CVE-2024-27890": RANGES90,
        "CVE-2024-27892": RANGES92,
    }
    single = normalize(html("0103"), PREFIX + "synthetic-security-advisory-9999")
    assert single["cves"] == ["CVE-2024-6858"]
    assert [v["expression"] for v in single["assessments"][0]["versions"]] == RANGES103


@pytest.mark.parametrize("entry", [URL103, CSAF])
def test_offline_retained_cache_resolution_uses_html_without_writes(tmp_path, entry):
    from infrastructure_impact.collection.retained import retained_fetch

    path = tmp_path / "cache.sqlite"
    with connect(path) as db:
        evidence(db, html("0103"), URL103)
        evidence(db, csaf(), CSAF)
    with connect(path, read_only=True) as db:
        result = resolve_document(db, entry, "arista", fetcher=retained_fetch)
        assert tuple(result) == (URL103, html("0103"))
        assert normalize(result[1], result[0])["cves"] == ["CVE-2024-6858"]
        assert len(result.selection.unavailable) == 1
        assert not db.execute("SELECT 1 FROM revisions").fetchone()
        assert not db.execute("SELECT 1 FROM source_selections").fetchone()
        assert not db.execute("SELECT 1 FROM collection_runs").fetchone()


def test_direct_csaf_with_unavailable_html_cannot_create_wrong_primary():
    def fetch(db, url, vendor):
        if url == CSAF:
            return csaf()
        raise HTTPError(url, 503, "unavailable", {}, None)

    with connect(":memory:") as db, pytest.raises(HTTPError):
        resolve_document(db, CSAF, "arista", fetcher=fetch)


@pytest.mark.parametrize("entry", [URL103, CSAF])
def test_reviewed_html_route_returning_structured_data_fails_closed(entry):
    with connect(":memory:") as db, pytest.raises(ValueError):
        resolve_document(db, entry, "arista", fetcher=lambda *_: csaf())


def test_csaf_link_outside_reviewed_article_header_cannot_supply_pairing():
    link = f'<a title="Download CSAF" href="{CSAF}">CSAF</a>'.encode()
    raw = html("0103").replace(link, b"") + link
    with connect(":memory:") as db, pytest.raises(ValueError, match="pairing"):
        resolve_document(
            db, URL103, "arista", fetcher=lambda db, url, vendor: raw if url == URL103 else csaf()
        )
