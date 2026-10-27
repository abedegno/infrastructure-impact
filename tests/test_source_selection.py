"""Reviewed source selection preserves scope without silently merging representations."""

import json
import sqlite3
from copy import deepcopy
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from infrastructure_impact.adapters.cisco_campaign import (
    ADVISORY_ID,
    CVE,
    TITLE,
    URL,
    parse_campaign,
)
from infrastructure_impact.application.publication import public_projection
from infrastructure_impact.application.query import state
from infrastructure_impact.collection.service import resolve_document, retain_resolution, run
from infrastructure_impact.plugins import SourceSelection, SourceView, SourceViewIssue
from infrastructure_impact.storage.repository import connect, health, latest
from infrastructure_impact.storage.source_selections import latest as choices

CSAF_URL = URL + "/csaf/" + ADVISORY_ID + ".json"


def html():
    return f'''<html><h1 class="headline">{TITLE}</h1>
    <p>Advisory ID: {ADVISORY_ID} First Published: 2024 July 2 16:00 GMT
    Last Updated: 2024 September 13 14:43 GMT Version 1.16: Final {CVE}</p>
    <h2>Summary</h2><p>Synthetic review example</p><h2>Affected Products</h2>
    <div id="vulnerableproducts"><p>The following table lists Cisco products that are affected</p>
    <table><tr><th>Product</th><th>Cisco Bug ID</th><th>Fixed Release Availability</th></tr>
    <tr><td class="categoryheader" colspan="3">Network and Content Security Devices</td></tr>
    <tr><td>Adaptive Security Appliance (ASA) Software</td><td>CSCexample1</td><td>1.2.3<br>2.0 (Oct 2024)</td></tr>
    <tr><td>Firepower Threat Defense (FTD) Software</td><td>CSCexample2</td><td>Consult the Cisco bug ID for details</td></tr></table>
    <p>Background footnote CVE-2006-5051 is not another current campaign CVE.</p></div>
    <div id="productsconfirmednotvulnerable"><p>Cisco has confirmed that this vulnerability does not affect the following Cisco products</p>
    <p>Wireless</p><ul><li>Example Listed Product</li></ul>
    <p>Cisco Cloud Hosted Services</p><ul><li>Example Listed Product</li></ul></div>
    <h2>Unrelated content</h2><ul><li>Unrelated unlisted product</li></ul>
    <a href="{CSAF_URL}">Download CSAF</a><p>PRIVATE_RAW_SENTINEL</p></html>'''.encode()


def csaf():
    return json.dumps(
        {
            "document": {
                "title": "Synthetic campaign counterpart",
                "tracking": {"id": ADVISORY_ID, "status": "final"},
            },
            "product_tree": {
                "full_product_names": [{"name": "Cisco Example SD-WAN", "product_id": "sdwan"}]
            },
            "vulnerabilities": [{"cve": CVE, "product_status": {"known_affected": ["sdwan"]}}],
        }
    ).encode()


def fetcher(db, target, vendor):
    return {URL: html(), CSAF_URL: csaf()}[target]


def collected_resolution(db, url, vendor, *, fetcher):
    resolution = resolve_document(db, url, vendor, fetcher=fetcher)
    retain_resolution(db, vendor, url, resolution)
    return resolution


def test_campaign_has_one_cve_explicit_products_and_source_dated_remediation_limits():
    document = parse_campaign(html(), URL)
    assert document["cves"] == [CVE]
    assert len(document["assessments"]) == 3
    assert document["published_at"] == "2024-07-02T16:00:00Z"
    assert all(a["scope"] == "cve_specific" and not a["versions"] for a in document["assessments"])
    asa, ftd, unaffected = document["assessments"]
    assert asa["status"] == ftd["status"] == "affected"
    assert [r["availability"] for r in asa["remediations"]] == ["vendor_reports_fixed", "planned"]
    assert ftd["remediations"][0]["availability"] == "unknown"
    assert unaffected["status"] == "unaffected"
    assert ["publisher_category", "Wireless"] in unaffected["product_context"]
    assert ["publisher_category", "Cisco Cloud Hosted Services"] in unaffected["product_context"]
    assert "Unrelated unlisted product" not in json.dumps(document)
    assert "PRIVATE_RAW_SENTINEL" not in json.dumps(document)
    assert parse_campaign(html(), URL + "/unreviewed") is None


def test_changed_identity_columns_cve_scope_categories_or_nested_lists_fail_closed():
    for before, after in [
        (TITLE.encode(), b"Unreviewed campaign"),
        (("Advisory ID: " + ADVISORY_ID).encode(), b"Advisory ID: other"),
        (b"Version 1.16: Final", b"Version 1.16: Interim"),
        (b"Fixed Release Availability", b"Unreviewed column"),
        (b"Network and Content Security Devices", b"Other category"),
        (b"Synthetic review example", b"CVE-2025-12345"),
        (
            b"<li>Example Listed Product</li>",
            b"<li>Example Listed Product<ul><li>Conditional model</li></ul></li>",
        ),
    ]:
        with pytest.raises(ValueError):
            parse_campaign(html().replace(before, after), URL)


def test_resolver_preserves_both_sources_and_retains_choice_without_merging_claims():
    with connect(":memory:") as db:
        selected_url, selected_raw = collected_resolution(db, URL, "cisco", fetcher=fetcher)
        assert selected_url == URL and selected_raw == html()
        report = choices(db)[0]
        assert [(v["selected"], v["normalized_statements"]) for v in report["views"]] == [
            (True, 3),
            (False, 1),
        ]
        assert all(v["adapter_version"] for v in report["views"])
        assert not report["unavailable"]
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 2
        collected_resolution(db, URL, "cisco", fetcher=fetcher)
        assert db.execute("SELECT COUNT(*) FROM source_selections").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 2
        assert not db.execute("SELECT 1 FROM revisions").fetchone()


def test_failed_or_identity_mismatched_alternate_stays_visible_and_recovery_clears_health(tmp_path):
    path = tmp_path / "choice.sqlite"
    for failure in ["http", "identity"]:

        def retrieve(db, target, vendor):
            if target == URL:
                return html()
            if failure == "http":
                raise HTTPError(target, 403, "PRIVATE_DIAGNOSTIC_SENTINEL", {}, None)
            return csaf().replace(ADVISORY_ID.encode(), b"unrelated-advisory")

        with connect(path) as db:
            url, body = collected_resolution(db, URL, "cisco", fetcher=retrieve)
            assert url == URL and body == html()
            selected = choices(db)[0]
            assert len(selected["views"]) == 1 and len(selected["unavailable"]) == 1
            assert "PRIVATE_DIAGNOSTIC_SENTINEL" not in json.dumps(selected)
            assert next(r for r in health(db) if r["source_url"] == CSAF_URL)["outcome"] == "error"
    with connect(path) as db:
        collected_resolution(db, URL, "cisco", fetcher=fetcher)
        assert choices(db)[0]["unavailable"] == []
        assert next(r for r in health(db) if r["source_url"] == CSAF_URL)["outcome"] == "ok"


def test_official_route_policy_applies_even_to_explicit_plugin_choices():
    outside = "https://private.example/csaf/source.json"
    raw = html().replace(CSAF_URL.encode(), outside.encode())
    with connect(":memory:") as db, pytest.raises(ValueError, match="outside"):
        resolve_document(
            db, URL, "cisco", fetcher=lambda db, target, vendor: raw if target == URL else csaf()
        )
    for count in [-1, True]:
        with pytest.raises(ValueError):
            SourceView(URL, b"raw", "synthetic", count, "test/1")
    with pytest.raises(ValueError):
        SourceSelection(SourceView(URL, b"raw", "synthetic", 0, "test/1"), (), "No evidence")
    with pytest.raises(ValueError):
        SourceViewIssue(URL, "PRIVATE BAD DIAGNOSTIC")


def test_selected_capture_is_published_with_provenance_but_private_fields_are_not(tmp_path):
    path = tmp_path / "choice.sqlite"
    with patch("infrastructure_impact.collection.service.fetch", side_effect=fetcher):
        assert run({"vendors": [], "pinned": [{"vendor": "cisco", "url": URL}]}, db_path=path) == (
            1,
            0,
        )
    with connect(path) as db:
        records = latest(db)
        assert len(records) == 1 and records[0]["source_url"] == URL
        assert len(records[0]["assessments"]) == 3
        data = state(db)
    data["source_audit"]["source_selections"][0]["raw"] = "PRIVATE_FIELD_SENTINEL"
    data["source_audit"]["source_selections"][0]["views"][0]["cookies"] = "PRIVATE_FIELD_SENTINEL"
    public = public_projection(data)
    assert len(public["source_audit"]["source_selections"]) == 1
    study = public["component_studies"]["studies"][0]
    cell = next(c for c in study["cells"] if c["vendor"] == "cisco" and c["cve_id"] == CVE)
    assert cell["state"] == "explicit_affected_statement" and len(cell["evidence"]) == 2
    assert all(e["source_url"] == URL for e in cell["evidence"])
    assert study["family_catalogue_version"] == "2026-10-27.1"
    assert len(study["family_scope_sha256"]) == 64
    assert "PRIVATE_FIELD_SENTINEL" not in json.dumps(public)
    assert "PRIVATE_RAW_SENTINEL" not in json.dumps(public)
    other = deepcopy(data)
    other["records"] = []
    assert public_projection(other)["source_audit"]["source_selections"] == []
    legacy = sqlite3.connect(":memory:")
    assert choices(legacy) == []
    legacy.close()


def test_alternate_failures_count_as_partial_collection_without_losing_valid_html(tmp_path):
    def retrieve(db, target, vendor):
        if target == URL:
            return html()
        raise HTTPError(target, 503, "unavailable", {}, None)

    path = tmp_path / "partial.sqlite"
    with patch("infrastructure_impact.collection.service.fetch", side_effect=retrieve):
        assert run({"vendors": [], "pinned": [{"vendor": "cisco", "url": URL}]}, db_path=path) == (
            1,
            1,
        )
    with connect(path) as db:
        assert len(latest(db)[0]["assessments"]) == 3
        assert next(row for row in health(db) if row["source_url"] == URL)["outcome"] == "partial"
        resolved = collected_resolution(db, URL, "cisco", fetcher=retrieve)
        assert resolved == (URL, html()) and isinstance(resolved, tuple)
        assert resolved.source_failures == 1


def test_remediation_negative_and_dated_claims_do_not_become_available_fixes():
    from infrastructure_impact.adapters.cisco_campaign import remediation

    assert remediation("No fix planned")["availability"] == "no_fix_planned"
    assert remediation("No fixed release available")["availability"] == "unavailable"
    assert remediation("None")["availability"] == "unknown"
    assert remediation("2.0 (Oct 2024)")["availability"] == "planned"
    assert remediation("No fix needed")["availability"] == "unknown"


def test_integrity_audit_detects_a_selected_capture_outside_the_view_graph(tmp_path, monkeypatch):
    from infrastructure_impact.storage.audit import audit
    from infrastructure_impact.storage.repository import evidence

    path = tmp_path / "integrity.sqlite"
    monkeypatch.setenv("IMPACT_DATABASE", str(path))
    with patch("infrastructure_impact.collection.service.fetch", side_effect=fetcher):
        assert run({"vendors": [], "pinned": [{"vendor": "cisco", "url": URL}]}, db_path=path) == (
            1,
            0,
        )
    assert audit()["source_selections"] == 1
    with connect(path) as db:
        other = evidence(db, b"Synthetic unrelated capture", URL)
        db.execute("UPDATE source_selections SET selected_evidence_id=?", (other["id"],))
    with pytest.raises(ValueError, match="missing"):
        audit()


@pytest.mark.parametrize("retain_alternate", [False, True])
def test_retained_triage_is_read_only_and_does_not_manufacture_health_or_selections(
    tmp_path, retain_alternate
):
    from infrastructure_impact.collection.archive import enqueue
    from infrastructure_impact.collection.triage import review_batch
    from infrastructure_impact.storage.repository import evidence, now

    path = tmp_path / "triage.sqlite"
    with connect(path) as db:
        evidence(db, html(), URL)
        if retain_alternate:
            evidence(db, csaf(), CSAF_URL)
        cursor = db.execute(
            "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
            ("cisco", URL, "index", now()),
        )
        enqueue(db, cursor.lastrowid, "document", URL)
    with connect(path, read_only=True) as db:
        with patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("Offline triage must not request network access"),
        ):
            report = review_batch(db, vendor="cisco", limit=1)
        item = report["documents"][0]
        assert item["outcome"] == "normalized" and item["assessments"] == 3
        assert item["alternate_issues"] == (
            []
            if retain_alternate
            else [{"source_url": CSAF_URL, "error_code": "retained_source_missing"}]
        )
        assert not choices(db)
        assert not db.execute("SELECT 1 FROM collection_runs").fetchone()
        assert not db.execute("SELECT 1 FROM source_observations").fetchone()
        assert not db.execute("SELECT 1 FROM revisions").fetchone()
        assert db.execute("SELECT state FROM archive_items").fetchone()[0] == "pending"


def test_direct_reviewed_csaf_does_not_replace_the_selected_html_with_narrower_scope(tmp_path):
    path = tmp_path / "direct-csaf.sqlite"
    with patch("infrastructure_impact.collection.service.fetch", side_effect=fetcher):
        assert run(
            {
                "vendors": [],
                "pinned": [{"vendor": "cisco", "url": URL}, {"vendor": "cisco", "url": CSAF_URL}],
            },
            db_path=path,
        ) == (1, 0)
    with connect(path) as db:
        record = latest(db)[0]
        assert record["source_url"] == URL and len(record["assessments"]) == 3
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 1
        assert len(choices(db)) == 2
