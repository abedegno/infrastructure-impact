"""Positive notices retain bytes and remain eligible for later advisory revisions."""

import json
from dataclasses import replace
from unittest.mock import patch

import pytest

from infrastructure_impact.collection import archive, archive_replay, service
from infrastructure_impact.collection.retained import retained_fetch
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.storage.repository import connect, evidence, latest, now

URL = "https://www.arista.com/en/support/advisories-notices/security-advisory/25024-security-advisory-0204"
ROOT = "https://www.arista.com/en/support/advisories-notices/security-advisories"
CISCO_URL = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-notice-I8z3n6lK"


def notice(edit=lambda s: s):
    return edit("""<div class="item-page"><div><h2>Security Advisory 0204 <a>PDF</a></h2></div><p>Date: November 3, 2026</p>
    <h4>Advance Notice for Publication of November 10, 2026 Security Advisories Release</h4>
    <table><tr><th>Revision</th><th>Date</th><th>Changes</th></tr><tr><td>1.0</td><td>November 3, 2026</td><td>Synthetic initial notice</td></tr></table>
    <h4>Update Type:</h4><p>Informational</p><h4>Overview:</h4><p>Arista is providing advance notice for multiple Security Advisories scheduled for publication on November 10, 2026.</p>
    <h4>Background:</h4><p>Synthetic planning context.</p><h4>Scope of the Upcoming Release:</h4><p>Synthetic possible product scope.</p>
    <h4>Next Steps for Our Customers:</h4><p>This notice is intended solely to help Arista customers prepare for the upcoming releases.</p><p>Synthetic details will be published later.</p>
    <h4>For More Information:</h4><p>PRIVATE_NOTICE_SENTINEL</p></div>""").encode()


def advisory():
    return json.dumps(
        {
            "document": {
                "title": "Synthetic later advisory",
                "tracking": {
                    "id": "25024-security-advisory-0204",
                    "version": "2.0",
                    "status": "final",
                    "initial_release_date": "2026-11-10T00:00:00Z",
                },
            },
            "product_tree": {"full_product_names": [{"product_id": "eos", "name": "Arista EOS"}]},
            "vulnerabilities": [
                {"cve": "CVE-2099-12345", "product_status": {"known_not_affected": ["eos"]}}
            ],
        }
    ).encode()


def seed(db):
    cursor = db.execute(
        "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
        ("arista", ROOT, "listing", now()),
    )
    source = dict(
        db.execute("SELECT * FROM archive_sources WHERE id=?", (cursor.lastrowid,)).fetchone()
    )
    archive.enqueue(db, source["id"], "document", URL)
    item = dict(db.execute("SELECT * FROM archive_items").fetchone())
    archive.document(db, source, item, fetcher=lambda *_: notice())
    return source, dict(db.execute("SELECT * FROM archive_items").fetchone())


def test_positive_notice_has_no_present_cve_product_fix_or_future_publication():
    registry = default_registry()
    doc = registry.normalize(notice(), URL, "arista")
    assert doc["source_format"] == "Arista reviewed advance notice HTML"
    assert registry.get("arista").non_cve_notice(doc)
    assert doc["cves"] == doc["assessments"] == doc["metrics"] == []
    assert doc["published_at"] == doc["updated_at"] == "2026-11-03"
    assert "November 10, 2026" in json.dumps(doc["notes"])
    assert "PRIVATE_NOTICE_SENTINEL" not in json.dumps(doc)
    result = registry.research_evidence(notice(), URL, "arista", doc)
    assert result["claims"] == result["bundles"] == []


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"<html>Verify you are human</html>",
        notice(lambda s: s.replace("Informational", "Unspecified")),
        notice(lambda s: s.replace("Synthetic possible product scope.", "CVE-2099-12345")),
        notice(lambda s: s.replace("Advance Notice for Publication", "Unreviewed publication")),
    ],
)
def test_empty_challenge_cve_or_unreviewed_html_never_becomes_notice(raw):
    with pytest.raises(ValueError):
        default_registry().normalize(raw, URL, "arista")


def test_ordinary_collection_retains_notice_then_ingests_validated_same_url_revision(
    tmp_path, monkeypatch
):
    path = tmp_path / "notices.sqlite"
    config = {"vendors": [], "pinned": [{"vendor": "arista", "url": URL}]}
    monkeypatch.setattr(service, "fetch", lambda *_: notice())
    assert service.run(config, db_path=path) == (0, 0)
    with connect(path) as db:
        assert not latest(db)
        assert retained_fetch(db, URL, "arista") == notice()
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    monkeypatch.setattr(service, "fetch", lambda *_: advisory())
    assert service.run(config, db_path=path) == (1, 0)
    with connect(path) as db:
        assert latest(db)[0]["cves"] == ["CVE-2099-12345"]
        assert latest(db)[0]["assessments"][0]["status"] == "unaffected"
        assert not default_registry().get("arista").non_cve_notice(latest(db)[0])


def test_archive_rediscovery_requeues_notice_with_existing_document_budget():
    with connect(":memory:") as db:
        source, item = seed(db)
        assert item["state"] == "not_applicable" and not latest(db)
        archive.enqueue(db, source["id"], "document", URL)
        ready = archive.ready(db, source["id"], "document", 1)
        assert len(ready) == 1
        archive.document(db, source, ready[0], fetcher=lambda *_: advisory())
        assert db.execute("SELECT state FROM archive_items").fetchone()[0] == "done"
        assert latest(db)[0]["cves"] == ["CVE-2099-12345"]


def test_retained_notice_replay_uses_changed_source_or_parser_and_is_idempotent():
    with connect(":memory:") as db:
        source, item = seed(db)
        with patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ):
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
            db.execute("UPDATE archive_items SET parser_version='old-parser'")
            result = archive_replay.reprocess_errors(db, source, 1)
            assert result["attempted"] == result["not_applicable"] == 1
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
            evidence(db, advisory(), URL)
            result = archive_replay.reprocess_errors(db, source, 1)
            assert result["attempted"] == result["recovered"] == result["imported"] == 1
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 2
        assert not db.execute("SELECT 1 FROM source_observations").fetchone()
        assert latest(db)[0]["cves"] == ["CVE-2099-12345"]


def cisco_notice(edit=lambda s: s):
    return edit("""<h1 class="headline">Cisco Advance Notification for Publication of November 4, 2026, Security Advisories</h1>
    <div id="advisorycontentcontainer"><div id="advisorycontentheader"><div id="severitycirclecontent">Informational</div><div id="ud-advisory-identifier">Advisory ID: cisco-sa-notice-I8z3n6lK</div><div id="ud-published">First Published: 2026 October 28 16:00 GMT</div><div id="ud-last-updated">Last Updated: 2026 November 4 16:01 GMT</div><div>Version 1.1: Final</div><div class="CVEList"></div></div>
    <div id="advisorycontentbody"><h2>Summary</h2><div id="summaryfield"><p>Cisco PSIRT published the following advisories:</p><table><tr><th>Cisco Security Advisory</th><th>CVE ID</th><th>Security Impact Rating</th><th>CVSS Base Score</th></tr><tr><td><a href="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-synthetic">Synthetic separate advisory</a></td><td>CVE-2099-23456</td><td>High</td><td>7.6</td></tr></table><p>Synthetic advisory references.</p></div>
    <h2>Details</h2><div id="detailfield"><span><p>Synthetic seven-day advance notice of upcoming security vulnerability disclosures. This schedule is not a final commitment of releases.</p></span></div></div></div><footer>CVE-2099-99999 PRIVATE_NOTICE_SENTINEL</footer>""").encode()


def test_cisco_informational_article_keeps_linked_cves_outside_own_scope():
    doc = default_registry().normalize(cisco_notice(), CISCO_URL, "cisco")
    assert doc["source_format"] == "Cisco reviewed informational schedule HTML"
    assert default_registry().get("cisco").non_cve_notice(doc)
    assert doc["cves"] == doc["assessments"] == []
    assert doc["published_at"] == "2026-10-28T16:00:00Z"
    assert doc["updated_at"] == "2026-11-04T16:01:00Z"
    assert "CVE-2099-23456" in json.dumps(doc["notes"])
    assert "CVE-2099-99999" not in json.dumps(doc)


@pytest.mark.parametrize(
    "old,new",
    [
        ("Informational", "High"),
        ('<div class="CVEList"></div>', '<div class="CVEList">CVE-2099-23456</div>'),
        ("Synthetic advisory references.", "This document affects CVE-2099-23456."),
        ("seven-day advance notice", "new vulnerability"),
        ("Cisco Security Advisory</th><th>CVE ID", "Products</th><th>CVE ID"),
        ('cisco-sa-synthetic"', 'cisco-sa-notice-I8z3n6lK"'),
        ("Synthetic advisory references.", "<h2>Affected Products</h2><p>All software</p>"),
    ],
)
def test_cisco_notice_own_cve_scope_and_positive_markers_are_required(old, new):
    with pytest.raises(ValueError):
        default_registry().normalize(
            cisco_notice(lambda s: s.replace(old, new)), CISCO_URL, "cisco"
        )


def cache(db, raw):
    retained = evidence(db, raw, URL)
    db.execute(
        "INSERT INTO http_cache(url,evidence_id) VALUES(?,?) ON CONFLICT(url) DO UPDATE SET evidence_id=excluded.evidence_id",
        (URL, retained["id"]),
    )
    return retained["id"]


def test_source_replay_preserves_old_parser_receipt_and_failed_bytes_do_not_loop():
    with connect(":memory:") as db:
        source, item = seed(db)
        db.execute("UPDATE archive_items SET parser_version='old-parser'")
        archive_replay.reprocess_errors(db, source, 1)
        receipt = dict(db.execute("SELECT * FROM archive_parser_replays").fetchone())
        failed_id = cache(db, b"<html>Unknown future advisory layout</html>")
        with patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ):
            result = archive_replay.reprocess_errors(db, source, 1)
            assert result["still_unsupported"] == result["attempted"] == 1
            attempted = db.execute("SELECT * FROM archive_items").fetchone()
            assert attempted["state"] == "error" and attempted["evidence_id"] == failed_id
            assert attempted["attempts"] == 0 and attempted["retry_after"] is None
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
            # A -> B -> A: cache pointer, not first-retained/id ordering, selects A.
            cache(db, notice())
            result = archive_replay.reprocess_errors(db, source, 1)
            assert result["not_applicable"] == result["attempted"] == 1
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
            cache(db, advisory())
            assert archive_replay.reprocess_errors(db, source, 1)["recovered"] == 1
        assert dict(db.execute("SELECT * FROM archive_parser_replays").fetchone()) == receipt
        assert db.execute("SELECT COUNT(*) FROM archive_parser_replays").fetchone()[0] == 1
        assert not db.execute("SELECT 1 FROM source_observations").fetchone()
        assert latest(db)[0]["cves"] == ["CVE-2099-12345"]


def test_missing_retained_bytes_do_not_disable_later_source_recovery():
    with connect(":memory:") as db:
        cursor = db.execute(
            "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
            ("arista", ROOT, "listing", now()),
        )
        source = dict(
            db.execute("SELECT * FROM archive_sources WHERE id=?", (cursor.lastrowid,)).fetchone()
        )
        archive.enqueue(db, source["id"], "document", URL)
        db.execute(
            "UPDATE archive_items SET state='error',error_code='unsupported_or_invalid_document',parser_version='old-parser'"
        )
        assert archive_replay.reprocess_errors(db, source, 1)["not_retained"] == 1
        evidence(db, notice(), URL)
        assert archive_replay.reprocess_errors(db, source, 1)["not_applicable"] == 1
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0


@pytest.mark.parametrize("cid", ["CVE-2099-33333", "CVE-2099-23456"])
def test_cisco_new_own_body_section_cannot_hide_a_cve_even_if_already_linked(cid):
    raw = cisco_notice(
        lambda s: s.replace(
            "<h2>Details</h2>",
            f"<h2>Vulnerability Details</h2><p>This advisory addresses {cid} in the affected product.</p><h2>Details</h2>",
        )
    )
    with pytest.raises(ValueError):
        default_registry().normalize(raw, CISCO_URL, "cisco")


@pytest.mark.parametrize("parser_changed", [False, True])
def test_notice_access_challenge_retains_failure_and_recovers_changed_bytes_offline(parser_changed):
    with connect(":memory:") as db:
        source, item = seed(db)
        db.execute("UPDATE archive_items SET parser_version='old-parser'")
        archive_replay.reprocess_errors(db, source, 1)
        receipt = dict(db.execute("SELECT * FROM archive_parser_replays").fetchone())
        challenge_id = cache(
            db,
            b"<html><title>Client Challenge</title><p>/_fs-ch- Javascript is disabled</p></html>",
        )
        with patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ):
            result = archive_replay.reprocess_errors(db, source, 1)
            assert result["attempted"] == result["still_unsupported"] == 1
            item = db.execute("SELECT * FROM archive_items").fetchone()
            assert (item["state"], item["error_code"], item["evidence_id"]) == (
                "error",
                "access_verification_required",
                challenge_id,
            )
            assert item["attempts"] == 0 and item["retry_after"] is None
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
            # A parser change can revisit this established source, but unchanged
            # challenge bytes still fail honestly and do not create a retry loop.
            if parser_changed:
                db.execute("UPDATE archive_items SET parser_version='earlier-parser'")
                result = archive_replay.reprocess_errors(db, source, 1)
                assert result["attempted"] == result["still_unsupported"] == 1
                assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
            cache(db, advisory())
            result = archive_replay.reprocess_errors(db, source, 1)
            assert result["attempted"] == result["recovered"] == result["imported"] == 1
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        assert dict(db.execute("SELECT * FROM archive_parser_replays").fetchone()) == receipt
        assert db.execute("SELECT COUNT(*) FROM archive_parser_replays").fetchone()[0] == 1
        assert not db.execute("SELECT 1 FROM source_observations").fetchone()
        assert latest(db)[0]["cves"] == ["CVE-2099-12345"]


@pytest.mark.parametrize("error_code", ["access_verification_required", "access_denied"])
@pytest.mark.parametrize("parser_changed", [False, True])
def test_initial_access_failures_are_not_new_offline_transition_candidates(
    error_code, parser_changed
):
    with connect(":memory:") as db:
        source, item = seed(db)
        # An initial transport failure has no prior completed document resolution.
        db.execute(
            "UPDATE archive_items SET state='error',error_code=?,resolved_url=NULL,parser_version=?",
            (
                error_code,
                "old-parser" if parser_changed else default_registry().fingerprint("arista"),
            ),
        )
        cache(db, advisory())
        with patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ):
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        assert not latest(db)


@pytest.mark.parametrize(
    "insertion",
    [
        "<p>This notice now addresses CVE-2099-23456.</p>",
        "<h2>Product Applicability</h2><p>All synthetic product versions.</p>",
    ],
)
def test_cisco_unreviewed_own_body_prose_or_product_heading_requires_review(insertion):
    raw = cisco_notice(lambda s: s.replace("<h2>Details</h2>", insertion + "<h2>Details</h2>"))
    with pytest.raises(ValueError):
        default_registry().normalize(raw, CISCO_URL, "cisco")


WRAPPER_URL = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-synthetic-wrapper"
SELECTED_URL = "https://sec.cloudapps.cisco.com/synthetic/csaf/notice.json"


def wrapper(selected=SELECTED_URL, suffix=""):
    return f'<html><a href="{selected}">CSAF</a>{suffix}</html>'.encode()


def selected_notice(title="Synthetic notice"):
    return json.dumps(
        {
            "document": {
                "title": "Cisco Informational: " + title,
                "tracking": {"id": "cisco-sa-synthetic-notice", "status": "final"},
            },
            "vulnerabilities": [],
        }
    ).encode()


def cache_url(db, url, raw):
    retained = evidence(db, raw, url)
    db.execute(
        "INSERT INTO http_cache(url,evidence_id) VALUES(?,?) ON CONFLICT(url) DO UPDATE SET evidence_id=excluded.evidence_id",
        (url, retained["id"]),
    )
    return retained["id"]


def seed_wrapper(db):
    db.execute(
        "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
        ("cisco", "https://sec.cloudapps.cisco.com/synthetic/index", "index", now()),
    )
    source = dict(db.execute("SELECT * FROM archive_sources").fetchone())
    archive.enqueue(db, source["id"], "document", WRAPPER_URL)
    cache_url(db, WRAPPER_URL, wrapper())
    cache_url(db, SELECTED_URL, selected_notice())
    archive.document(
        db, source, db.execute("SELECT * FROM archive_items").fetchone(), fetcher=retained_fetch
    )
    return source


@pytest.mark.parametrize("rediscover", [False, True])
def test_missing_linked_notice_dependency_arrival_recovers_without_network(rediscover):
    with (
        connect(":memory:") as db,
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        source, _ = seed(db)
        db.execute("UPDATE archive_items SET parser_version='old-parser'")
        assert archive_replay.reprocess_errors(db, source, 1)["not_applicable"] == 1
        receipt = dict(db.execute("SELECT * FROM archive_parser_replays").fetchone())
        linked = "https://www.arista.com/synthetic/csaf/later-advisory.json"
        evidence(db, wrapper(linked), URL)
        result = archive_replay.reprocess_errors(db, source, 1)
        assert result["attempted"] == result["not_retained"] == 1
        item = db.execute("SELECT * FROM archive_items").fetchone()
        assert item["state"] == "error" and item["error_code"] == "retained_source_missing"
        assert item["attempts"] == 0 and item["retry_after"] is None
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        # Unrelated retention must not spend this document's budget.
        evidence(db, advisory(), "https://www.arista.com/synthetic/unrelated.json")
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        evidence(db, advisory(), linked)
        if rediscover:
            archive.enqueue(db, source["id"], "document", URL)
        result = archive_replay.reprocess_errors(db, source, 1)
        assert result["attempted"] == result["recovered"] == result["imported"] == 1
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        assert latest(db)[0]["cves"] == ["CVE-2099-12345"]
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 1
        assert dict(db.execute("SELECT * FROM archive_parser_replays").fetchone()) == receipt
        assert db.execute("SELECT COUNT(*) FROM archive_parser_replays").fetchone()[0] == 1
        assert not db.execute("SELECT 1 FROM source_observations").fetchone()


@pytest.mark.parametrize("changed_url", [WRAPPER_URL, SELECTED_URL])
def test_wrapper_notice_tracks_both_inputs_and_cache_reversions(changed_url):
    with (
        connect(":memory:") as db,
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        source = seed_wrapper(db)
        before = db.execute("SELECT COUNT(*) FROM collection_runs").fetchone()[0]
        for _ in range(3):
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        assert db.execute("SELECT COUNT(*) FROM collection_runs").fetchone()[0] == before
        original = wrapper() if changed_url == WRAPPER_URL else selected_notice()
        changed = (
            wrapper(suffix="<p>Updated wrapper</p>")
            if changed_url == WRAPPER_URL
            else selected_notice("Updated synthetic notice")
        )
        # Each A -> B -> A transition is processed once, even with reused evidence IDs.
        for raw in (changed, original):
            cache_url(db, changed_url, raw)
            result = archive_replay.reprocess_errors(db, source, 1)
            assert result["attempted"] == result["not_applicable"] == 1
            assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        assert db.execute("SELECT COUNT(*) FROM collection_runs").fetchone()[0] == before + 2
        assert not db.execute("SELECT 1 FROM archive_parser_replays").fetchone()
        assert not db.execute("SELECT 1 FROM source_observations").fetchone()
        assert not latest(db)


@pytest.mark.parametrize(
    "failed_raw",
    [b"{}", b"<html><title>Client Challenge</title><p>/_fs-ch- Javascript is disabled</p></html>"],
)
def test_failed_selected_bytes_are_reconsidered_only_when_relevant_inputs_change(failed_raw):
    with (
        connect(":memory:") as db,
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        source = seed_wrapper(db)
        cache_url(db, SELECTED_URL, failed_raw)
        result = archive_replay.reprocess_errors(db, source, 1)
        assert result["attempted"] == result["still_unsupported"] == 1
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        cache_url(db, SELECTED_URL, selected_notice())
        result = archive_replay.reprocess_errors(db, source, 1)
        assert result["attempted"] == result["not_applicable"] == 1
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0


def test_unchanged_wrapper_notice_leaves_shared_budget_for_pending_document(tmp_path, monkeypatch):
    # Cisco uses a feed in production. This synthetic archive-capable plugin
    # keeps its real source resolver/parser while exercising the shared runner.
    registry = default_registry()
    monkeypatch.setitem(registry._plugins, "cisco", replace(registry.get("cisco"), parse_feed=None))
    path = tmp_path / "wrapper-budget.sqlite"
    pending = "https://sec.cloudapps.cisco.com/synthetic/csaf/pending.json"
    with connect(path) as db:
        source = seed_wrapper(db)
        cache_url(db, pending, advisory())
        archive.enqueue(db, source["id"], "document", pending)
    config = {
        "vendors": [],
        "archives": [
            {"vendor": "cisco", "url": source["source_url"], "kind": "index", "document_limit": 1}
        ],
    }
    with (
        patch(
            "infrastructure_impact.collection.archive.fetch", return_value=(pending + "\n").encode()
        ),
        patch("infrastructure_impact.collection.service.fetch", side_effect=retained_fetch),
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        assert archive.run(config, path) == (1, 0)
    with connect(path) as db:
        assert (
            db.execute("SELECT state FROM archive_items WHERE url=?", (pending,)).fetchone()[0]
            == "done"
        )
        assert (
            db.execute(
                "SELECT COUNT(*) FROM collection_runs WHERE source_url=?", (WRAPPER_URL,)
            ).fetchone()[0]
            == 1
        )


@pytest.mark.parametrize(
    "scope",
    [
        "",
        "not-json",
        "[]",
        *[
            json.dumps(
                dict(
                    version=1,
                    kind="document",
                    requested_url=WRAPPER_URL,
                    inputs={WRAPPER_URL: None},
                )
                | changes
            )
            for changes in (
                {"version": 99},
                {"version": True},
                {"kind": "page"},
                {"requested_url": SELECTED_URL},
                {"inputs": []},
                {"inputs": {}},
                {"inputs": {WRAPPER_URL: True}},
                {"inputs": {WRAPPER_URL: -1}},
            )
        ],
    ],
)
def test_legacy_or_invalid_document_snapshot_establishes_state_once(scope):
    with (
        connect(":memory:") as db,
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        source = seed_wrapper(db)
        db.execute("UPDATE archive_items SET scope=?", (scope,))
        assert archive_replay.reprocess_errors(db, source, 1)["not_applicable"] == 1
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0


def test_legacy_missing_dependency_null_error_state_can_recover():
    with (
        connect(":memory:") as db,
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        source, _ = seed(db)
        linked = "https://www.arista.com/synthetic/csaf/later-advisory.json"
        requested_id = evidence(db, wrapper(linked), URL)["id"]
        # Row written by the previous implementation after source-only failure.
        db.execute(
            "UPDATE archive_items SET state='error',error_code=NULL,scope='',evidence_id=?",
            (requested_id,),
        )
        evidence(db, advisory(), linked)
        result = archive_replay.reprocess_errors(db, source, 1)
        assert result["attempted"] == result["recovered"] == result["imported"] == 1
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0


def test_missing_linked_bytes_preserve_http_backoff_until_offline_recovery():
    with (
        connect(":memory:") as db,
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        source, _ = seed(db)
        linked = "https://www.arista.com/synthetic/csaf/later-advisory.json"
        evidence(db, wrapper(linked), URL)
        db.execute(
            "UPDATE archive_items SET state='error',error_code='unsupported_or_invalid_document',"
            "attempts=5,retry_after='2099-01-01T00:00:00+00:00'"
        )
        assert archive_replay.reprocess_errors(db, source, 1)["not_retained"] == 1
        archive.enqueue(db, source["id"], "document", URL)
        assert archive.ready(db, source["id"], "document", 1) == []
        item = db.execute("SELECT * FROM archive_items").fetchone()
        assert item["attempts"] == 5 and item["retry_after"] == "2099-01-01T00:00:00+00:00"
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        evidence(db, advisory(), linked)
        assert archive_replay.reprocess_errors(db, source, 1)["recovered"] == 1


def test_unchanged_inputs_do_not_hide_later_changed_item_with_limit_one():
    with (
        connect(":memory:") as db,
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        source = seed_wrapper(db)
        other = "https://sec.cloudapps.cisco.com/synthetic/csaf/other.json"
        archive.enqueue(db, source["id"], "document", other)
        cache_url(db, other, selected_notice("Another synthetic notice"))
        archive.document(
            db,
            source,
            db.execute("SELECT * FROM archive_items WHERE url=?", (other,)).fetchone(),
            fetcher=retained_fetch,
        )
        cache_url(db, other, advisory())
        assert archive_replay.reprocess_errors(db, source, 0)["attempted"] == 0
        result = archive_replay.reprocess_errors(db, source, 1)
        assert result["attempted"] == result["recovered"] == result["imported"] == 1
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0


def test_document_snapshot_never_replaces_or_exports_page_scope():
    with connect(":memory:") as db:
        source, item = seed(db)
        archive.enqueue(db, source["id"], "page", ROOT)
        page = dict(db.execute("SELECT * FROM archive_items WHERE kind='page'").fetchone())
        db.execute(
            "UPDATE archive_items SET state='done',scope='Synthetic listing scope' WHERE id=?",
            (page["id"],),
        )
        before = dict(db.execute("SELECT * FROM archive_items WHERE kind='page'").fetchone())
        db.execute("UPDATE archive_items SET parser_version='old-parser' WHERE kind='document'")
        assert archive_replay.reprocess_errors(db, source, 1)["not_applicable"] == 1
        assert (
            dict(db.execute("SELECT * FROM archive_items WHERE kind='page'").fetchone()) == before
        )
        config = {"archives": [{"vendor": "arista", "url": ROOT, "kind": "listing"}]}
        progress = archive.progress(db, latest(db), config)[0]
        assert progress["observed_scopes"] == ["Synthetic listing scope"]
        assert "requested_url" not in json.dumps(progress["observed_scopes"])


def test_wrapper_reselection_stops_tracking_previous_dependency():
    with (
        connect(":memory:") as db,
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        source = seed_wrapper(db)
        replacement = "https://sec.cloudapps.cisco.com/synthetic/csaf/replacement.json"
        cache_url(db, WRAPPER_URL, wrapper(replacement))
        cache_url(db, replacement, selected_notice("Replacement notice"))
        assert archive_replay.reprocess_errors(db, source, 1)["not_applicable"] == 1
        cache_url(db, SELECTED_URL, advisory())
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
        assert db.execute("SELECT resolved_url FROM archive_items").fetchone()[0] == replacement
        assert not latest(db)


def test_interrupted_missing_dependency_attempt_does_not_commit_inputs_before_outcome():
    with (
        connect(":memory:") as db,
        patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No network"),
        ),
    ):
        source, _ = seed(db)
        before = dict(db.execute("SELECT * FROM archive_items").fetchone())
        evidence(db, wrapper("https://www.arista.com/synthetic/csaf/missing.json"), URL)
        db.commit()  # This capture arrived before the interrupted replay transaction.
        # Stop after resolution has failed, before the error outcome is written.
        with patch.object(archive_replay, "failure_code", side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                archive_replay.reprocess_errors(db, source, 1)
        assert dict(db.execute("SELECT * FROM archive_items").fetchone()) == before
        assert archive_replay.reprocess_errors(db, source, 1)["not_retained"] == 1
        assert archive_replay.reprocess_errors(db, source, 1)["attempted"] == 0
