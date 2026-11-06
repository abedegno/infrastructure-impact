"""Window-bound discovery must retain uncertainty and durable resume points."""

import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from infrastructure_impact.collection import switching_backfill as backfill
from infrastructure_impact.collection.errors import CiscoAccessError
from infrastructure_impact.storage.repository import connect

API = "https://apix.cisco.com/security/advisories/v2/"
ARISTA = "https://www.arista.com/en/support/advisories-notices"
ARUBA = "https://csaf.arubanetworking.hpe.com/index.txt"


def config(route="all", page_size=2):
    return {
        "vendors": [],
        "switching_sources": [
            {"vendor": "cisco", "kind": "openvuln", "url": API + route, "page_size": page_size}
        ],
    }


def run(db, cfg=None, **kwargs):
    return backfill.run(
        db,
        config() if cfg is None else cfg,
        vendor=kwargs.pop("vendor", "cisco"),
        start_date=kwargs.pop("start_date", "2021-01-01"),
        end_date=kwargs.pop("end_date", "2026-11-04"),
        page_limit=kwargs.pop("page_limit", 2),
        document_limit=kwargs.pop("document_limit", 8),
        **kwargs,
    )


def entry(identity, **kwargs):
    return dict(
        advisoryId=identity,
        firstPublished="2024-03-01T00:00:00",
        lastUpdated="2024-03-02T00:00:00",
        status="Final",
        version="1.0",
        publicationUrl="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
        + identity,
        **kwargs,
    )


def page(entries, **metadata):
    return json.dumps(dict(advisories=entries, **metadata)).encode()


def capture(pages, requests):
    def get(self, url):
        requests.append(url)
        query = parse_qs(urlsplit(url).query)
        assert int(query["pageSize"][0]) <= 100
        index = int(query["pageIndex"][0])
        assert 1 <= index <= 100
        response = pages[index]
        if isinstance(response, BaseException):
            raise response
        return response

    return get


def test_missing_auth_and_unconfigured_vendors_are_explicit(monkeypatch):
    monkeypatch.delenv("CISCO_OPENVULN_CLIENT_ID", raising=False)
    monkeypatch.delenv("CISCO_OPENVULN_CLIENT_SECRET", raising=False)
    with connect(":memory:") as db:
        result = run(db, vendor=None)
        by_vendor = {e["vendor"]: e for e in result["entries"]}
        assert by_vendor["cisco"]["coverage_state"] == "blocked"
        assert by_vendor["cisco"]["errors"] == ["auth_not_configured"]
        assert by_vendor["cisco"]["expected_total"] is None
        assert by_vendor["aruba"]["coverage_state"] == "not_configured"
        assert by_vendor["arista"]["coverage_state"] == "not_configured"


@pytest.mark.parametrize("route", ["all", "year/2021", "all/firstpublished"])
def test_one_based_enumeration_resume_and_window_identity(route):
    requests = []
    responses = {1: page([entry("a"), entry("b")]), 2: page([entry("c")])}
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(responses, requests)),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        first = run(db, config(route), page_limit=1)
        e = first["entries"][0]
        assert e["checkpoint"]["next_page"] == 2
        assert e["coverage_state"] == "partial"
        assert e["expected_total"] is None
        assert e["documents"]["error"] == 2
        second = run(db, config(route), page_limit=1)
        e = second["entries"][0]
        assert e["coverage_state"] == "enumerated"
        assert e["discovered_unique_identities"] == 3
        assert e["documents"]["error"] == 3
        assert e["parse_failed"] == 3
        assert e["classification_pending"] == 3
        assert e["unknown_models"] == 3
        assert [parse_qs(urlsplit(u).query)["pageIndex"] for u in requests] == [["1"], ["2"]]
        assert len(e["page_evidence"]) == 2
        assert len(e["page_evidence"][0]["sha256"]) == 64
        assert backfill.manifest(db, study_id="campus-branch-switching") == second
        run(db, config(route), page_limit=1)
        assert len(requests) == 2
        run(db, config(route), end_date="2026-11-03", page_limit=1)
        assert len(backfill.manifest(db, study_id="campus-branch-switching")["entries"]) == 2
        assert len(requests) == 3


def test_moving_totals_duplicates_withdrawn_unknown_dates_remain_visible():
    a, b = entry("a"), entry("b")
    b["firstPublished"] = None
    b["status"] = "Withdrawn"
    responses = {1: page([a, b], total=3), 2: page([b], total=4)}
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(responses, [])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        e = run(db)["entries"][0]
        assert e["coverage_state"] == "unstable"
        assert e["discovered_unique_identities"] == 2
        assert e["duplicate_entries"] == 1
        assert e["withdrawn_entries"] == 1
        assert e["unknown_dates"] == 1
        assert set(e["errors"]) >= {"publisher_total_changed", "overlapping_pages"}
        assert e["documents"]["error"] == 2
        assert (
            db.execute("SELECT count(*) FROM archive_items WHERE kind='document'").fetchone()[0]
            == 2
        )
        assert e["identity_evidence"][1]["status"] == "Withdrawn"
        assert e["identity_evidence"][1]["source_locator"] == "/advisories/1"


def test_unresolved_access_stops_without_advancing_or_retrying_documents():
    responses = {1: page([entry("a"), entry("b")]), 2: CiscoAccessError("request_state_unresolved")}
    requests = []
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(responses, requests)),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        e = run(db)["entries"][0]
        assert e["coverage_state"] == "blocked"
        assert e["checkpoint"]["next_page"] == 2
        assert e["documents"]["pending"] == 2
        assert e["errors"] == ["request_state_unresolved"]
        assert db.execute("SELECT count(*) FROM switching_requests").fetchone()[0] == 0


@pytest.mark.parametrize(
    "metadata",
    [
        {"next": "https://untrusted.example/"},
        {"next": API + "all?pageIndex=1&pageSize=2"},
        {"pageIndex": 99},
        {"advisories": {}},
    ],
)
def test_invalid_pagination_never_advances(metadata):
    raw = (
        json.dumps(dict(advisories=[entry("a")], **metadata)).encode()
        if "advisories" not in metadata
        else json.dumps(metadata).encode()
    )
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", return_value=raw),
    ):
        e = run(db)["entries"][0]
        assert e["coverage_state"] in ("blocked", "unstable")
        assert e["checkpoint"]["next_page"] == 1
        assert e["documents"]["pending"] == 0


def test_interruption_before_queue_commit_does_not_advance():
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", return_value=page([entry("a")])),
    ):
        db.execute(
            "CREATE TRIGGER abort_queue BEFORE INSERT ON archive_links BEGIN SELECT RAISE(ABORT,'interrupted'); END"
        )
        e = run(db)["entries"][0]
        assert e["checkpoint"]["next_page"] == 1
        assert e["discovered_unique_identities"] == 0
        assert e["page_evidence"] == []
        assert db.execute("SELECT count(*) FROM archive_links").fetchone()[0] == 0
        db.execute("DROP TRIGGER abort_queue")
        # A failed durable page commit now respects the same persisted backoff
        # as a failed fetch; simulate the retry boundary passing.
        db.execute(
            "UPDATE archive_items SET retry_after='2021-01-01T00:00:00+00:00' WHERE kind='page'"
        )
        db.commit()
        with patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ):
            e = run(db)["entries"][0]
        assert e["coverage_state"] == "enumerated"
        assert e["discovered_unique_identities"] == 1
        item = db.execute("SELECT * FROM archive_items WHERE kind='page'").fetchone()
        assert item["attempts"] == 0
        assert item["retry_after"] is None


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(page_limit=0),
        dict(page_limit=21),
        dict(document_limit=0),
        dict(document_limit=201),
        dict(page_limit=True),
        dict(start_date="2021-02-30"),
        dict(start_date="2022-01-01"),
        dict(end_date="2020-01-01"),
        dict(end_date="20261104"),
        dict(vendor="juniper"),
    ],
)
def test_invalid_limits_and_dates_precede_io(kwargs):
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", side_effect=AssertionError("I/O")),
    ):
        with pytest.raises(ValueError):
            run(db, **kwargs)
        assert db.execute("SELECT count(*) FROM archive_sources").fetchone()[0] == 0


@pytest.mark.parametrize(
    "url",
    [
        API + "OSType/iosxe?version=17",
        "https://api.cisco.com/security/advisories/v2/all",
        API + "all?client_secret=private",
        API + "all#fragment",
    ],
)
def test_staging_api_config_rejects_non_enumeration_routes(url):
    cfg = config()
    cfg["switching_sources"][0]["url"] = url
    with connect(":memory:") as db, pytest.raises(ValueError):
        run(db, cfg)


def listing(index, terminal=False):
    links = "".join(
        f'<h2><a href="/en/support/advisories-notices/security-advisory/{n}-security-advisory-{n:04}">Security Advisory {n:04}</a></h2>'
        for n in range(index * 3 + 1, index * 3 + 4)
    )
    nav = (
        '<li class="disabled"><a href="javascript:void(0);"><span class="pageNext">Next</span></a></li>'
        if terminal
        else f'<li><a href="/en/support/advisories-notices/securityadvisory?start={(index + 1) * 10}"><span class="pageNext">Next</span></a></li>'
    )
    return (
        "<h2>Security Advisories</h2>"
        + links
        + '<div class="pagination"><ul>'
        + nav
        + "</ul></div>"
    ).encode()


def test_twenty_one_page_traversal_preserves_52_exhausted_failures_and_drafts():
    cfg = {"vendors": [], "archives": [{"vendor": "arista", "kind": "listing", "url": ARISTA}]}

    def fetch(db, url, vendor):
        index = int(parse_qs(urlsplit(url).query).get("start", ["0"])[0]) // 10
        return listing(index, terminal=index == 20)

    with (
        connect(":memory:") as db,
        patch.object(backfill, "fetch", fetch),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("draft or denied"),
        ),
    ):
        run(db, cfg, vendor="arista", page_limit=20, document_limit=52)
        db.execute("UPDATE archive_items SET attempts=5 WHERE kind='document' AND state='error'")
        db.commit()
        e = run(db, cfg, vendor="arista", page_limit=20, document_limit=1)["entries"][0]
        assert e["coverage_state"] == "enumerated"
        assert len(e["page_evidence"]) == 21
        assert e["documents"]["error"] == 53
        assert e["exhausted_errors"] == 52
        assert e["discovered_unique_identities"] == 63
        again = run(db, cfg, vendor="arista", page_limit=20, document_limit=1)["entries"][0]
        assert again["documents"]["error"] == 54
        assert again["exhausted_errors"] == 52


def test_aruba_known_index_exhaustion_retains_pre2022_gap():
    cfg = {"vendors": [], "archives": [{"vendor": "aruba", "kind": "index", "url": ARUBA}]}
    with (
        connect(":memory:") as db,
        patch.object(backfill, "fetch", return_value=b"2022/example.json\n"),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        e = run(db, cfg, vendor="aruba")["entries"][0]
        assert e["coverage_state"] == "enumerated"
        assert e["expected_total"] is None
        assert "pre_2022_history_not_enumerated" in e["gaps"]
        assert e["unknown_dates"] == 1
        assert e["documents"]["error"] == 1


@pytest.mark.parametrize("ordinary", [False, True])
def test_aruba_historical_text_archive_interruption_resume(tmp_path, ordinary):
    from hashlib import sha256
    from pathlib import Path

    from test_aruba_text_coverage import DIRECTORY, URL, listing, signed_text

    from infrastructure_impact.application import switching_evidence
    from infrastructure_impact.collection import archive, service
    from infrastructure_impact.storage.repository import latest

    name = URL.rsplit("/", 1)[1]
    other = name.replace("013", "019")
    raw = signed_text()
    excluded = signed_text(excluded=True).replace(b"ARUBA-PSA-2021-013", b"ARUBA-PSA-2021-019")
    captures = {DIRECTORY: listing(name, name, other), URL: raw, DIRECTORY + other: excluded}
    cfg = {"vendors": [], "archives": [{"vendor": "aruba", "kind": "listing", "url": DIRECTORY}]}
    protected = [
        Path("infrastructure_impact/resources") / n
        for n in ("sources.json", "switching-study.json", "switching-source-bindings.json")
    ]
    before = {p: sha256(p.read_bytes()).hexdigest() for p in protected}
    path = tmp_path / "stage.sqlite3"

    def fetch(db, url, vendor):
        assert vendor == "aruba"
        return captures[url]

    with (
        patch.object(archive, "fetch", fetch),
        patch.object(service, "fetch", fetch),
        patch.object(backfill, "fetch", fetch),
    ):

        def invoke():
            if ordinary:
                return archive.run(cfg, path, vendor="aruba", page_limit=1, document_limit=1)
            with connect(path) as db:
                return run(db, cfg, vendor="aruba", page_limit=1, document_limit=1)

        # The first document is committed before its queue acknowledgement.
        original = archive.evidence

        def interrupt(db, body, url, *args):
            if url == URL:
                raise KeyboardInterrupt
            return original(db, body, url, *args)

        with patch.object(archive, "evidence", interrupt), pytest.raises(KeyboardInterrupt):
            invoke()
        with connect(path) as db:
            assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 1
        invoke()
        invoke()
        invoke()
        with connect(path) as db:
            assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 2
            assert (
                db.execute(
                    "SELECT count(*) FROM archive_items WHERE kind='document' AND state='done'"
                ).fetchone()[0]
                == 2
            )
            assert (
                db.execute("SELECT entry_count FROM archive_items WHERE kind='page'").fetchone()[0]
                == 3
            )
            assert (
                db.execute("SELECT raw FROM evidence WHERE source_url=?", (URL,)).fetchone()[0]
                == raw
            )
            report = switching_evidence.project(
                switching_evidence.inputs(db, latest(db)),
                publication=None,
                generated_at="2026-11-05T12:00:00Z",
            )
            cx = [c for c in report["claims"] if c["family"] == "aruba-aoscx"]
            assert len(cx) == 8
            assert {c["status"] for c in cx} == {"affected", "unaffected"}
            if not ordinary:
                entry = invoke()["entries"][0]
                assert entry["coverage_state"] == "enumerated"
                assert entry["expected_total"] is None
                assert entry["duplicate_entries"] == 1
                assert entry["parse_failed"] == entry["retrieval_failed"] == 0
                assert entry["documents"]["error"] == 0
                assert entry["gaps"] == []
                assert entry["unknown_models"] == 2
                assert entry["source_url"] == DIRECTORY
                assert entry["portfolio_completeness"] == "not_established"
                assert "listing_duplicate_links" in entry["errors"]
                assert "overlapping_pages" not in entry["errors"]
    assert {p: sha256(p.read_bytes()).hexdigest() for p in protected} == before


def test_aruba_historical_text_missing_links_are_not_counted_as_duplicates():
    from dataclasses import replace

    from test_aruba_text_coverage import DIRECTORY, URL, signed_text

    from infrastructure_impact.plugins import ArchivePage, default_registry

    registry = default_registry()
    plugin = replace(registry.get("aruba"), parse_archive=lambda *_: ArchivePage((URL,), 4, 2))
    cfg = {"vendors": [], "archives": [{"vendor": "aruba", "kind": "listing", "url": DIRECTORY}]}
    get = registry.get
    with (
        connect(":memory:") as db,
        patch.object(
            registry, "get", side_effect=lambda vendor: plugin if vendor == "aruba" else get(vendor)
        ),
        patch.object(backfill, "fetch", return_value=b"synthetic listing"),
        patch("infrastructure_impact.collection.service.fetch", return_value=signed_text()),
    ):
        first = run(db, cfg, vendor="aruba")["entries"][0]
        again = run(db, cfg, vendor="aruba")["entries"][0]
        assert first["duplicate_entries"] == again["duplicate_entries"] == 1
        assert first["discovered_unique_identities"] == 1
        assert "entries_without_links" in first["errors"]
        assert (
            db.execute("SELECT entry_count FROM archive_items WHERE kind='page'").fetchone()[0] == 4
        )


@pytest.mark.parametrize("count,missing", [(True, 0), (-1, 0), (1, True), (1, -1), (1, 1)])
def test_aruba_historical_text_inconsistent_listing_counts_fail_visibly(count, missing):
    from test_aruba_text_coverage import DIRECTORY, URL

    with patch.object(
        backfill,
        "inventory",
        return_value=dict(
            urls=[URL], next_pages=[], entry_count=count, entries_without_links=missing
        ),
    ):
        with pytest.raises(ValueError, match="entry counts"):
            backfill._public_page(b"synthetic", DIRECTORY, {"vendor": "aruba", "kind": "index"})


def test_cli_requires_explicit_staging_vault_and_never_publishes(tmp_path, monkeypatch, capsys):
    from infrastructure_impact.cli import main

    cfg = tmp_path / "sources.json"
    cfg.write_text(json.dumps({"vendors": []}))
    monkeypatch.setenv("IMPACT_DATABASE", str(tmp_path / "staging.sqlite3"))
    monkeypatch.setenv("IMPACT_HOME", str(tmp_path))
    with patch(
        "infrastructure_impact.application.publication.build",
        side_effect=AssertionError("publication"),
    ):
        main(
            [
                "switching-backfill",
                "--config",
                str(cfg),
                "--start-date",
                "2021-01-01",
                "--end-date",
                "2026-11-04",
            ]
        )
    receipt = json.loads(capsys.readouterr().out)
    assert len(receipt["entries"]) == 3
    assert all(e["coverage_state"] == "not_configured" for e in receipt["entries"])
    assert not (tmp_path / "publications").exists()


def test_full_page_limit_reports_incomplete_instead_of_guessing_exhaustion():
    response = page([entry("unique")])
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", return_value=response),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        # Force the real documented boundary without issuing 100 requests.
        run(db, config(page_size=1), page_limit=1)
        db.execute("UPDATE switching_backfill_pages SET ordinal=100 WHERE evidence_id IS NULL")
        db.execute(
            "UPDATE archive_items SET url=? WHERE kind='page' AND state='pending'",
            (API + "all?pageIndex=100&pageSize=1",),
        )
        db.commit()
        e = run(db, config(page_size=1))["entries"][0]
        assert e["coverage_state"] != "enumerated"
        assert "publisher_page_limit" in e["errors"]


@pytest.mark.parametrize(
    "pages",
    [
        {1: page([entry("a")], total=100)},
        {1: page([entry("a"), entry("b")], total=3), 2: page([entry("c")])},
    ],
)
def test_inconsistent_totals_never_claim_stable_enumeration(pages):
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(pages, [])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        e = run(db)["entries"][0]
        assert e["coverage_state"] == "unstable"
        assert any(code.startswith("publisher_total_") for code in e["errors"])


def test_short_page_with_explicit_next_does_not_drop_candidates():
    requests = []
    responses = {
        1: page([entry("a")], next=API + "all?pageIndex=2&pageSize=2"),
        2: page([entry("b")]),
    }
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(responses, requests)),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        e = run(db)["entries"][0]
        assert e["discovered_unique_identities"] == 2
        assert len(requests) == 2


def test_unresolved_marker_blocks_reopened_vault_and_public_archive_documents(tmp_path):
    from infrastructure_impact.storage.switching import reserve_request

    path = tmp_path / "staging.sqlite3"
    with (
        connect(path) as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", return_value=page([entry("a")])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        run(db)
        db.execute("UPDATE archive_items SET state='pending' WHERE kind='document'")
        db.commit()
        reserve_request(db, "cisco_openvuln", "2021-01-01T00:00:00+00:00", pending=True)
    with (
        connect(path) as db,
        patch.object(backfill, "fetch", side_effect=AssertionError("network")),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=AssertionError("document I/O"),
        ),
    ):
        e = run(db)["entries"][0]
        assert e["coverage_state"] == "blocked"
        assert "request_state_unresolved" in e["errors"]
        assert e["documents"]["pending"] == 1
        assert db.execute("SELECT pending FROM switching_requests").fetchone()[0] == 1


def test_defaults_and_budgets_are_shared_across_vendor_sources():
    cfg = config()
    cfg["switching_sources"].append(
        dict(vendor="cisco", kind="openvuln", url=API + "year/2021", page_size=2)
    )
    requests = []
    responses = {1: page([entry("a"), entry("b")]), 2: page([entry("c"), entry("d")])}
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(responses, requests)),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        backfill.run(db, cfg, vendor="cisco", start_date="2021-01-01", end_date="2026-11-04")
        assert len(requests) == 2
        assert (
            db.execute(
                "SELECT count(*) FROM archive_items WHERE state='error' AND kind='document'"
            ).fetchone()[0]
            == 4
        )


def test_real_parser_ingests_once_and_reconciles_publisher_identity():
    from pathlib import Path

    raw = Path("tests/fixtures/aruba.json").read_bytes()
    cfg = {"vendors": [], "archives": [{"vendor": "aruba", "kind": "index", "url": ARUBA}]}
    with (
        connect(":memory:") as db,
        patch.object(backfill, "fetch", return_value=b"2022/example.json\n"),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=lambda db, url, vendor, *, fetcher=None: (url, raw),
        ),
    ):
        e = run(db, cfg, vendor="aruba")["entries"][0]
        again = run(db, cfg, vendor="aruba")["entries"][0]
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 1
        assert e["parsed"] == again["parsed"] == 1
        assert e["unknown_dates"] == 0
        assert e["identity_evidence"][0]["normalized_identity"] == "synthetic-aruba"
        assert e["identity_evidence"][0]["status"] == "final"
        assert e["classified"] == 0
        assert e["unknown_models"] == 1


def test_duplicate_identity_retains_changed_revision_and_withdrawal_observations():
    a = entry("a")
    revised = entry("a")
    revised.update(version="2.0", status="Withdrawn")
    responses = {1: page([a, entry("b")]), 2: page([revised])}
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(responses, [])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        e = run(db)["entries"][0]
        assert e["withdrawn_entries"] == 1
        a = e["identity_evidence"][0]
        assert a["revision"] == "2.0"
        assert [o["revision"] for o in a["observations"]] == ["1.0", "2.0"]
        assert a["observations"][1]["source_locator"] == "/advisories/0"


def test_retrieval_failure_is_not_a_parse_failure():
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", return_value=page([entry("a")])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=TimeoutError("offline"),
        ),
    ):
        e = run(db)["entries"][0]
        assert e["documents"]["error"] == 1
        assert e["parse_failed"] == 0
        assert e["retrieval_failed"] == 1


def test_persisted_cooldown_stops_public_document_io_after_enumeration():
    from infrastructure_impact.storage.switching import defer_request

    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", return_value=page([entry("a")])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        run(db)
        db.execute("UPDATE archive_items SET state='pending' WHERE kind='document'")
        db.commit()
        defer_request(
            db, "cisco_openvuln", "2099-01-01T00:00:00+00:00", retry_at="2099-01-02T00:00:00+00:00"
        )
        e = run(db)["entries"][0]
        assert e["coverage_state"] == "blocked"
        assert e["documents"]["pending"] == 1
        assert e["retry_at"] == "2099-01-02T00:00:00+00:00"


def test_api_page_indices_must_be_integers_not_booleans():
    with (
        connect(":memory:") as db,
        patch.object(
            backfill.CiscoOpenVuln, "get_json", return_value=page([entry("a")], pageIndex=True)
        ),
    ):
        e = run(db)["entries"][0]
        assert e["coverage_state"] == "blocked"
        assert e["checkpoint"]["next_page"] == 1


def test_document_interruption_after_ingest_is_idempotent_on_resume():
    from pathlib import Path

    raw = Path("tests/fixtures/aruba.json").read_bytes()
    cfg = {"vendors": [], "archives": [{"vendor": "aruba", "kind": "index", "url": ARUBA}]}
    with (
        connect(":memory:") as db,
        patch.object(backfill, "fetch", return_value=b"2022/example.json\n"),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=lambda db, url, vendor, *, fetcher=None: (url, raw),
        ),
    ):
        with patch(
            "infrastructure_impact.collection.archive.evidence", side_effect=KeyboardInterrupt
        ):
            with pytest.raises(KeyboardInterrupt):
                run(db, cfg, vendor="aruba")
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 1
        e = run(db, cfg, vendor="aruba")["entries"][0]
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 1
        assert e["documents"]["done"] == 1


@pytest.mark.parametrize("size", [0, 101, True, "100"])
def test_invalid_api_page_size_precedes_io(size):
    with connect(":memory:") as db, pytest.raises(ValueError):
        run(db, config(page_size=size))


def test_definition_identity_is_independent_and_queue_counts_are_explicit():
    from copy import deepcopy

    from infrastructure_impact.application.switching_evidence import definition

    changed = deepcopy(definition())
    changed["version"] += 1
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", return_value=page([entry("a")])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        first = run(db)["entries"][0]
        with patch.object(backfill, "definition", return_value=changed):
            result = run(db)
        assert len(result["entries"]) == 2
        assert result["entries"][1]["definition_sha256"] != first["definition_sha256"]
        assert result["entries"][1]["run_id"] != first["run_id"]
        assert first["pages"] == {"retained": 1, "pending": 0}
        assert first["window"]["start_date"] == "2021-01-01"


def test_cli_staging_does_not_mutate_protected_resources_or_native_vault(
    tmp_path, monkeypatch, capsys
):
    import hashlib
    from pathlib import Path

    from infrastructure_impact.cli import main

    paths = [Path("sources.json"), Path("infrastructure_impact/resources/sources.json")]
    paths += list(Path(".github/workflows").glob("*"))
    paths = [p for p in paths if p.is_file()]
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    native = tmp_path / "native.sqlite3"
    native.write_bytes(b"native vault sentinel")
    native_stat = native.stat()
    cfg = tmp_path / "staging-sources.json"
    cfg.write_text('{"vendors":[]}')
    monkeypatch.setenv("IMPACT_HOME", str(tmp_path / "staging"))
    monkeypatch.setenv("IMPACT_DATABASE", str(tmp_path / "staging/vault.sqlite3"))
    main(
        [
            "switching-backfill",
            "--config",
            str(cfg),
            "--start-date",
            "2021-01-01",
            "--end-date",
            "2026-11-04",
        ]
    )
    capsys.readouterr()
    assert {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths} == before
    assert native.read_bytes() == b"native vault sentinel"
    assert native.stat().st_mtime_ns == native_stat.st_mtime_ns


def test_changing_batch_budgets_does_not_reset_logical_run():
    cfg = {
        "vendors": [],
        "archives": [
            {"vendor": "aruba", "kind": "index", "url": ARUBA, "page_limit": 1, "document_limit": 1}
        ],
    }
    with (
        connect(":memory:") as db,
        patch.object(backfill, "fetch", return_value=b"2022/example.json\n"),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        first = run(db, cfg, vendor="aruba")["entries"][0]["run_id"]
        cfg["archives"][0].update(page_limit=2, document_limit=8)
        result = run(db, cfg, vendor="aruba")
        assert len(result["entries"]) == 1
        assert result["entries"][0]["run_id"] == first


@pytest.mark.parametrize(
    "first_url",
    [None, "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/old-a"],
)
def test_duplicate_occurrences_keep_all_document_memberships(first_url):
    first = entry("a")
    first["publicationUrl"] = first_url
    later = entry("a")
    responses = {1: page([first]), 2: page([later]), 3: page([])}
    urls = []

    def resolve(db, url, vendor, *, fetcher=None):
        urls.append(url)
        raise ValueError("unsupported")

    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(responses, [])),
        patch("infrastructure_impact.collection.archive.resolve_document", side_effect=resolve),
    ):
        e = run(db, config(page_size=1), page_limit=3)["entries"][0]
        expected_urls = ([first_url] if first_url else []) + [later["publicationUrl"]]
        assert e["documents"]["error"] == len(expected_urls)
        assert urls == expected_urls
        assert e["identity_evidence"][0]["alternate_urls"] == expected_urls
        assert e["identity_evidence"][0]["observations"][1]["alternate_urls"] == [
            later["publicationUrl"]
        ]
        assert e["discovered_unique_identities"] == 1
        assert (
            sum(e["documents"].values())
            == db.execute("SELECT count(*) FROM archive_items WHERE kind='document'").fetchone()[0]
        )
        run(db, config(page_size=1), page_limit=3)
        assert urls == expected_urls  # deferred errors do not immediately re-run


def test_all_advertised_alternates_are_durable_document_members():
    a = entry("a", csafUrl="https://www.cisco.com/.well-known/csaf/2024/a.json")
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", return_value=page([a])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        e = run(db)["entries"][0]
        assert e["documents"]["error"] == 2
        assert e["identity_evidence"][0]["observations"][0]["alternate_urls"] == [
            a["csafUrl"],
            a["publicationUrl"],
        ]


def test_listing_failures_persist_attempts_backoff_and_exhaustion_across_reopen(tmp_path):
    from datetime import datetime, timezone

    cfg = {"vendors": [], "archives": [{"vendor": "arista", "kind": "listing", "url": ARISTA}]}
    path = tmp_path / "staging.sqlite3"
    requested = []

    def timeout(db, url, vendor):
        requested.append(url)
        raise TimeoutError("listing unavailable")

    with connect(path) as db, patch.object(backfill, "fetch", side_effect=timeout):
        run(db, cfg, vendor="arista")
    with connect(path) as db, patch.object(backfill, "fetch", side_effect=timeout):
        e = run(db, cfg, vendor="arista")["entries"][0]
        item = db.execute("SELECT * FROM archive_items WHERE kind='page'").fetchone()
        assert requested == [ARISTA]
        assert item["state"] == "error"
        assert item["attempts"] == 1
        assert item["error_code"] == "network_error"
        assert datetime.fromisoformat(item["retry_after"]) > datetime.now(timezone.utc)
        assert e["checkpoint"]["next_page"] == 1
        db.execute("UPDATE archive_items SET retry_after='2021-01-01T00:00:00+00:00'")
        db.commit()
        run(db, cfg, vendor="arista")
        assert len(requested) == 2
        db.execute("UPDATE archive_items SET attempts=5,retry_after='2021-01-01T00:00:00+00:00'")
        db.commit()
        run(db, cfg, vendor="arista")
        assert len(requested) == 2
        assert db.execute("SELECT attempts FROM archive_items WHERE kind='page'").fetchone()[0] == 5


def test_publisher_page_limit_keeps_bounded_document_drain_resumable():
    responses = {1: page([entry("a"), entry("b")]), 2: page([])}
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(responses, [])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        run(db, document_limit=1)
        db.execute("UPDATE switching_backfills SET error_code='publisher_page_limit',enumerated=0")
        db.commit()
        with patch.object(
            backfill.CiscoOpenVuln, "get_json", side_effect=AssertionError("listing must stop")
        ):
            e = run(db, document_limit=1)["entries"][0]
        assert e["coverage_state"] != "enumerated"
        assert "publisher_page_limit" in e["errors"]
        assert e["documents"]["error"] == 2
        assert e["documents"]["pending"] == 0


def test_membership_migration_repairs_pre014_orphans_and_unqueued_alternates():
    from infrastructure_impact.storage.migrations import migrate

    first = entry("a")
    first["publicationUrl"] = None
    later = entry("a", csafUrl="https://www.cisco.com/.well-known/csaf/2024/a.json")
    responses = {1: page([first]), 2: page([later]), 3: page([])}
    with (
        connect(":memory:") as db,
        patch.object(backfill.CiscoOpenVuln, "get_json", capture(responses, [])),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("blocked"),
        ),
    ):
        run(db, config(page_size=1), page_limit=3)
        # Model already-applied013: first entry pointer NULL; later occurrence
        # has an orphaned selected CSAF item and an unqueued HTML alternate.
        assert db.execute("SELECT item_id FROM switching_backfill_entries").fetchone()[0] is None
        db.execute("DROP TABLE switching_backfill_documents")
        db.execute("DELETE FROM schema_migrations WHERE version=14")
        db.execute(
            "DELETE FROM archive_links WHERE item_id IN (SELECT id FROM archive_items WHERE url=?)",
            (later["publicationUrl"],),
        )
        db.execute("DELETE FROM archive_items WHERE url=?", (later["publicationUrl"],))
        old = dict(db.execute("SELECT * FROM archive_items WHERE kind='document'").fetchone())
        checksum = db.execute("SELECT checksum FROM schema_migrations WHERE version=13").fetchone()[
            0
        ]
        db.commit()
        migrate(db)
        assert (
            db.execute("SELECT checksum FROM schema_migrations WHERE version=13").fetchone()[0]
            == checksum
        )
        assert db.execute("SELECT count(*) FROM switching_backfill_documents").fetchone()[0] == 2
        assert (
            db.execute(
                "SELECT count(*) FROM archive_links WHERE item_id IN (SELECT id FROM archive_items WHERE kind='document')"
            ).fetchone()[0]
            == 2
        )
        adopted = dict(
            db.execute("SELECT * FROM archive_items WHERE id=?", (old["id"],)).fetchone()
        )
        assert adopted == old
        e = backfill.manifest(db, study_id="campus-branch-switching")["entries"][0]
        assert e["documents"]["error"] == 1
        assert e["documents"]["pending"] == 1
        e = run(db, config(page_size=1), page_limit=3)["entries"][0]
        assert e["documents"]["error"] == 2
        assert e["documents"]["pending"] == 0


def test_api_page_failure_keeps_transport_cooldown_boundary():
    boundary = "2099-01-02T00:00:00+00:00"
    requested = []

    def limited(self, url):
        requested.append(url)
        raise CiscoAccessError("rate_limited", retry_at=boundary)

    with connect(":memory:") as db, patch.object(backfill.CiscoOpenVuln, "get_json", limited):
        e = run(db)["entries"][0]
        item = db.execute("SELECT * FROM archive_items WHERE kind='page'").fetchone()
        assert item["state"] == "error"
        assert item["attempts"] == 1
        assert item["retry_after"] == boundary
        assert e["retry_at"] == boundary
        assert e["checkpoint"]["next_page"] == 1
        run(db)
        assert len(requested) == 1
