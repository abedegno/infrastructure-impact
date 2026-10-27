"""Parser recovery uses retained bytes, keeps HTTP backoff, and records provenance."""

import json
from unittest.mock import patch
from urllib.error import HTTPError

from infrastructure_impact.application.jobs import execute
from infrastructure_impact.collection.archive import enqueue, fail, run
from infrastructure_impact.collection.archive_replay import reprocess_errors
from infrastructure_impact.collection.service import ResolvedSource
from infrastructure_impact.plugins import SourceSelection, SourceView, default_registry
from infrastructure_impact.storage.archive_replays import summary
from infrastructure_impact.storage.repository import (
    collection_result,
    connect,
    evidence,
    health,
    latest,
    now,
)

ROOT = "https://csaf.arubanetworking.hpe.com/index.txt"
URL = "https://csaf.arubanetworking.hpe.com/one.json"
OTHER = "https://csaf.arubanetworking.hpe.com/two.json"
CONFIG = {
    "vendors": [],
    "archives": [{"vendor": "aruba", "url": ROOT, "kind": "index", "document_limit": 1}],
}


def document():
    return json.dumps(
        {
            "document": {
                "title": "Synthetic retained advisory",
                "tracking": {"id": "synthetic-one", "status": "final"},
            },
            "product_tree": {"full_product_names": [{"product_id": "r", "name": "Example router"}]},
            "vulnerabilities": [
                {"cve": "CVE-2025-12345", "product_status": {"known_affected": ["r"]}}
            ],
        }
    ).encode()


def seed(db, *, raw=None, retain=True, http_error=False, version="old-parser"):
    with db:
        cursor = db.execute(
            "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
            ("aruba", ROOT, "index", now()),
        )
        source = dict(
            db.execute("SELECT * FROM archive_sources WHERE id=?", (cursor.lastrowid,)).fetchone()
        )
        enqueue(db, source["id"], "document", URL)
        item = db.execute(
            "SELECT * FROM archive_items WHERE source_id=?", (source["id"],)
        ).fetchone()
        if retain:
            evidence(db, document() if raw is None else raw, URL)
    error = (
        HTTPError(URL, 403, "Denied", {}, None)
        if http_error
        else ValueError("Synthetic unsupported old parser")
    )
    with patch.object(default_registry(), "fingerprint", return_value=version):
        fail(db, source, item, error)
    return source, dict(
        db.execute("SELECT * FROM archive_items WHERE id=?", (item["id"],)).fetchone()
    )


def test_updated_parser_recovers_without_network_or_new_observations_and_is_idempotent():
    with connect(":memory:") as db:
        source, original = seed(db)
        captured = dict(db.execute("SELECT * FROM evidence").fetchone())
        with patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No HTTP during parser recovery"),
        ):
            result = reprocess_errors(db, source, 1)
            assert result["recovered"] == result["imported"] == result["attempted"] == 1
            assert reprocess_errors(db, source, 1)["attempted"] == 0
        item = db.execute("SELECT * FROM archive_items").fetchone()
        assert item["state"] == "done" and item["attempts"] == 0 and item["retry_after"] is None
        assert latest(db)[0]["source_observed_at"] == captured["observed_at"]
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
        assert not db.execute("SELECT 1 FROM source_observations").fetchone()
        assert not db.execute("SELECT 1 FROM changes").fetchone()
        assert health(db)[0]["outcome"] == "reprocessed"
        from infrastructure_impact.application.catalogue import catalogue

        profile = next(
            p for p in catalogue(db, latest(db), config=CONFIG)["vendors"] if p["vendor"] == "aruba"
        )
        assert profile["freshness"] == "not_checked" and profile["last_successful_check"] is None
        report = summary(db, source["id"])
        assert report["attempts"] == report["recovered"] == 1
        assert report["examples"][0]["source_sha256"] == captured["sha256"]
        assert report["examples"][0]["source_observed_at"] == captured["observed_at"]
        assert original["retry_after"] is not None


def test_same_parser_and_http_denials_are_not_retried_by_offline_recovery():
    for http_error in [False, True]:
        with connect(":memory:") as db:
            source, original = seed(
                db, http_error=http_error, version=default_registry().fingerprint("aruba")
            )
            with patch(
                "infrastructure_impact.collection.transport.build_opener",
                side_effect=AssertionError("No HTTP"),
            ):
                assert reprocess_errors(db, source, 10)["attempted"] == 0
            item = dict(db.execute("SELECT * FROM archive_items").fetchone())
            assert item == original
            assert summary(db, source["id"])["attempts"] == 0


def test_still_unsupported_and_missing_captures_keep_network_attempts_and_retry_time():
    for retain in [False, True]:
        with connect(":memory:") as db:
            source, original = seed(db, retain=retain, raw=b"{}")
            before_checks = db.execute("SELECT COUNT(*) FROM collection_runs").fetchone()[0]
            with patch(
                "infrastructure_impact.collection.transport.build_opener",
                side_effect=AssertionError("No HTTP"),
            ):
                result = reprocess_errors(db, source, 1)
                assert result["not_retained" if not retain else "still_unsupported"] == 1
                assert reprocess_errors(db, source, 1)["attempted"] == 0
            item = db.execute("SELECT * FROM archive_items").fetchone()
            assert item["state"] == "error" and item["attempts"] == original["attempts"]
            assert item["retry_after"] == original["retry_after"]
            if not retain:
                assert (
                    db.execute("SELECT COUNT(*) FROM collection_runs").fetchone()[0]
                    == before_checks
                )
            assert not db.execute("SELECT 1 FROM source_observations").fetchone()
            assert summary(db, source["id"])["examples"][0]["source_sha256"] is None


def test_replay_work_shares_the_document_budget_and_does_not_fetch_pending_documents(tmp_path):
    path = tmp_path / "budget.sqlite"
    with connect(path) as db:
        source, _ = seed(db)
        enqueue(db, source["id"], "document", OTHER)
    with (
        patch(
            "infrastructure_impact.collection.archive.fetch",
            return_value=(URL + "\n" + OTHER + "\n").encode(),
        ) as page_fetch,
        patch(
            "infrastructure_impact.collection.service.fetch",
            side_effect=AssertionError("Document budget consumed by retained replay"),
        ),
    ):
        assert run(CONFIG, path) == (1, 0)
        assert page_fetch.call_count == 1
    with connect(path) as db:
        assert (
            db.execute("SELECT state FROM archive_items WHERE url=?", (URL,)).fetchone()[0]
            == "done"
        )
        assert (
            db.execute("SELECT state FROM archive_items WHERE url=?", (OTHER,)).fetchone()[0]
            == "pending"
        )


def test_retained_selection_processing_does_not_clear_an_alternates_live_http_error():
    with connect(":memory:") as db:
        source, _ = seed(db)
        collection_result(
            db, "aruba", OTHER, "error", "Previous real transport failure", "access_denied"
        )
        selected = SourceSelection(
            SourceView(URL, document(), "CSAF", 1, "synthetic/1"),
            (SourceView(OTHER, document(), "CSAF", 1, "synthetic/1"),),
            "Synthetic reviewed choice",
        )
        resolution = ResolvedSource(URL, document(), selection=selected, requested_url=URL)
        with patch(
            "infrastructure_impact.collection.archive.resolve_document", return_value=resolution
        ):
            assert reprocess_errors(db, source, 1)["recovered"] == 1
        assert next(r for r in health(db) if r["source_url"] == OTHER)["outcome"] == "error"
        assert db.execute("SELECT COUNT(*) FROM source_selections").fetchone()[0] == 1
        assert not db.execute("SELECT 1 FROM source_observations").fetchone()


def test_valid_retained_recovery_can_publish_with_network_failures_but_stays_partial(tmp_path):
    path = tmp_path / "job.sqlite"
    built = []

    def collect():
        with connect(path) as db:
            collection_result(db, "aruba", ROOT, "error", "Network unavailable", "network_error")
            collection_result(
                db, "aruba", URL, "reprocessed", "Validated retained capture; no HTTP", None
            )
        return 1, 1

    result = execute(collect, lambda: (0, 0), lambda: None, lambda: built.append(True), path)
    assert result["outcome"] == "partial" and built == [True]


def test_exhausted_unsupported_capture_can_recover_without_bypassing_http_retry_limits():
    with connect(":memory:") as db:
        source, original = seed(db)
        db.execute("UPDATE archive_items SET attempts=5 WHERE id=?", (original["id"],))
        with patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("No HTTP"),
        ):
            assert reprocess_errors(db, source, 1)["recovered"] == 1
        assert db.execute("SELECT state FROM archive_items").fetchone()[0] == "done"
        assert not db.execute("SELECT 1 FROM source_observations").fetchone()
