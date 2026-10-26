"""Historical queue acceptance: bounded work, crash recovery, scope and failures."""

import copy
import json
from unittest.mock import patch

import pytest

from infrastructure_impact.application.source_audit import source_audit
from infrastructure_impact.collection.archive import progress, run
from infrastructure_impact.collection.config import validate_config
from infrastructure_impact.storage.repository import connect, latest

ROOT = "https://csaf.arubanetworking.hpe.com/index.txt"
CONFIG = {
    "vendors": [],
    "archives": [{"vendor": "aruba", "url": ROOT, "kind": "index", "document_limit": 1}],
}


def document(url):
    return json.dumps(
        {
            "document": {
                "title": "Synthetic historical advisory",
                "tracking": {
                    "id": url.rsplit("/", 1)[-1],
                    "status": "final",
                    "initial_release_date": "2022-01-01T00:00:00Z",
                },
            },
            "product_tree": {"full_product_names": [{"product_id": "r", "name": "Example router"}]},
            "vulnerabilities": [
                {"cve": "CVE-2022-12345", "product_status": {"known_affected": ["r"]}}
            ],
        }
    ).encode()


def test_restart_resumes_documents_and_new_index_links_are_additive(tmp_path):
    path = tmp_path / "vault.sqlite3"
    index = [b"one.json\ntwo.json\n"]
    docs = []

    def resolve(db, url, vendor):
        docs.append(url)
        return url, document(url)

    with (
        patch("infrastructure_impact.collection.archive.fetch", side_effect=lambda *_: index[0]),
        patch("infrastructure_impact.collection.archive.resolve_document", side_effect=resolve),
    ):
        assert run(CONFIG, path) == (1, 0)
        with connect(path) as db:
            status = progress(db, latest(db), CONFIG)[0]
            assert status["documents"] == dict(pending=1, done=1, not_applicable=0, error=0)
            assert status["publisher_date_range"]["earliest"].startswith("2022-01-01")
            assert not status["known_queue_exhausted"]
        assert run(CONFIG, path) == (1, 0)
        assert run(CONFIG, path) == (0, 0)
        assert len(docs) == 2
        index[0] = b"two.json\nthree.json\n"
        assert run(CONFIG, path) == (1, 0)
        with connect(path) as db:
            status = progress(db, latest(db), CONFIG)[0]
            assert status["discovered_documents"] == 3  # Removed links do not delete history.
            assert status["known_queue_exhausted"]
            assert status["portfolio_completeness"] == "not_established"


def test_pagination_is_bounded_resumable_and_cycles_do_not_loop(tmp_path):
    path = tmp_path / "vault.sqlite3"
    config = {
        "vendors": [],
        "archives": [{"vendor": "aruba", "url": ROOT, "kind": "rss", "page_limit": 1}],
    }
    page2 = "https://csaf.arubanetworking.hpe.com/page2"
    responses = {
        ROOT: b'<feed xmlns="http://www.w3.org/2005/Atom"><link rel="next" href="page2"/><entry><link href="one.json"/></entry></feed>',
        page2: b'<feed xmlns="http://www.w3.org/2005/Atom"><link rel="next" href="index.txt"/><entry><link href="two.json"/></entry></feed>',
    }
    requested = []

    def fetch(db, url, vendor):
        requested.append(url)
        return responses[url]

    with (
        patch("infrastructure_impact.collection.archive.fetch", side_effect=fetch),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=lambda db, url, vendor: (url, document(url)),
        ),
    ):
        assert run(config, path) == (1, 0)
        assert requested == [ROOT]
        assert run(config, path) == (1, 0)
        assert requested == [ROOT, page2]  # A one-page budget must not starve page two.
        assert run(config, path, page_limit=2) == (0, 0)
        with connect(path) as db:
            assert (
                db.execute("SELECT count(*) FROM archive_items WHERE kind='page'").fetchone()[0]
                == 2
            )
        responses[page2] = responses[page2].replace(b"two.json", b"three.json")
        assert run(config, path, refresh_pages=True, page_limit=2) == (1, 0)


def test_backoff_and_exhausted_errors_remain_visible_and_manual_retry_is_explicit(tmp_path):
    path = tmp_path / "vault.sqlite3"
    with (
        patch("infrastructure_impact.collection.archive.fetch", return_value=b"one.json\n"),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=ValueError("SYNTHETIC_PRIVATE_ERROR_BODY"),
        ) as resolve,
    ):
        assert run(CONFIG, path) == (0, 1)
        assert run(CONFIG, path) == (0, 0)  # Backoff, not a false success.
        assert resolve.call_count == 1
        with connect(path) as db:
            db.execute(
                "UPDATE archive_items SET attempts=5,retry_after='2000-01-01' WHERE kind='document'"
            )
        assert run(CONFIG, path) == (0, 0)
        with connect(path) as db:
            status = source_audit(db, [], CONFIG)
            archive = next(v for v in status["vendors"] if v["vendor"] == "aruba")["archives"][0]
            assert archive["exhausted_errors"] == 1
            assert not archive["known_queue_exhausted"]
            assert "SYNTHETIC_PRIVATE_ERROR_BODY" not in json.dumps(status)
        assert run(CONFIG, path, retry_errors=True) == (0, 1)


def test_crash_after_ingest_before_queue_commit_replays_without_duplicate_revision(tmp_path):
    path = tmp_path / "vault.sqlite3"
    from infrastructure_impact.collection import archive

    real_ingest = archive.ingest

    def interrupted(*args, **kwargs):
        real_ingest(*args, **kwargs)
        raise KeyboardInterrupt

    with (
        patch("infrastructure_impact.collection.archive.fetch", return_value=b"one.json\n"),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=lambda db, url, vendor: (url, document(url)),
        ),
    ):
        with (
            patch("infrastructure_impact.collection.archive.ingest", side_effect=interrupted),
            pytest.raises(KeyboardInterrupt),
        ):
            run(CONFIG, path)
        assert run(CONFIG, path) == (0, 0)
        with connect(path) as db:
            assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 1
            assert progress(db, latest(db), CONFIG)[0]["known_queue_exhausted"]


def test_untrusted_links_and_unlinked_entries_prevent_exhaustion_claim(tmp_path):
    config = copy.deepcopy(CONFIG)
    config["archives"][0]["kind"] = "rss"
    raw = b'<rss><channel><item><link>https://untrusted.example/x</link></item><item><title>Missing</title></item><atom:link xmlns:atom="http://www.w3.org/2005/Atom" rel="next" href="http://csaf.arubanetworking.hpe.com/page2"/></channel></rss>'
    path = tmp_path / "vault.sqlite3"
    with (
        patch("infrastructure_impact.collection.archive.fetch", return_value=raw),
        patch("infrastructure_impact.collection.archive.resolve_document") as resolve,
    ):
        assert run(config, path) == (0, 0)
        resolve.assert_not_called()
    with connect(path) as db:
        status = progress(db, [], config)[0]
        assert status["discovery_link_gaps"] == 3
        assert not status["known_queue_exhausted"]
        assert not status["publisher_date_range"]["earliest"]


def test_malformed_page_is_error_not_empty_archive(tmp_path):
    path = tmp_path / "vault.sqlite3"
    with patch(
        "infrastructure_impact.collection.archive.fetch",
        return_value=b"<html>Application shell</html>",
    ):
        assert run(CONFIG, path) == (0, 1)
    with connect(path) as db:
        assert progress(db, [], CONFIG)[0]["pages"]["error"] == 1
        assert not progress(db, [], CONFIG)[0]["known_queue_exhausted"]


@pytest.mark.parametrize(
    "changes",
    [
        {"url": "https://untrusted.example/index.txt"},
        {"kind": "html"},
        {"page_limit": True},
        {"document_limit": 201},
        {"page_limit": 0},
        {"unknown": 1},
    ],
)
def test_archive_configuration_rejects_unsafe_or_unbounded_sources(changes):
    config = copy.deepcopy(CONFIG)
    config["archives"][0].update(changes)
    with pytest.raises(ValueError):
        validate_config(config)


def test_metadata_only_vendor_feed_cannot_be_misclassified_as_document_archive():
    config = {
        "vendors": [],
        "archives": [
            {"vendor": "juniper", "kind": "rss", "url": "https://supportportal.juniper.net/rss"}
        ],
    }
    with pytest.raises(ValueError, match="document-link"):
        validate_config(config)


def test_discovery_edges_retain_each_index_revision_and_progress_has_no_raw_bytes(tmp_path):
    path = tmp_path / "vault.sqlite3"
    index = [b"one.json\n"]
    with (
        patch("infrastructure_impact.collection.archive.fetch", side_effect=lambda *_: index[0]),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=lambda db, url, vendor: (url, document(url)),
        ),
    ):
        run(CONFIG, path)
        index[0] = b"one.json\ntwo.json\n"
        run(CONFIG, path)
    with connect(path) as db:
        assert db.execute("SELECT count(*) FROM archive_links").fetchone()[0] == 3
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        public = json.dumps(progress(db, latest(db), CONFIG))
        assert "page_evidence" in public
        assert "Synthetic historical advisory" not in public
        assert '"raw"' not in public


def test_archive_progress_survives_sanitized_publication_and_api(tmp_path, monkeypatch):
    from infrastructure_impact.application.publication import publish
    from infrastructure_impact.application.query import state
    from infrastructure_impact.http import Application

    path = tmp_path / "vault.sqlite3"
    config_path = tmp_path / "sources.json"
    config_path.write_text(json.dumps(CONFIG))
    monkeypatch.setenv("IMPACT_SOURCES", str(config_path))
    with (
        patch(
            "infrastructure_impact.collection.archive.fetch", return_value=b"one.json\ntwo.json\n"
        ),
        patch(
            "infrastructure_impact.collection.archive.resolve_document",
            side_effect=lambda db, url, vendor: (url, document(url)),
        ),
    ):
        run(CONFIG, path)
    with connect(path) as db:
        data = state(db)
    public_root = tmp_path / "publications"
    generation = publish(data, root=public_root)
    public = json.loads((generation / "source-audit.json").read_text())
    archive = next(v for v in public["vendors"] if v["vendor"] == "aruba")["archives"][0]
    assert archive["documents"]["done"] == 1
    assert archive["documents"]["pending"] == 1
    status, _, body = Application(public_root).route(
        {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/source-audit"}
    )
    assert status == 200
    assert json.loads(body)["vendors"] == public["vendors"]
