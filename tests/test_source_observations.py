"""Retrieval history, cache validation, byte reversions and public metadata limits."""

import io
import json
import sqlite3
from pathlib import Path
from shutil import copyfile
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from infrastructure_impact.application.fix_leads import public_retrieval_history
from infrastructure_impact.collection.errors import AccessVerificationRequired
from infrastructure_impact.collection.transport import fetch
from infrastructure_impact.storage.observations import history, observe
from infrastructure_impact.storage.repository import connect, evidence

URL = "https://docs.fortinet.com/document/fortigate/7.2.7/fortios-release-notes/example"


class Response:
    status = 200
    headers = {"ETag": "PRIVATE_HEADER_SENTINEL"}

    def __init__(self, raw):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, limit):
        return self.raw[:limit]


def test_unchanged_304_and_a_to_b_to_a_are_distinct_retrieval_events_not_new_evidence():
    with (
        connect(":memory:") as db,
        patch("infrastructure_impact.collection.transport.build_opener") as opener,
    ):
        opener.return_value.open.side_effect = [
            Response(b"A"),
            HTTPError(URL, 304, "Not Modified", {}, io.BytesIO()),
            Response(b"B"),
            Response(b"A"),
            Response(b"A"),
        ]
        assert fetch(db, URL, "fortinet") == b"A"
        assert fetch(db, URL, "fortinet") == b"A"
        assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1
        for expected in [b"B", b"A", b"A"]:
            assert fetch(db, URL, "fortinet") == expected
        result = history(db, "fortinet", URL)
        assert result["logged_checks"] == 5 and result["distinct_fingerprints"] == 2
        assert result["same_as_previous_checks"] == 2 and result["http_304_checks"] == 1
        assert [c["content_state"] for c in result["checks"]] == [
            "same_as_previous_capture",
            "different_from_previous_capture",
            "different_from_previous_capture",
            "same_as_previous_capture",
            "first_logged_capture",
        ]
        assert (
            opener.return_value.open.call_args_list[1].args[0].headers["If-none-match"]
            == "PRIVATE_HEADER_SENTINEL"
        )
        assert "PRIVATE_HEADER_SENTINEL" not in json.dumps(result)


def test_access_challenges_are_retained_but_not_successful_document_retrievals():
    raw = b'<!DOCTYPE html><title>Client Challenge</title><script src="/_fs-ch-example/script.js"></script>JavaScript is disabled'
    with (
        connect(":memory:") as db,
        patch("infrastructure_impact.collection.transport.build_opener") as opener,
    ):
        opener.return_value.open.return_value = Response(raw)
        with pytest.raises(AccessVerificationRequired):
            fetch(db, URL, "fortinet")
        assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1
        assert history(db, "fortinet", URL)["logged_checks"] == 0


def test_retrieval_observations_cannot_claim_failures_or_another_urls_evidence():
    with connect(":memory:") as db:
        ev = evidence(db, b"A", URL)
        for status in [403, 500, True]:
            with pytest.raises(ValueError):
                observe(db, "fortinet", URL, ev["id"], status)
        with pytest.raises(ValueError):
            observe(db, "fortinet", URL + "-other", ev["id"], 200)


def test_history_is_bounded_and_no_older_checks_are_fabricated():
    with connect(":memory:") as db:
        ev = evidence(db, b"A", URL)
        for _ in range(15):
            observe(db, "fortinet", URL, ev["id"], 200)
        result = history(db, "fortinet", URL, limit=14)
        result["PRIVATE_OPERATOR_SENTINEL"] = "private"
        result["checks"][0]["PRIVATE_OPERATOR_SENTINEL"] = "private"
        projected = public_retrieval_history(result)
        assert projected["logged_checks"] == 15 and len(projected["checks"]) == 12
        assert projected["checks_truncated"] and "PRIVATE_OPERATOR_SENTINEL" not in json.dumps(
            projected
        )
        with pytest.raises(ValueError):
            history(db, "fortinet", URL, limit=0)
    old = sqlite3.connect(":memory:")
    assert history(old, "fortinet", URL)["first_logged_check_at"] is None
    assert old.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0
    old.close()


def test_additive_migration_preserves_old_evidence_without_backfilling_checks(tmp_path):
    from infrastructure_impact.storage.migrations import migrate

    old_migrations = tmp_path / "old"
    old_migrations.mkdir()
    source = Path(__file__).resolve().parents[1] / "infrastructure_impact/migrations"
    for file in source.glob("00[1-6]_*.sql"):
        copyfile(file, old_migrations / file.name)
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    migrate(db, old_migrations)
    ev = evidence(db, b"previously retained", URL)
    db.commit()
    migrate(db)
    assert (
        db.execute("SELECT sha256 FROM evidence WHERE id=?", (ev["id"],)).fetchone()[0]
        == ev["sha256"]
    )
    assert history(db, "fortinet", URL)["logged_checks"] == 0
    observe(db, "fortinet", URL, ev["id"], 200)
    migrate(db)
    assert history(db, "fortinet", URL)["logged_checks"] == 1
    db.close()


def test_vault_audit_rejects_cross_url_observation_relationships(tmp_path, monkeypatch):
    from infrastructure_impact.storage.audit import audit

    path = tmp_path / "vault.sqlite3"
    monkeypatch.setenv("IMPACT_DATABASE", str(path))
    with connect(path) as db:
        ev = evidence(db, b"retained", URL)
        observe(db, "fortinet", URL, ev["id"], 200)
        db.execute("UPDATE source_observations SET source_url=?", (URL + "-other",))
    with pytest.raises(ValueError, match="URL mismatch"):
        audit()
