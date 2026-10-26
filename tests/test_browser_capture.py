"""Provenance, history completeness and HTTP/browser separation contracts."""

import hashlib
import io
import json
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.error import HTTPError

import pytest
from jsonschema import ValidationError

from infrastructure_impact.application.browser_capture import captures, import_capture
from infrastructure_impact.application.publication import public_projection
from infrastructure_impact.application.query import state
from infrastructure_impact.collection.errors import SourceHTTPError, failure_code
from infrastructure_impact.collection.transport import fetch
from infrastructure_impact.storage.repository import collection_result, connect, health

URL = "https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/4100i%20Release%20Notes/aos-cx-10-13-xx/version-history-43.html"
AT = datetime(2026, 10, 26, tzinfo=timezone.utc)


def envelope(rows=None):
    rows = rows or [("10.13.1030", "27/06/2024")]
    table = "".join(
        f"<tr><td>{v}</td><td>{d}</td><td>Released, fully supported, and posted on the Web.</td></tr>"
        for v, d in rows
    )
    html = (
        "<article><h1>Version history</h1><table><tr><th>Version number</th><th>Release date</th><th>Remarks</th></tr>"
        + table
        + "</table><p>PRIVATE_CAPTURE_SENTINEL</p></article>"
    )
    return dict(
        schema_version=1,
        vendor="aruba",
        source_url=URL,
        captured_at=AT.isoformat(),
        capture_method="browser_dom",
        capture_scope="visible_main_article",
        browser_name="Example browser",
        rendered_html=html,
        rendered_sha256=hashlib.sha256(html.encode()).hexdigest(),
    )


def test_browser_capture_does_not_repair_http_health_or_invent_missing_date():
    with connect(":memory:") as db:
        collection_result(db, "aruba", URL, "error", "Denied", "edge_access_denied")
        raw = json.dumps(envelope()).encode()
        report = import_capture(db, raw, expected_version="10.13.1031", at=AT)
        assert report["completeness"] == "selected_version_missing"
        assert report["releases"][0]["reported_released_at"] == "2024-06-27"
        assert not any(r["version"] == "10.13.1031" for r in report["releases"])
        import_capture(db, raw, expected_version="10.13.1031", at=AT)
        assert len(captures(db)) == 1
        other = import_capture(db, raw, expected_version="10.13.1030", at=AT)
        assert other["completeness"] == "not_established"
        assert len(captures(db)) == 2
        assert health(db)[0]["error_code"] == "edge_access_denied"
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM fix_evidence").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM release_assets").fetchone()[0] == 0
        data = state(db)
        data["research"]["browser_captures"] = [report]
        public = json.dumps(public_projection(data, [URL]))
        assert "PRIVATE_CAPTURE_SENTINEL" not in public
        assert "browser_captures" not in public
        assert "rendered_html" not in json.dumps(report)


def test_duplicate_and_conflicting_dates_are_reported_without_guessing():
    with connect(":memory:") as db:
        raw = json.dumps(
            envelope(
                [
                    ("10.13.1030", "27/06/2024"),
                    ("10.13.1030", "27/06/2024"),
                    ("10.13.1030", "28/06/2024"),
                ]
            )
        ).encode()
        report = import_capture(db, raw, expected_version="10.13.1030", at=AT)
        assert report["duplicate_rows"] == 1
        assert report["conflicting_versions"] == ["10.13.1030"]
        assert report["completeness"] == "conflicting_dates"
        assert len(report["releases"]) == 3


@pytest.mark.parametrize(
    "field,value",
    [
        ("rendered_sha256", "a" * 64),
        ("capture_method", "http"),
        ("captured_at", "2026-10-28T00:00:00Z"),
        ("cookies", "PRIVATE"),
        ("source_url", "https://attacker.example/version-history-43.html"),
        ("source_url", URL.replace("4100i", "6000")),
    ],
)
def test_invalid_provenance_or_unreviewed_scope_is_not_saved(field, value):
    doc = envelope()
    doc[field] = value
    with connect(":memory:") as db:
        with pytest.raises((ValueError, ValidationError)):
            import_capture(db, json.dumps(doc).encode(), at=AT)
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 0


def test_changed_table_layout_is_not_silently_empty_history():
    doc = envelope()
    doc["rendered_html"] = doc["rendered_html"].replace("Release date", "Updated date")
    doc["rendered_sha256"] = hashlib.sha256(doc["rendered_html"].encode()).hexdigest()
    with connect(":memory:") as db:
        with pytest.raises(ValueError, match="table"):
            import_capture(db, json.dumps(doc).encode(), at=AT)


@pytest.mark.parametrize(
    "status,resolved,server,body,expected",
    [
        (404, URL, "nginx", b"Not Found", "source_missing"),
        (410, URL, "nginx", b"Gone", "source_missing"),
        (404, URL + "?moved=1", "nginx", b"Not Found", "redirect_target_missing"),
        (403, URL, "AkamaiGHost", b"<html>Access Denied</html>", "edge_access_denied"),
        (403, URL, "AkamaiGHost", b"Other error", "access_denied"),
        (403, URL, "nginx", b"Access Denied", "access_denied"),
    ],
)
def test_transport_retains_precise_failure_category(status, resolved, server, body, expected):
    error = HTTPError(resolved, status, "Failure", {"Server": server}, io.BytesIO(body))
    with (
        connect(":memory:") as db,
        patch("infrastructure_impact.collection.transport.build_opener") as opener,
    ):
        opener.return_value.open.side_effect = error
        with pytest.raises(SourceHTTPError) as caught:
            fetch(db, URL, "aruba")
        assert failure_code(caught.value) == expected
        assert db.execute("SELECT COUNT(*) FROM http_cache").fetchone()[0] == 0
