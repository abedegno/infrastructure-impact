"""Import labelled browser DOM evidence without promoting it to HTTP collection."""

import inspect
import json
import re
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from jsonschema import Draft202012Validator

from ..collection.transport import allowed
from ..domain import validator
from ..plugins.registry import default_registry
from ..settings import PACKAGE
from ..storage.repository import evidence, now

MAX_CAPTURE_BYTES = 2500000


def import_capture(db, raw, *, expected_version=None, at=None):
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError("Browser capture exceeds 2.5 MB")
    capture = json.loads(raw)
    schema = json.loads((PACKAGE / "schemas/browser-capture-v1.json").read_text())
    Draft202012Validator(schema, format_checker=validator().format_checker).validate(capture)
    vendor, url = capture["vendor"], capture["source_url"]
    if not allowed(url, vendor):
        raise ValueError("Browser capture requires an allowed official HTTPS source")
    captured = datetime.fromisoformat(capture["captured_at"].replace("Z", "+00:00"))
    if captured > (at or datetime.now(timezone.utc)) + timedelta(minutes=5):
        raise ValueError("Browser capture time is in the future")
    html = capture["rendered_html"].encode("utf-8")
    if sha256(html).hexdigest() != capture["rendered_sha256"]:
        raise ValueError("Rendered article fingerprint mismatch")
    plugin = default_registry().get(vendor)
    if not plugin.parse_release_history:
        raise ValueError("No reviewed release-history parser for this vendor")
    if expected_version is not None and not re.fullmatch(
        r"[A-Za-z0-9._+-]{1,100}", expected_version
    ):
        raise ValueError("Expected version must be an explicit version token")
    parsed = plugin.parse_release_history(html, url, vendor)
    history_schema = json.loads((PACKAGE / "schemas/release-history-v1.json").read_text())
    Draft202012Validator(history_schema, format_checker=validator().format_checker).validate(parsed)
    adapter_version = sha256(
        Path(inspect.getsourcefile(plugin.parse_release_history)).read_bytes()
        + plugin.version.encode()
    ).hexdigest()[:16]
    dates = {}
    for row in parsed["releases"]:
        dates.setdefault(row["version"], set()).add(row["reported_released_at"])
    missing = expected_version is not None and expected_version not in dates
    conflicts = sorted(version for version, values in dates.items() if len(values) > 1)
    report = dict(
        schema_version=1,
        vendor=vendor,
        source_url=url,
        captured_at=captured.astimezone(timezone.utc).isoformat(),
        capture_method=capture["capture_method"],
        capture_scope=capture["capture_scope"],
        browser_name=capture["browser_name"],
        rendered_sha256=capture["rendered_sha256"],
        adapter_version=adapter_version,
        **parsed,
        expected_version=expected_version,
        expected_version_missing=missing,
        conflicting_versions=conflicts,
        duplicate_rows=len(parsed["releases"])
        - len({(r["version"], r["reported_released_at"]) for r in parsed["releases"]}),
        completeness="conflicting_dates"
        if conflicts
        else "selected_version_missing"
        if missing
        else "not_established",
        limitations="Browser-rendered article, not origin response bytes. Capture metadata is importer-supplied, not a browser attestation. Publisher release dates do not verify historical download availability or CVE applicability. Presence of a selected version does not establish exhaustive history.",
    )
    with db:
        ev = evidence(db, raw, url, "application/vnd.infrastructure-impact.browser-capture+json")
        db.execute(
            "INSERT OR IGNORE INTO browser_captures(evidence_id,vendor,source_url,captured_at,imported_at,adapter_version,expected_version,normalized) VALUES(?,?,?,?,?,?,?,?)",
            (
                ev["id"],
                vendor,
                url,
                report["captured_at"],
                now(),
                adapter_version,
                expected_version or "",
                json.dumps(report, sort_keys=True),
            ),
        )
    return {**report, "evidence_id": ev["id"]}


def captures(db):
    """Private operator summaries; HTML stays only in the evidence vault."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='browser_captures'").fetchone():
        return []
    return [
        {**json.loads(row["normalized"]), "evidence_id": row["evidence_id"]}
        for row in db.execute(
            "SELECT normalized,evidence_id FROM browser_captures ORDER BY captured_at DESC,id DESC"
        )
    ]
