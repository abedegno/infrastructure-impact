"""Evidence store for infrastructure vulnerability assessments (schema v2)."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ..domain import validate_advisory
from ..plugins.registry import default_registry
from ..settings import Paths
from .migrations import migrate

DB = Paths.from_env().database
VENDORS = default_registry().names()


def now():
    return datetime.now(timezone.utc).isoformat()


def connect(path=None, *, read_only=False):
    path = Paths.from_env().database if path is None else path
    if read_only:
        db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
        db.execute("PRAGMA query_only=ON")
    else:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    if not read_only:
        if str(path) != ":memory:":
            db.execute("PRAGMA journal_mode=WAL")
        migrate(db)
    return db


def evidence(db, raw, url, media_type="application/json"):
    raw = raw.encode() if isinstance(raw, str) else raw
    digest = hashlib.sha256(raw).hexdigest()
    db.execute(
        "INSERT OR IGNORE INTO evidence(source_url,sha256,observed_at,raw,media_type) VALUES(?,?,?,?,?)",
        (url, digest, now(), raw, media_type),
    )
    return db.execute(
        "SELECT * FROM evidence WHERE source_url=? AND sha256=?", (url, digest)
    ).fetchone()


def claim_key(c):
    return (c["cve_id"], c["product_id"])


def semantic_diff(before, after):
    changes = []
    for key in ("cves", "published_at", "updated_at", "document_status", "notes", "metrics"):
        if before.get(key) != after.get(key):
            changes.append({"field": key, "before": before.get(key), "after": after.get(key)})
    old = {claim_key(c): c for c in before.get("assessments", [])}
    new = {claim_key(c): c for c in after.get("assessments", [])}
    for key in sorted(old.keys() | new.keys()):
        if old.get(key) != new.get(key):
            changes.append(
                {
                    "field": "assessment",
                    "cve_id": key[0],
                    "product_id": key[1],
                    "before": old.get(key),
                    "after": new.get(key),
                }
            )
    return changes


def ingest(db, raw, url, adapter, vendor):
    """A->B->A reversions are revisions, while repeated identical states are not."""
    normalized = json.loads(json.dumps(adapter(raw, url, vendor)))
    if not normalized.get("advisory_id") or not normalized.get("cves"):
        raise ValueError("Advisory has no stable identity or explicit CVE references")
    validate_advisory(normalized, vendor=vendor, source_url=url)
    for c in normalized["assessments"]:
        if c["cve_id"] not in normalized["cves"]:
            raise ValueError("Assessment CVE outside advisory scope")
    with db:
        e = evidence(db, raw, url, normalized.get("source_format", "application/json"))
        previous = db.execute(
            "SELECT * FROM revisions WHERE vendor=? AND advisory_id=? ORDER BY id DESC LIMIT 1",
            (vendor, normalized["advisory_id"]),
        ).fetchone()
        if (
            previous
            and previous["evidence_id"] == e["id"]
            and json.loads(previous["normalized"]) == normalized
        ):
            return False
        at = now()
        cursor = db.execute(
            "INSERT INTO revisions(evidence_id,vendor,advisory_id,source_url,observed_at,normalized) VALUES(?,?,?,?,?,?)",
            (e["id"], vendor, normalized["advisory_id"], url, at, json.dumps(normalized)),
        )
        if previous:
            before = json.loads(previous["normalized"])
            delta = semantic_diff(before, normalized)
            parser_changed = before.get("adapter_version") != normalized.get("adapter_version")
            view_changed = previous["source_url"] != url
            if delta:
                kind = (
                    "source_view_change"
                    if view_changed
                    else "parser_reinterpretation"
                    if parser_changed or previous["evidence_id"] == e["id"]
                    else "assessment_revision"
                )
                db.execute(
                    "INSERT INTO changes(revision_id,observed_at,vendor,advisory_id,kind,details) VALUES(?,?,?,?,?,?)",
                    (
                        cursor.lastrowid,
                        at,
                        vendor,
                        normalized["advisory_id"],
                        kind,
                        json.dumps(delta),
                    ),
                )
            added = set(normalized["cves"]) - set(before["cves"])
            if (
                added
                and previous["evidence_id"] != e["id"]
                and not parser_changed
                and not view_changed
            ):
                db.execute(
                    "INSERT INTO changes(revision_id,observed_at,vendor,advisory_id,kind,details) VALUES(?,?,?,?,?,?)",
                    (
                        cursor.lastrowid,
                        at,
                        vendor,
                        normalized["advisory_id"],
                        "cve_reference_added",
                        json.dumps(
                            {
                                "cves": sorted(added),
                                "meaning": "CVE references added between locally observed revisions; no inference about first vendor disclosure.",
                            }
                        ),
                    ),
                )
    return True


def latest(db):
    rows = db.execute("""SELECT r.*,e.sha256,e.observed_at AS source_observed_at FROM revisions r JOIN evidence e ON e.id=r.evidence_id
      WHERE r.id IN (SELECT MAX(id) FROM revisions GROUP BY vendor,advisory_id) ORDER BY r.vendor,r.advisory_id""")
    return [
        {
            **json.loads(r["normalized"]),
            "revision_id": r["id"],
            "evidence_id": r["evidence_id"],
            "sha256": r["sha256"],
            "source_observed_at": r["source_observed_at"],
            "observed_at": r["observed_at"],
        }
        for r in rows
    ]


def history(db, full=True):
    result = []
    for r in db.execute("SELECT * FROM changes ORDER BY id DESC LIMIT 200"):
        details = json.loads(r["details"])
        if not full and isinstance(details, list):
            details = [
                {
                    "field": d["field"],
                    "cve_id": d.get("cve_id"),
                    "product_id": d.get("product_id"),
                    "before_status": (d.get("before") or {}).get("status")
                    if isinstance(d.get("before"), dict)
                    else None,
                    "after_status": (d.get("after") or {}).get("status")
                    if isinstance(d.get("after"), dict)
                    else None,
                }
                for d in details
            ]
        result.append({**dict(r), "details": details})
    return result


def collection_result(db, vendor, url, outcome, details):
    with db:
        db.execute(
            "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details) VALUES(?,?,?,?,?)",
            (vendor, url, now(), outcome, details),
        )


def health(db):
    rows = db.execute(
        "SELECT * FROM collection_runs WHERE id IN (SELECT MAX(id) FROM collection_runs GROUP BY vendor,source_url) ORDER BY vendor,source_url"
    )
    return [dict(r) for r in rows]
