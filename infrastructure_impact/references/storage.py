"""Append reference revisions without mixing them into vendor advisory storage."""

import json

from ..storage.repository import evidence, now
from .registry import SOURCES, source


def ingest(db, raw, source_id):
    spec = source(source_id)
    parsed = spec.parse(raw)
    with db:
        ev = evidence(db, raw, spec.url)
        previous = db.execute(
            "SELECT * FROM reference_documents WHERE source_id=? ORDER BY id DESC LIMIT 1",
            (source_id,),
        ).fetchone()
        if (
            previous
            and previous["evidence_id"] == ev["id"]
            and json.loads(previous["normalized"]) == parsed
        ):
            return False
        db.execute(
            "INSERT INTO reference_documents(source_id,source_url,evidence_id,observed_at,normalized) VALUES(?,?,?,?,?)",
            (source_id, spec.url, ev["id"], now(), json.dumps(parsed)),
        )
    return True


def latest(db):
    """Older read-only vaults have an explicit missing reference, not a backfill."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='reference_documents'").fetchone():
        return []
    result = []
    for spec in SOURCES.values():
        row = db.execute(
            "SELECT d.*, e.sha256,e.observed_at AS source_observed_at FROM reference_documents d JOIN evidence e ON e.id=d.evidence_id WHERE d.source_id=? ORDER BY d.id DESC LIMIT 1",
            (spec.id,),
        ).fetchone()
        if not row:
            continue
        check = db.execute(
            "SELECT checked_at,outcome,error_code FROM collection_runs WHERE vendor='upstream' AND source_url=? ORDER BY id DESC LIMIT 1",
            (spec.url,),
        ).fetchone()
        result.append(
            {
                "source_id": spec.id,
                "source_url": row["source_url"],
                "source_sha256": row["sha256"],
                "source_observed_at": row["source_observed_at"],
                "parsed_at": row["observed_at"],
                "collection": dict(check) if check else None,
                **json.loads(row["normalized"]),
            }
        )
    return result
