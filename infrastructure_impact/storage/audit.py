"""Integrity checks for operators; not exposed by the public reader."""

from contextlib import closing
from hashlib import sha256

from ..domain import validate_advisory
from .repository import connect, latest


def audit():
    with closing(connect(read_only=True)) as db:
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
        records = latest(db)
        for record in records:
            validate_advisory(record)
        assets = []
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='release_assets'").fetchone():
            from ..application.release_assets import listings

            assets = listings(db)
        count = 0
        for row in db.execute("SELECT raw,sha256 FROM evidence"):
            if sha256(row["raw"]).hexdigest() != row["sha256"]:
                raise ValueError("Evidence fingerprint mismatch")
            count += 1
        return {
            "database": "ok",
            "schema_version": 2,
            "records": len(records),
            "release_assets": len(assets),
            "evidence_snapshots": count,
            "fingerprints": "ok",
        }
