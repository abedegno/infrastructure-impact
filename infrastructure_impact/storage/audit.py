"""Integrity checks for operators; not exposed by the public reader."""

from contextlib import closing
from hashlib import sha256

from ..domain import validate_advisory
from .repository import connect, latest


def audit():
    with closing(connect(read_only=True)) as db:
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
        if db.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Evidence relationship integrity check failed")
        observation_count = 0
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='source_observations'").fetchone():
            if db.execute(
                "SELECT 1 FROM source_observations o JOIN evidence e ON e.id=o.evidence_id WHERE o.source_url<>e.source_url LIMIT 1"
            ).fetchone():
                raise ValueError("Retrieval observation evidence URL mismatch")
            observation_count = db.execute("SELECT count(*) FROM source_observations").fetchone()[0]
        reference_count = 0
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='reference_documents'").fetchone():
            import json

            from ..references.registry import source

            for row in db.execute(
                "SELECT d.*,e.source_url AS evidence_url,e.raw FROM reference_documents d JOIN evidence e ON e.id=d.evidence_id"
            ):
                spec = source(row["source_id"])
                if row["source_url"] != spec.url or row["evidence_url"] != spec.url:
                    raise ValueError("Reference evidence URL mismatch")
                if spec.parse(row["raw"]) != json.loads(row["normalized"]):
                    raise ValueError("Reference normalization differs from retained source")
                reference_count += 1
        records = latest(db)
        for record in records:
            validate_advisory(record)
        assets = []
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='release_assets'").fetchone():
            from ..application.release_assets import listings

            assets = listings(db)
        from ..application.browser_capture import captures

        browser = captures(db)
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
            "browser_captures": len(browser),
            "evidence_snapshots": count,
            "source_observations": observation_count,
            "reference_documents": reference_count,
            "fingerprints": "ok",
        }
