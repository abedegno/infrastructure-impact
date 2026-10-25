"""Append-only SQL migration runner. Existing evidence is adopted, never reset."""

import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path


def migrate(db, directory=None):
    directory = Path(directory or Path(__file__).parent.parent / "migrations")
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL,checksum TEXT)"
        )
        columns = {row[1] for row in db.execute("PRAGMA table_info(schema_migrations)")}
        if "checksum" not in columns:
            db.execute("ALTER TABLE schema_migrations ADD COLUMN checksum TEXT")
        for path in sorted(directory.glob("*.sql")):
            version = int(path.name.split("_", 1)[0])
            digest = sha256(path.read_bytes()).hexdigest()
            applied = db.execute(
                "SELECT checksum FROM schema_migrations WHERE version=?", (version,)
            ).fetchone()
            if applied:
                if applied[0] is not None and applied[0] != digest:
                    raise ValueError(
                        f"Applied migration {version} was changed; append a new migration"
                    )
                db.execute(
                    "UPDATE schema_migrations SET checksum=? WHERE version=?", (digest, version)
                )
                continue
            statement = ""
            for character in path.read_text():
                statement += character
                if character == ";" and sqlite3.complete_statement(statement):
                    db.execute(statement)
                    statement = ""
            if statement.strip():
                db.execute(statement)
            db.execute(
                "INSERT INTO schema_migrations VALUES(?,?,?)",
                (version, datetime.now(timezone.utc).isoformat(), digest),
            )
        db.commit()
    except BaseException:
        db.rollback()
        raise
