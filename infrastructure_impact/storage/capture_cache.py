"""Private, transactional byte captures; never stores normalized assessments."""

import os
import sqlite3
from datetime import datetime
from hashlib import sha256
from pathlib import Path


class CaptureError(ValueError):
    pass


def validate_path(path, database, output):
    path, database, output = Path(path), Path(database), Path(output)
    for candidate in (path, *(Path(str(path) + s) for s in ("-wal", "-shm", "-journal"))):
        if any(p.is_symlink() for p in (candidate, *candidate.parents)):
            raise CaptureError("storage")
    resolved, source, destination = path.resolve(), database.resolve(), output.resolve()
    if (
        resolved == source
        or resolved in source.parents
        or resolved.is_relative_to(source.parent)
        or resolved == destination
        or resolved.is_relative_to(destination)
        or destination.is_relative_to(resolved)
    ):
        raise CaptureError("storage")
    if path.exists() and (not path.is_file() or os.path.samefile(path, database)):
        raise CaptureError("storage")
    return path


def connect(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # No symlink following when creating a new cache. Existing caches were checked
    # under the same collector lock by the caller.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        with db:
            db.execute("""CREATE TABLE IF NOT EXISTS captures (
                url TEXT NOT NULL, sha256 TEXT NOT NULL, observed_at TEXT NOT NULL,
                raw BLOB NOT NULL, media_type TEXT NOT NULL, etag TEXT, modified TEXT,
                PRIMARY KEY(url,sha256))""")
        return db
    except Exception:
        db.close()
        raise


def checked(row, url, digest, maximum):
    if row is None:
        return None
    if row["raw_size"] > maximum:
        raise CaptureError("source_access")
    raw = row["raw"]
    try:
        timestamp = datetime.fromisoformat(row["observed_at"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("Missing capture timezone")
    except (ValueError, TypeError, AttributeError):
        raise CaptureError("storage") from None
    if (
        not isinstance(raw, bytes)
        or row["url"] != url
        or row["sha256"] != digest
        or sha256(raw).hexdigest() != digest
        or not isinstance(row["observed_at"], str)
        or not row["observed_at"]
    ):
        raise CaptureError("storage")
    if len(raw) > maximum:
        raise CaptureError("source_access")
    return row


def lookup(db, url, digest, maximum):
    row = db.execute(
        """SELECT url,sha256,observed_at,media_type,etag,modified,length(raw) AS raw_size,
        CASE WHEN length(raw)<=? THEN raw END AS raw FROM captures WHERE url=? AND sha256=?""",
        (maximum, url, digest),
    ).fetchone()
    return checked(row, url, digest, maximum)


def from_evidence(db, url, digest, maximum):
    row = db.execute(
        """SELECT e.source_url AS url,e.sha256,e.observed_at,e.media_type,
        length(e.raw) AS raw_size,CASE WHEN length(e.raw)<=? THEN e.raw END AS raw,
        h.etag,h.modified FROM evidence e LEFT JOIN http_cache h
        ON h.evidence_id=e.id AND h.url=e.source_url
        WHERE e.source_url=? AND e.sha256=?""",
        (maximum, url, digest),
    ).fetchone()
    return checked(row, url, digest, maximum)


def save(db, capture):
    # INSERT OR IGNORE retains the first capture timestamp. Each document commits
    # independently, so later acquisition/validation failures cannot roll it back.
    with db:
        db.execute(
            "INSERT OR IGNORE INTO captures VALUES(?,?,?,?,?,?,?)",
            tuple(
                capture[k]
                for k in ("url", "sha256", "observed_at", "raw", "media_type", "etag", "modified")
            ),
        )


def replay(db, capture):
    with db:
        db.execute(
            """INSERT OR IGNORE INTO evidence
            (source_url,sha256,observed_at,raw,media_type) VALUES(?,?,?,?,?)""",
            tuple(capture[k] for k in ("url", "sha256", "observed_at", "raw", "media_type")),
        )
