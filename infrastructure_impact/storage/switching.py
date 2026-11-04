"""Committed rolling quotas, cooldowns and typed enumeration resume points.

Callers must finish their own transaction first. Reservations deliberately commit
before network I/O, so interrupted and failed attempts still consume the quota.
"""

import re
import sqlite3
from bisect import bisect_right
from datetime import date, datetime, timezone

SERVICE = "cisco_openvuln"
WINDOWS = ((1, 5), (60, 30), (86400, 5000))


def _timestamp(at):
    value = datetime.fromisoformat(at)
    if value.tzinfo is None:
        raise ValueError("A timezone-aware reservation time is required")
    return value.timestamp()


def _iso(at):
    return datetime.fromtimestamp(at, timezone.utc).isoformat()


def _validate_service(service):
    if service != SERVICE:
        raise ValueError("Unknown quota service")


def _begin(db):
    if db.in_transaction:
        raise ValueError("Finish the current transaction before reserving network access")
    # Do not inherit repository.connect's potentially long 30-second lock wait.
    previous = db.execute("PRAGMA busy_timeout").fetchone()[0]
    db.execute("PRAGMA busy_timeout=250")
    try:
        db.execute("BEGIN IMMEDIATE")
    finally:
        db.execute(f"PRAGMA busy_timeout={int(previous)}")


def reserve_request(db, service: str, at: str) -> dict:
    """Atomically reserve against rolling 1/60/86400-second request windows."""
    _validate_service(service)
    stamp = _timestamp(at)
    try:
        _begin(db)
    except sqlite3.OperationalError:
        return dict(allowed=False, retry_at=_iso(stamp + 1))
    try:
        state = db.execute(
            "SELECT cooldown_until FROM switching_service_state WHERE service=?", (service,)
        ).fetchone()
        retry = state[0] if state else 0
        db.execute(
            "DELETE FROM switching_requests WHERE service=? AND reserved_at<=?",
            (service, stamp - 86400),
        )
        stamps = [
            r[0]
            for r in db.execute(
                "SELECT reserved_at FROM switching_requests WHERE service=? ORDER BY reserved_at",
                (service,),
            )
        ]
        for seconds, limit in WINDOWS:
            count = len(stamps) - bisect_right(stamps, stamp - seconds)
            if count >= limit:
                retry = max(retry, stamps[-limit] + seconds)
        allowed = retry <= stamp
        if allowed:
            db.execute(
                "INSERT INTO switching_requests(service,reserved_at) VALUES(?,?)", (service, stamp)
            )
        db.commit()
        return dict(allowed=allowed, retry_at=None if allowed else _iso(retry))
    except BaseException:
        db.rollback()
        raise


def defer_request(db, service, at, *, retry_at=None):
    """Persist escalating backoff, extended by a publisher Retry-After if supplied."""
    _validate_service(service)
    stamp = _timestamp(at)
    _begin(db)
    try:
        state = db.execute(
            "SELECT cooldown_until,failures FROM switching_service_state WHERE service=?",
            (service,),
        ).fetchone()
        failures = min((state[1] if state else 0) + 1, 10)
        until = max(
            state[0] if state else 0,
            stamp + min(2 ** (failures - 1), 300),
            _timestamp(retry_at) if retry_at else 0,
        )
        db.execute(
            "INSERT INTO switching_service_state(service,cooldown_until,failures) VALUES(?,?,?) "
            "ON CONFLICT(service) DO UPDATE SET cooldown_until=excluded.cooldown_until,failures=excluded.failures",
            (service, until, failures),
        )
        db.commit()
        return _iso(until)
    except BaseException:
        db.rollback()
        raise


def request_succeeded(db, service):
    """Reset backoff without erasing another caller's still-active cooldown."""
    _validate_service(service)
    if db.in_transaction:
        raise ValueError("Finish the current transaction before updating network state")
    with db:
        db.execute("UPDATE switching_service_state SET failures=0 WHERE service=?", (service,))


def _window(service, window_start, window_end, definition_fingerprint):
    _validate_service(service)
    try:
        start, end = date.fromisoformat(window_start), date.fromisoformat(window_end)
    except (TypeError, ValueError):
        raise ValueError("Cursor windows require ISO calendar dates") from None
    if start.isoformat() != window_start or end.isoformat() != window_end or start >= end:
        raise ValueError("Cursor windows require ordered ISO calendar dates")
    if definition_fingerprint and not re.fullmatch(r"[0-9a-f]{64}", definition_fingerprint):
        raise ValueError("Cursor definition fingerprint must be a SHA-256 digest")
    return service, window_start, window_end, definition_fingerprint


def save_cursor(db, service, *, window_start, window_end, page_index, definition_fingerprint=""):
    key = _window(service, window_start, window_end, definition_fingerprint)
    if type(page_index) is not int or not 1 <= page_index <= 100:
        raise ValueError("Cursor page index must be an integer from 1 to 100")
    if db.in_transaction:
        raise ValueError("Finish the current transaction before saving a cursor")
    with db:
        db.execute(
            "INSERT INTO switching_cursors VALUES(?,?,?,?,?) "
            "ON CONFLICT(service,window_start,window_end,definition_fingerprint) "
            "DO UPDATE SET page_index=excluded.page_index",
            (*key, page_index),
        )


def load_cursor(db, service, *, window_start, window_end, definition_fingerprint=""):
    key = _window(service, window_start, window_end, definition_fingerprint)
    row = db.execute(
        "SELECT page_index FROM switching_cursors WHERE service=? AND window_start=? "
        "AND window_end=? AND definition_fingerprint=?",
        key,
    ).fetchone()
    return dict(page_index=row[0]) if row else None
