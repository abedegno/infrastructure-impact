"""Opt-in private VulnCheck KEV intake; intentionally outside public reference storage.

Backup API contract: https://docs.vulncheck.com/api/v3/backup
No signed URLs, credentials, exploit repositories or remote exception text are retained.
"""

import hashlib
import io
import json
import os
import re
import sqlite3
import zipfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..application.strict_json import loads

API_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
ATTRIBUTION = {
    "name": "VulnCheck Known Exploited Vulnerabilities",
    "url": "https://www.vulncheck.com/kev",
}
MAX_ZIP_BYTES = 32_000_000
MAX_JSON_BYTES = 128_000_000
MAX_ENTRIES = 100_000
CACHE_SECONDS = 86400
FRESH_SECONDS = 129600
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})",
        value,
    ):
        raise ValueError("Expected timezone-aware publisher timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _now(at):
    at = at or datetime.now(timezone.utc)
    if at.tzinfo is None:
        raise ValueError("Evaluation time must include timezone")
    return at.astimezone(timezone.utc)


def _web_url(value):
    if not isinstance(value, str) or any(ord(c) <= 32 for c in value):
        raise ValueError("Invalid source URL")
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.fragment
    ):
        raise ValueError("Invalid source URL")
    return value


def _reference_url_status(value):
    # Publisher citations are literal evidence, never transport destinations.
    # Preserve malformed text without silently repairing or following it.
    if not isinstance(value, str) or not value:
        raise ValueError("Missing publisher reference URL")
    try:
        parts = urlsplit(value)
        valid = (
            parts.scheme in ("http", "https")
            and bool(parts.hostname)
            and not parts.username
            and not parts.password
            and not any(ord(c) <= 32 for c in value)
        )
    except ValueError:
        valid = False
    return "valid_web_url" if valid else "publisher_url_unresolved"


def parse(raw):
    """Validate one bounded ZIP member and normalize membership by exact CVE ID.

    Backup files are JSON arrays; the documented API envelope is also accepted.
    XDB presence is deliberately not interpreted as exploitation evidence.
    """
    if len(raw) > MAX_ZIP_BYTES:
        raise ValueError("VulnCheck archive exceeds byte budget")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        if len(members) != 1:
            raise ValueError("Expected a single JSON backup member")
        member = members[0]
        if (
            member.is_dir()
            or not member.filename.endswith(".json")
            or member.file_size > MAX_JSON_BYTES
        ):
            raise ValueError("Unsupported VulnCheck backup member")
        with archive.open(member) as stream:
            data = loads(
                stream.read(MAX_JSON_BYTES + 1), budget=MAX_JSON_BYTES, label="VulnCheck backup"
            )
    rows = data.get("data") if isinstance(data, dict) else data
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ENTRIES:
        raise ValueError("Expected nonempty complete VulnCheck backup")
    entries = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid VulnCheck entry")
        ids = row.get("cve")
        if (
            not isinstance(ids, list)
            or not ids
            or any(not isinstance(cid, str) or not CVE.fullmatch(cid) for cid in ids)
        ):
            raise ValueError("Invalid VulnCheck CVE identities")
        for key in ("vendorProject", "product"):
            if row.get(key) is not None and not isinstance(row[key], str):
                raise ValueError("Invalid publisher label")
        _date(row.get("date_added"))
        reports = row.get("vulncheck_reported_exploitation", [])
        if not isinstance(reports, list):
            raise ValueError("Invalid exploitation references")
        normalized = []
        for report in reports:
            if not isinstance(report, dict):
                raise ValueError("Invalid exploitation reference")
            _date(report.get("date_added"))
            normalized.append(
                dict(
                    url=report.get("url"),
                    date_added=report["date_added"],
                    url_status=_reference_url_status(report.get("url")),
                )
            )
        canaries = row.get("reported_exploited_by_vulncheck_canaries")
        if canaries is not None and type(canaries) is not bool:
            raise ValueError("Invalid canary indicator")
        entry = dict(
            vendor_label=row.get("vendorProject"),
            product_label=row.get("product"),
            missing_labels=[
                key for key in ("vendorProject", "product") if not (row.get(key) or "").strip()
            ],
            listed_at=row["date_added"],
            reported_exploitation=normalized,
            canary_reported=canaries,
        )
        for cid in ids:
            if cid in entries:
                raise ValueError("Duplicate VulnCheck CVE identity")
            entries[cid] = entry
    if len(entries) > MAX_ENTRIES:
        raise ValueError("VulnCheck CVE budget exceeded")
    return dict(sorted(entries.items()))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect_rejected")


def _db(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Private state cannot be a symbolic link")
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    path.chmod(0o600)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if tables - {"revisions", "attempts"}:
        db.close()
        raise ValueError("State must be a dedicated VulnCheck database")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS revisions (
            id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE, observed_at TEXT NOT NULL,
            publisher_backup_at TEXT NOT NULL, raw BLOB NOT NULL, normalized TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY, checked_at TEXT NOT NULL, outcome TEXT NOT NULL,
            error_code TEXT, retry_at TEXT, revision_id INTEGER);
    """)
    return db


def _read(session, url, limit, token=None):
    headers = {"Accept": "application/json", "User-Agent": "Infrastructure-Impact/0.13"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with session.open(Request(url, headers=headers), timeout=30) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("unexpected_response")
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("response_too_large")
    return raw


def collect(path, *, token=None, session=None, at=None, force=False):
    """Download once per day, reuse identical archives, persist bounded retry state.

    Only stable codes escape the transport boundary. Force bypasses daily caching,
    but never a provider backoff. Storage is explicit and never the main vault.
    """
    at = _now(at)
    token = os.environ.get("VULNCHECK_API_TOKEN", "") if token is None else token
    session = session or build_opener(_NoRedirect())
    with closing(_db(path)) as db, db:
        latest = db.execute("SELECT * FROM attempts ORDER BY id DESC LIMIT 1").fetchone()
        if latest and latest["retry_at"] and at < _date(latest["retry_at"]):
            return dict(outcome="deferred", retry_at=latest["retry_at"])
        if (
            latest
            and latest["outcome"] == "ok"
            and not force
            and 0 <= (at - _date(latest["checked_at"])).total_seconds() < CACHE_SECONDS
        ):
            return dict(outcome="cached", revision_id=latest["revision_id"])
        code, retry_at, revision_id = None, None, None
        try:
            if not token or any(ord(c) <= 32 for c in token):
                code = "credentials_missing"
            else:
                metadata = _read(session, API_URL, 64_000, token)
                if token.encode() in metadata:
                    raise ValueError("private_content")
                data = loads(metadata, budget=64_000)
                rows = data.get("data") if isinstance(data, dict) else None
                if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
                    raise ValueError("invalid_backup_metadata")
                backup = rows[0]
                url = _web_url(backup.get("url"))
                if urlsplit(url).netloc != "serve.vulncheck.com":
                    raise ValueError("download_url_rejected")
                sha = backup.get("sha256")
                if not isinstance(sha, str) or not re.fullmatch("[a-f0-9]{64}", sha):
                    raise ValueError("invalid_backup_hash")
                _date(backup.get("date_added"))
                retained = db.execute("SELECT id FROM revisions WHERE sha256=?", (sha,)).fetchone()
                if retained:
                    revision_id = retained["id"]
                else:
                    raw = _read(session, url, MAX_ZIP_BYTES)
                    if hashlib.sha256(raw).hexdigest() != sha:
                        raise ValueError("backup_hash_mismatch")
                    entries = parse(raw)
                    if token in json.dumps(entries):
                        raise ValueError("private_content")
                    # Scan decompressed bytes too; unknown publisher fields are retained only privately.
                    with zipfile.ZipFile(io.BytesIO(raw)) as z:
                        if token.encode() in z.read(z.infolist()[0]):
                            raise ValueError("private_content")
                    revision_id = db.execute(
                        "INSERT INTO revisions(sha256,observed_at,publisher_backup_at,raw,normalized) VALUES(?,?,?,?,?)",
                        (sha, at.isoformat(), backup["date_added"], raw, json.dumps(entries)),
                    ).lastrowid
        except HTTPError as error:
            code = (
                "rate_limited"
                if error.code == 429
                else "access_denied"
                if error.code in (401, 403)
                else "http_error"
            )
            seconds = 60
            if error.code == 429 or error.code >= 500:
                value = (error.headers or {}).get("Retry-After", "")
                if value.isascii() and value.isdigit():
                    seconds = min(86400, max(60, int(value[:10])))
                else:
                    try:
                        until = parsedate_to_datetime(value)
                        if until.tzinfo is not None:
                            seconds = min(86400, max(60, (until - at).total_seconds()))
                    except (ValueError, TypeError, OverflowError):
                        pass
            if error.code == 429 or error.code >= 500:
                retry_at = (at + timedelta(seconds=seconds)).isoformat()
            error.close()
        except Exception:
            code = "source_rejected"
            retry_at = (at + timedelta(seconds=60)).isoformat()
        outcome = "failed" if code else "ok"
        db.execute(
            "INSERT INTO attempts(checked_at,outcome,error_code,retry_at,revision_id) VALUES(?,?,?,?,?)",
            (at.isoformat(), outcome, code, retry_at, revision_id),
        )
        return dict(outcome=outcome, error_code=code, retry_at=retry_at, revision_id=revision_id)


def report(path, scope, *, at=None, cisa_ids=None):
    """Private exact-CVE comparison; labels do not establish model affectedness.

    cisa_ids must come from a separately verified available CISA report; None is
    unknown, and an empty set is a verified empty selection, not a missing source.
    """
    at = _now(at)
    ids = sorted(set(scope))
    if len(ids) > MAX_ENTRIES or any(
        not isinstance(cid, str) or not CVE.fullmatch(cid) for cid in ids
    ):
        raise ValueError("Scope requires exact CVE identities")
    source = dict(
        id="vulncheck-kev",
        url=API_URL,
        availability="missing",
        checked_at=None,
        sha256=None,
        revision_id=None,
        retrieved_at=None,
        publisher_backup_at=None,
        parser_version=1,
        error_code=None,
    )
    entries = {}
    path = Path(path)
    if path.exists():
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        try:
            attempt = db.execute("SELECT * FROM attempts ORDER BY id DESC LIMIT 1").fetchone()
            revision = db.execute(
                "SELECT r.* FROM revisions r JOIN attempts a ON a.revision_id=r.id WHERE a.outcome='ok' ORDER BY a.id DESC LIMIT 1"
            ).fetchone()
            if revision:
                entries = json.loads(revision["normalized"])
                source.update(
                    sha256=revision["sha256"],
                    revision_id=revision["id"],
                    retrieved_at=revision["observed_at"],
                    publisher_backup_at=revision["publisher_backup_at"],
                )
            if attempt:
                source.update(checked_at=attempt["checked_at"], error_code=attempt["error_code"])
                age = (at - _date(attempt["checked_at"])).total_seconds()
                source["availability"] = (
                    "failed"
                    if attempt["outcome"] != "ok"
                    else "future"
                    if age < -300
                    else "stale"
                    if age > FRESH_SECONDS
                    else "available"
                )
        finally:
            db.close()
    available = source["availability"] == "available"
    listed = set(entries) & set(ids) if available else None
    cisa = set(cisa_ids) & set(ids) if cisa_ids is not None else None
    return dict(
        schema_version=1,
        distribution="private_research_only",
        evaluated_at=at.isoformat(),
        attribution=dict(ATTRIBUTION),
        source=source,
        counts=dict(
            vulncheck_listed=len(listed) if listed is not None else None,
            cisa_listed=len(cisa) if cisa is not None else None,
            both=len(listed & cisa) if listed is not None and cisa is not None else None,
            vulncheck_only=len(listed - cisa) if listed is not None and cisa is not None else None,
            cisa_only=len(cisa - listed) if listed is not None and cisa is not None else None,
        ),
        cves=[
            dict(
                cve_id=cid,
                cisa_membership="unknown"
                if cisa is None
                else "listed"
                if cid in cisa
                else "not_listed",
                vulncheck=dict(
                    membership="unknown"
                    if listed is None
                    else "listed"
                    if cid in listed
                    else "not_listed",
                    retained_listed=cid in entries,
                    evidence=entries.get(cid),
                ),
            )
            for cid in ids
        ],
        caveats=[
            "Listing is provider-reported exploitation, not proof a particular vendor model is affected.",
            "Not listed does not mean not exploited. Stale or failed sources are unknown.",
            "Listing and reference dates are not exploitation start dates; XDB availability is not exploitation proof.",
            "Counts measure source coverage, not vendor security quality; independent human review pending.",
        ],
    )
