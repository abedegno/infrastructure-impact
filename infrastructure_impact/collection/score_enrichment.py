"""Opt-in official CVE-level score staging, separate from product affectedness.

No keys, arbitrary URLs, redirects, automatic retries or frozen study mutations.
A committed pending marker fails closed after interruption. NVD is paced at
one request per 6.1 seconds, conservatively below 5 requests / rolling 30s.
CVE Services uses the same conservative local bound, not a claimed server quota.
"""

import json
import math
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..adapters import cvss
from ..storage.repository import evidence

MAX_BYTES = 2_000_000
SOURCES = ("cve_record", "nvd")
_clock = time.time


def _iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def _url(source, cid):
    return (
        "https://cveawg.mitre.org/api/cve/" + cid
        if source == "cve_record"
        else "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cid
    )


def _fetch(url):
    parsed = urlsplit(url)
    cid = (
        parsed.path.rsplit("/", 1)[-1]
        if parsed.hostname == "cveawg.mitre.org"
        else parsed.query.removeprefix("cveId=")
    )
    if not any(cvss.official_route(url, source, cid) for source in SOURCES):
        raise ValueError("Expected an exact official record route")

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError("Official record redirects are not supported")

    with build_opener(NoRedirect()).open(
        Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "VendorImpact/0.2 (public advisory research)",
            },
        ),
        timeout=25,
    ) as response:
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Official record exceeds byte bound")
        return raw


def _reserve(db, source, stamp):
    if db.in_transaction:
        raise ValueError("Finish current transaction before score staging")
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("INSERT OR IGNORE INTO score_service_state(source) VALUES(?)", (source,))
        row = db.execute("SELECT * FROM score_service_state WHERE source=?", (source,)).fetchone()
        if row["pending"] or row["next_at"] > stamp:
            db.commit()
            return False, None if row["pending"] else _iso(row["next_at"])
        db.execute(
            "UPDATE score_service_state SET next_at=?,pending=1 WHERE source=?",
            (stamp + 6.1, source),
        )
        db.commit()
        return True, None
    except BaseException:
        db.rollback()
        raise


def _retry(error, stamp):
    value = (
        error.headers.get("Retry-After") if isinstance(error, HTTPError) and error.headers else None
    )
    if value is None:
        return stamp
    try:
        seconds = float(value)
    except (TypeError, ValueError, OverflowError):
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                return stamp
            deadline = max(stamp, date.timestamp())
        except (TypeError, ValueError, OverflowError):
            return stamp
    else:
        if not math.isfinite(seconds):
            # Decimal delay-seconds can exceed float range while remaining a
            # valid publisher delay; nonfinite spellings such as NaN are invalid.
            return None if value.strip().isascii() and value.strip().isdigit() else stamp
        deadline = stamp + max(seconds, 0)
    try:
        _iso(deadline)
    except (ValueError, OverflowError, OSError):
        # A valid but unrepresentable delay must not become an earlier retry.
        # None leaves the durable pending marker blocked for explicit recovery.
        return None
    return deadline


def _record_matches(raw, source, cid):
    data = json.loads(raw)
    if source == "cve_record":
        return (
            data.get("dataType") == "CVE_RECORD"
            and data.get("cveMetadata", {}).get("cveId") == cid
            and data.get("cveMetadata", {}).get("state") in ("PUBLISHED", "REJECTED")
        )
    rows = data.get("vulnerabilities")
    return isinstance(rows, list) and len(rows) == 1 and rows[0].get("cve", {}).get("id") == cid


def run(db, cve_ids: list[str], *, limit: int) -> dict:
    """At most `limit` HTTP attempts (0 default at CLI), cache successes for a day.

    Every source stops on a durable rate/cooldown block. A 429 stops the batch;
    later invocations resume using retained records and current attempt state.
    """
    if type(limit) is not int or not 0 <= limit <= 200:
        raise ValueError("Score limit must be 0..200")
    if not isinstance(cve_ids, list) or any(
        not isinstance(c, str) or not cvss.CVE.fullmatch(c) for c in cve_ids
    ):
        raise ValueError("Expected canonical CVE IDs")
    result = dict(attempted=0, succeeded=0, failed=0, cached=0, blocked=0, retry_at=None)
    if not limit:
        return result
    blocked = set()
    for cid in sorted(set(cve_ids)):
        for source in SOURCES:
            if result["attempted"] >= limit:
                return result
            if source in blocked:
                continue
            stamp = _clock()
            previous = db.execute(
                "SELECT checked_at FROM score_documents WHERE source=? AND cve_id=? ORDER BY id DESC LIMIT 1",
                (source, cid),
            ).fetchone()
            if previous and datetime.fromisoformat(previous[0]).timestamp() > stamp - 86400:
                result["cached"] += 1
                continue
            reserved, retry = _reserve(db, source, stamp)
            if not reserved:
                result["blocked"] += 1
                result["retry_at"] = retry
                return result
            result["attempted"] += 1
            url = _url(source, cid)
            try:
                raw = _fetch(url)
                if len(raw) > MAX_BYTES or not _record_matches(raw, source, cid):
                    raise ValueError("Unexpected official record identity")
                parsed = cvss.extract(raw, url, "upstream", {})
                with db:
                    ev = evidence(db, raw, url)
                    cursor = db.execute(
                        "INSERT INTO score_documents(source,cve_id,evidence_id,checked_at,normalized) VALUES(?,?,?,?,?)",
                        (source, cid, ev["id"], _iso(stamp), json.dumps(parsed, allow_nan=False)),
                    )
                    revision = str(cursor.lastrowid)
                    for claim in parsed["claims"]:
                        claim["source"]["retrieved_at"] = _iso(stamp)
                        claim["revision"] = revision
                    db.execute(
                        "UPDATE score_documents SET normalized=? WHERE id=?",
                        (json.dumps(parsed, allow_nan=False), cursor.lastrowid),
                    )
                    db.execute(
                        "UPDATE score_service_state SET pending=0,failures=0 WHERE source=?",
                        (source,),
                    )
                    db.execute(
                        "INSERT INTO score_attempts(source,cve_id,checked_at,state) VALUES(?,?,?,?)",
                        (source, cid, _iso(stamp), "ok"),
                    )
                result["succeeded"] += 1
            except Exception as error:
                code = (
                    "rate_limited"
                    if isinstance(error, HTTPError) and error.code == 429
                    else "source_missing"
                    if isinstance(error, HTTPError) and error.code == 404
                    else "invalid_record"
                    if isinstance(error, (ValueError, TypeError, KeyError, AttributeError))
                    else "network_error"
                )
                with db:
                    failures = (
                        db.execute(
                            "SELECT failures FROM score_service_state WHERE source=?", (source,)
                        ).fetchone()[0]
                        + 1
                    )
                    publisher_retry = _retry(error, stamp)
                    retry = (
                        max(stamp + min(30 * 2 ** min(failures - 1, 7), 3600), publisher_retry)
                        if publisher_retry is not None
                        else None
                    )
                    db.execute(
                        "UPDATE score_service_state SET pending=?,failures=?,next_at=max(next_at,?) WHERE source=?",
                        (
                            int(retry is None),
                            failures,
                            retry if retry is not None else stamp,
                            source,
                        ),
                    )
                    db.execute(
                        "INSERT INTO score_attempts(source,cve_id,checked_at,state,retry_at) VALUES(?,?,?,?,?)",
                        (
                            source,
                            cid,
                            _iso(stamp),
                            code,
                            _iso(retry) if retry is not None else None,
                        ),
                    )
                result["failed"] += 1
                result["retry_at"] = _iso(retry) if retry is not None else None
                blocked.add(source)
                if code == "rate_limited":
                    return result
    return result


def inputs(db, cve_ids: list[str]) -> dict:
    """Retained latest successful records and independent sanitized latest attempts."""
    result = {"claims": [], "issues": [], "attempts": []}
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='score_documents'").fetchone():
        return result
    for cid in sorted(set(cve_ids)):
        for source in SOURCES:
            row = db.execute(
                "SELECT * FROM score_documents WHERE source=? AND cve_id=? ORDER BY id DESC LIMIT 1",
                (source, cid),
            ).fetchone()
            if row:
                retained = db.execute(
                    "SELECT raw FROM evidence WHERE id=?", (row["evidence_id"],)
                ).fetchone()
                parsed = cvss.extract(retained["raw"], _url(source, cid), "upstream", {})
                for claim in parsed["claims"]:
                    claim["revision"] = str(row["id"])
                    claim["source"]["retrieved_at"] = row["checked_at"]
                result["claims"].extend(parsed["claims"])
                result["issues"].extend(parsed["issues"])
            attempt = db.execute(
                "SELECT state,checked_at,retry_at FROM score_attempts WHERE source=? AND cve_id=? ORDER BY id DESC LIMIT 1",
                (source, cid),
            ).fetchone()
            service = db.execute(
                "SELECT pending,next_at FROM score_service_state WHERE source=?", (source,)
            ).fetchone()
            result["attempts"].append(
                dict(
                    source=source,
                    cve_id=cid,
                    state="request_state_unresolved"
                    if service and service["pending"]
                    else attempt["state"]
                    if attempt
                    else "unknown",
                    checked_at=attempt["checked_at"] if attempt else None,
                    retry_at=None
                    if service and service["pending"]
                    else attempt["retry_at"]
                    if attempt
                    else None,
                )
            )
    return result
