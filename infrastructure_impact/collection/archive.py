"""Resumable, additive archive discovery using the normal reviewed document path.

Each source has its own bounded page/document budget. Only official HTTPS links
are queued. Every item commits independently; a crash replays at most that item.
The root is refreshed every pass. Previously visited non-root pages are revisited
only with refresh_pages=True; this is not a historical availability measurement.
"""

from contextlib import closing
from datetime import datetime, timedelta, timezone
from urllib.parse import urldefrag

from ..adapters.compat import auto
from ..plugins.registry import default_registry
from ..storage.repository import collection_result, connect, evidence, ingest, now
from .config import validate_config
from .discovery import inventory
from .errors import failure_code
from .service import resolve_document
from .transport import allowed, fetch

MAX_ATTEMPTS = 5


def enqueue(db, source_id, kind, url):
    db.execute(
        "INSERT OR IGNORE INTO archive_items(source_id,kind,url,discovered_at) VALUES(?,?,?,?)",
        (source_id, kind, url, now()),
    )


def fail(db, source, item, error):
    attempted = item["attempts"] + 1
    retry = (
        datetime.now(timezone.utc) + timedelta(hours=min(24 * 2 ** (attempted - 1), 168))
    ).isoformat()
    with db:
        db.execute(
            "UPDATE archive_items SET state='error',checked_at=?,attempts=?,retry_after=?,error_code=? WHERE id=?",
            (now(), attempted, retry, failure_code(error), item["id"]),
        )
        collection_result(
            db, source["vendor"], item["url"], "error", str(error), failure_code(error)
        )


def ready(db, source_id, kind, limit):
    return list(
        db.execute(
            "SELECT * FROM archive_items WHERE source_id=? AND kind=? AND "
            "(state='pending' OR (state='error' AND attempts<? AND retry_after<=?)) "
            "ORDER BY CASE state WHEN 'pending' THEN 0 ELSE 1 END,(checked_at IS NOT NULL),checked_at,id LIMIT ?",
            (source_id, kind, MAX_ATTEMPTS, now(), limit),
        )
    )


def page(db, source, item):
    raw = fetch(db, item["url"], source["vendor"])
    found = inventory(raw, item["url"], source["kind"])
    rejected = 0
    with db:
        ev = evidence(db, raw, item["url"])
        for kind, links in (("document", found["urls"]), ("page", found["next_pages"])):
            for url in links:
                url = urldefrag(url)[0]
                try:
                    valid = allowed(url, source["vendor"])
                except ValueError:
                    valid = False
                if valid:
                    enqueue(db, source["id"], kind, url)
                    db.execute(
                        "INSERT OR IGNORE INTO archive_links SELECT id,? FROM archive_items WHERE source_id=? AND kind=? AND url=?",
                        (ev["id"], source["id"], kind, url),
                    )
                else:
                    rejected += 1
        db.execute(
            "UPDATE archive_items SET state='done',checked_at=?,attempts=0,retry_after=NULL,"
            "evidence_id=?,entry_count=?,missing_links=?,rejected_links=?,error_code=NULL WHERE id=?",
            (
                now(),
                ev["id"],
                found["entry_count"],
                found["entries_without_links"],
                rejected,
                item["id"],
            ),
        )
        collection_result(
            db,
            source["vendor"],
            item["url"],
            "partial" if rejected or found["entries_without_links"] else "ok",
            "Archive page inventoried; document processing is tracked separately; full portfolio not established.",
        )


def document(db, source, item):
    url, raw = resolve_document(db, item["url"], source["vendor"])
    parsed = auto(raw, url, source["vendor"])
    ignored = default_registry().get(source["vendor"]).non_cve_notice(parsed)
    changed = False if ignored else ingest(db, raw, url, lambda *_: parsed, source["vendor"])
    with db:
        ev = evidence(db, raw, url)
        db.execute(
            "UPDATE archive_items SET state=?,checked_at=?,attempts=0,retry_after=NULL,evidence_id=?,resolved_url=?,error_code=NULL WHERE id=?",
            ("not_applicable" if ignored else "done", now(), ev["id"], url, item["id"]),
        )
        collection_result(
            db,
            source["vendor"],
            item["url"],
            "not_applicable" if ignored else "ok",
            "Archive document processed through reviewed vendor parser; publisher dates are not observed historical availability.",
        )
    return int(changed)


def run(
    config,
    db_path=None,
    *,
    vendor=None,
    refresh_pages=False,
    retry_errors=False,
    page_limit=None,
    document_limit=None,
):
    """Return (new revisions, failed attempts), leaving deferred/exhausted errors visible."""
    validate_config(config)
    for value, maximum in ((page_limit, 20), (document_limit, 200)):
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum
        ):
            raise ValueError(f"Archive budget must be an integer from 1 to {maximum}")
    if vendor is not None and not any(s["vendor"] == vendor for s in config.get("archives", [])):
        raise ValueError("Vendor has no configured archive source")
    imported = failed = 0
    with closing(connect(db_path)) as db:
        for seed in config.get("archives", []):
            if vendor and seed["vendor"] != vendor:
                continue
            with db:
                db.execute(
                    "INSERT OR IGNORE INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
                    (seed["vendor"], seed["url"], seed["kind"], now()),
                )
                source = dict(
                    db.execute(
                        "SELECT * FROM archive_sources WHERE vendor=? AND source_url=? AND kind=?",
                        (seed["vendor"], seed["url"], seed["kind"]),
                    ).fetchone()
                )
                enqueue(db, source["id"], "page", seed["url"])
                if refresh_pages:
                    db.execute(
                        "UPDATE archive_items SET state='pending' WHERE source_id=? AND kind='page' AND state='done'",
                        (source["id"],),
                    )
                # Successful roots refresh each pass; failed roots respect backoff.
                db.execute(
                    "UPDATE archive_items SET state='pending' WHERE source_id=? AND kind='page' AND url=? AND state='done'",
                    (source["id"], seed["url"]),
                )
                if retry_errors:
                    db.execute(
                        "UPDATE archive_items SET state='pending',attempts=0,retry_after=NULL WHERE source_id=? AND state='error'",
                        (source["id"],),
                    )
            budget = page_limit or seed.get("page_limit", 2)
            visited = set()
            while len(visited) < budget:
                items = [
                    i for i in ready(db, source["id"], "page", budget) if i["id"] not in visited
                ]
                if not items:
                    break
                item = items[0]
                visited.add(item["id"])
                try:
                    page(db, source, item)
                except Exception as error:
                    failed += 1
                    fail(db, source, item, error)
            for item in ready(
                db, source["id"], "document", document_limit or seed.get("document_limit", 8)
            ):
                try:
                    imported += document(db, source, item)
                except Exception as error:
                    failed += 1
                    fail(db, source, item, error)
            with db:
                db.execute(
                    "UPDATE archive_sources SET checked_at=? WHERE id=?", (now(), source["id"])
                )
    return imported, failed


def progress(db, records, config):
    """Public counts and date ranges; no raw response, error body or private state."""
    result = []
    for seed in config.get("archives", []):
        source = db.execute(
            "SELECT * FROM archive_sources WHERE vendor=? AND source_url=? AND kind=?",
            (seed["vendor"], seed["url"], seed["kind"]),
        ).fetchone()
        items = (
            list(db.execute("SELECT * FROM archive_items WHERE source_id=?", (source["id"],)))
            if source
            else []
        )
        counts = {
            kind: {
                state: sum(i["kind"] == kind and i["state"] == state for i in items)
                for state in ("pending", "done", "not_applicable", "error")
            }
            for kind in ("page", "document")
        }
        urls = {
            i["resolved_url"] for i in items if i["kind"] == "document" and i["state"] == "done"
        }
        from ..application.comparison import parse_date

        dated_records = [
            r for r in records if r["vendor"] == seed["vendor"] and r["source_url"] in urls
        ]
        dates = sorted(
            [r["published_at"] for r in dated_records if parse_date(r.get("published_at"))],
            key=parse_date,
        )
        gaps = sum(i["missing_links"] + i["rejected_links"] for i in items if i["kind"] == "page")
        outstanding = sum(c["pending"] + c["error"] for c in counts.values())
        result.append(
            dict(
                vendor=seed["vendor"],
                source_url=seed["url"],
                kind=seed["kind"],
                started_at=source["started_at"] if source else None,
                checked_at=source["checked_at"] if source else None,
                page_limit=seed.get("page_limit", 2),
                document_limit=seed.get("document_limit", 8),
                pages=counts["page"],
                documents=counts["document"],
                discovered_documents=sum(counts["document"].values()),
                discovery_link_gaps=gaps,
                exhausted_errors=sum(
                    i["state"] == "error" and i["attempts"] >= MAX_ATTEMPTS for i in items
                ),
                known_queue_exhausted=bool(source)
                and counts["page"]["done"] > 0
                and not outstanding
                and not gaps,
                current_records_without_usable_publisher_date=sum(
                    not parse_date(r.get("published_at")) for r in dated_records
                ),
                publisher_date_range={
                    "earliest": dates[0] if dates else None,
                    "latest": dates[-1] if dates else None,
                },
                page_evidence=[
                    dict(
                        source_url=r["source_url"],
                        sha256=r["sha256"],
                        first_retained_at=r["observed_at"],
                    )
                    for r in db.execute(
                        "SELECT DISTINCT e.source_url,e.sha256,e.observed_at FROM archive_items i JOIN evidence e ON e.id=i.evidence_id WHERE i.source_id=? AND i.kind='page' ORDER BY e.observed_at DESC LIMIT 20",
                        (source["id"],),
                    )
                ]
                if source
                else [],
                page_evidence_limit=20,
                portfolio_completeness="not_established",
            )
        )
    return result
