"""Bounded staging discovery. Enumeration never establishes vendor exposure.

The run identity includes source, immutable window, definition and parser revision.
Listing evidence, queue links and the next checkpoint commit together. Documents
use the existing archive parser/queue; failed items are never silently reset.
"""

import json
from dataclasses import asdict
from datetime import date, datetime, timezone
from urllib.parse import urldefrag, urlencode, urlsplit

from ..application.switching_evidence import definition, definition_sha256
from ..plugins.registry import default_registry
from ..storage.repository import evidence, now
from ..storage.switching import SERVICE, pending_requests
from . import archive
from .cisco_openvuln import CiscoOpenVuln
from .config import validate_config
from .discovery import inventory
from .errors import CiscoAccessError, failure_code
from .transport import allowed, fetch

REVISION = "switching-enumeration-v1"
VENDORS = ("cisco", "aruba", "arista")


def _validate(config, vendor, start_date, end_date, page_limit, document_limit):
    validate_config(config)
    if vendor is not None and vendor not in VENDORS:
        raise ValueError("Unknown switching vendor")
    try:
        start, end = date.fromisoformat(start_date), date.fromisoformat(end_date)
    except (ValueError, TypeError):
        raise ValueError("Expected ISO calendar dates") from None
    if (
        start.isoformat() != start_date
        or end.isoformat() != end_date
        or start_date != "2021-01-01"
        or start >= end
    ):
        raise ValueError("Switching window must start 2021-01-01 and have a later explicit end")
    for value, maximum in ((page_limit, 20), (document_limit, 200)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"Budget must be an integer from 1 to {maximum}")


def _api_url(seed, index, start, end):
    query = {}
    if seed["url"].endswith("/firstpublished"):
        query.update(startDate=start, endDate=end)
    query.update(pageIndex=index, pageSize=seed.get("page_size", 100))
    return seed["url"] + "?" + urlencode(query)


def _queue(db, run_id, source_id, kind, url, ordinal=0):
    archive.enqueue(db, source_id, kind, url)
    item = db.execute(
        "SELECT id FROM archive_items WHERE source_id=? AND kind=? AND url=?",
        (source_id, kind, url),
    ).fetchone()[0]
    if kind == "page":
        db.execute(
            "INSERT OR IGNORE INTO switching_backfill_pages(run_id,item_id,ordinal) VALUES(?,?,?)",
            (run_id, item, ordinal),
        )
    return item


def _issue(db, run_id, code):
    db.execute("INSERT OR IGNORE INTO switching_backfill_issues VALUES(?,?)", (run_id, code))


def _initialize(db, study, digest, vendor, seed, start, end):
    identity = dict(
        study_id=study["id"],
        definition_sha256=digest,
        vendor=vendor,
        source={k: v for k, v in seed.items() if k not in {"page_limit", "document_limit"}}
        if seed
        else None,
        start_date=start,
        end_date=end,
        enumeration_revision=REVISION,
    )
    run_id = definition_sha256(identity)
    with db:
        source_id = None
        if seed:
            db.execute(
                "INSERT OR IGNORE INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
                (vendor, seed["url"], seed["kind"], now()),
            )
            source_id = db.execute(
                "SELECT id FROM archive_sources WHERE vendor=? AND source_url=? AND kind=?",
                (vendor, seed["url"], seed["kind"]),
            ).fetchone()[0]
        db.execute(
            "INSERT OR IGNORE INTO switching_backfills(id,study_id,definition_sha256,vendor,source_id,source_url,kind,start_date,end_date,enumeration_revision,started_at,checked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                study["id"],
                digest,
                vendor,
                source_id,
                seed["url"] if seed else None,
                seed["kind"] if seed else None,
                start,
                end,
                REVISION,
                now(),
                now(),
            ),
        )
        if seed:
            url = _api_url(seed, 1, start, end) if seed["kind"] == "openvuln" else seed["url"]
            _queue(db, run_id, source_id, "page", url, 1)
            if (
                vendor == "aruba"
                and seed["url"] == "https://csaf.arubanetworking.hpe.com/index.txt"
            ):
                _issue(db, run_id, "pre_2022_history_not_enumerated")
    return run_id


def _cisco_page(raw, seed, index, start, end):
    """Conservative advisory-array adapter; unobserved envelopes fail closed.

    Optional total/pageIndex/next fields are consistency checks, not required
    publisher guarantees. A missing total remains unknown even at exhaustion.
    """
    body = json.loads(raw)
    if not isinstance(body, dict) or not isinstance(body.get("advisories"), list):
        raise CiscoAccessError("unsupported_response")
    rows = body["advisories"]
    size = seed.get("page_size", 100)
    if len(rows) > size or (
        "pageIndex" in body and (type(body["pageIndex"]) is not int or body["pageIndex"] != index)
    ):
        raise CiscoAccessError("unsupported_response")
    total = body.get("total")
    if total is not None and (type(total) is not int or total < 0):
        raise CiscoAccessError("unsupported_response")
    expected_next = _api_url(seed, index + 1, start, end)
    if body.get("next") is not None and body["next"] != expected_next:
        raise CiscoAccessError("unsupported_response")
    candidates = []
    for n, row in enumerate(rows):
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("advisoryId"), str)
            or not row["advisoryId"].strip()
        ):
            raise CiscoAccessError("unsupported_response")
        urls = []
        for key in ("csafUrl", "publicationUrl"):
            url = row.get(key)
            if url is not None and (
                not isinstance(url, str)
                or not allowed(url, "cisco")
                or urlsplit(url).hostname == "apix.cisco.com"
            ):
                raise CiscoAccessError("url_rejected")
            if url and url not in urls:
                urls.append(url)
        candidates.append(
            dict(
                identity=row["advisoryId"],
                urls=urls,
                published_at=row.get("firstPublished"),
                status=row.get("status"),
                revision=row.get("version"),
                source_locator=f"/advisories/{n}",
            )
        )
    terminal = len(rows) < size and not body.get("next")
    # A null/absent next is not an exhaustion guarantee when a full page was returned.
    next_pages = [] if terminal or index == 100 else [expected_next]
    return candidates, next_pages, total, terminal, index == 100 and not terminal


def _public_page(raw, url, seed):
    found = (
        asdict(default_registry().get(seed["vendor"]).parse_archive(raw, url, seed["vendor"]))
        if seed["kind"] == "listing"
        else inventory(raw, url, seed["kind"])
    )
    candidates = []
    for n, url in enumerate(found["urls"]):
        url = urldefrag(url)[0]
        if not allowed(url, seed["vendor"]):
            raise ValueError("Unreviewed document link")
        candidates.append(
            dict(
                identity=url,
                urls=[url],
                published_at=None,
                status=None,
                revision=None,
                source_locator=f"listing/document-link/{n}",
            )
        )
    next_pages = found["next_pages"]
    for link in next_pages:
        if not allowed(link, seed["vendor"]):
            raise ValueError("Unreviewed continuation")
        # A feed continuation cannot move to another host/path/filter family.
        a, b = urlsplit(seed["url"]), urlsplit(link)
        if a.hostname != b.hostname:
            raise ValueError("Continuation changes publisher host")
        if seed["kind"] != "listing" and a.path != b.path:
            raise ValueError("Continuation changes listing route")
    return candidates, next_pages, found["entries_without_links"]


def _commit_page(
    db, run, item, raw, candidates, next_pages, total, terminal, source_limit=False, gaps=0
):
    with db:
        ev = evidence(db, raw, item["url"])
        duplicates = 0
        for candidate in candidates:
            old = db.execute(
                "SELECT 1 FROM switching_backfill_entries WHERE run_id=? AND identity=?",
                (run["id"], candidate["identity"]),
            ).fetchone()
            if old:
                duplicates += 1
                _issue(db, run["id"], "overlapping_pages")
            document_ids = []
            for url in candidate["urls"]:
                document_id = _queue(db, run["id"], run["source_id"], "document", url)
                document_ids.append(document_id)
                db.execute(
                    "INSERT OR IGNORE INTO archive_links VALUES(?,?)", (document_id, ev["id"])
                )
            item_id = next(iter(document_ids), None)
            if not candidate["urls"]:
                _issue(db, run["id"], "missing_document_link")
            # Literal publisher values and source locators are retained as discovery,
            # never promoted into affectedness or model claims.
            db.execute(
                "INSERT OR IGNORE INTO switching_backfill_entries VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    run["id"],
                    candidate["identity"],
                    item_id,
                    ev["id"],
                    candidate["source_locator"],
                    candidate["published_at"]
                    if isinstance(candidate["published_at"], str)
                    else None,
                    str(candidate["status"]) if candidate["status"] is not None else None,
                    str(candidate["revision"]) if candidate["revision"] is not None else None,
                    json.dumps(candidate["urls"]),
                ),
            )
            for document_id in document_ids:
                db.execute(
                    "INSERT OR IGNORE INTO switching_backfill_documents VALUES(?,?,?)",
                    (run["id"], candidate["identity"], document_id),
                )
            db.execute(
                "INSERT OR IGNORE INTO switching_backfill_observations VALUES(?,?,?,?,?,?,?,?)",
                (
                    run["id"],
                    candidate["identity"],
                    ev["id"],
                    candidate["source_locator"],
                    candidate["published_at"]
                    if isinstance(candidate["published_at"], str)
                    else None,
                    str(candidate["status"]) if candidate["status"] is not None else None,
                    str(candidate["revision"]) if candidate["revision"] is not None else None,
                    json.dumps(candidate["urls"]),
                ),
            )
        unstable = run["unstable"] or bool(duplicates)
        if total is None and run["expected_total"] is not None:
            _issue(db, run["id"], "publisher_total_missing")
            unstable = True
        if (
            total is not None
            and run["expected_total"] is not None
            and total != run["expected_total"]
        ):
            _issue(db, run["id"], "publisher_total_changed")
            unstable = True
        if terminal and total is not None:
            discovered = db.execute(
                "SELECT count(*) FROM switching_backfill_entries WHERE run_id=?", (run["id"],)
            ).fetchone()[0]
            if discovered != total:
                _issue(db, run["id"], "publisher_total_mismatch")
                unstable = True
        if source_limit:
            _issue(db, run["id"], "publisher_page_limit")
        if gaps:
            _issue(db, run["id"], "entries_without_links")
        for link in next_pages:
            previous = db.execute(
                "SELECT p.evidence_id FROM switching_backfill_pages p JOIN archive_items i ON i.id=p.item_id WHERE p.run_id=? AND i.url=?",
                (run["id"], link),
            ).fetchone()
            if previous is not None:
                unstable = True
                _issue(db, run["id"], "pagination_cycle")
                continue
            _queue(db, run["id"], run["source_id"], "page", link, item["ordinal"] + 1)
        db.execute(
            "UPDATE switching_backfill_pages SET evidence_id=? WHERE run_id=? AND item_id=?",
            (ev["id"], run["id"], item["id"]),
        )
        db.execute(
            "UPDATE archive_items SET state='done',checked_at=?,evidence_id=?,entry_count=?,attempts=0,retry_after=NULL,error_code=NULL WHERE id=?",
            (now(), ev["id"], len(candidates), item["id"]),
        )
        pending = db.execute(
            "SELECT count(*) FROM switching_backfill_pages WHERE run_id=? AND evidence_id IS NULL",
            (run["id"],),
        ).fetchone()[0]
        db.execute(
            "UPDATE switching_backfills SET next_page=?,enumerated=?,unstable=?,expected_total=?,duplicate_entries=duplicate_entries+?,error_code=NULL,retry_at=NULL,checked_at=? WHERE id=?",
            (
                min(item["ordinal"] + 1, 100) if not terminal else item["ordinal"],
                int(not pending and terminal and not source_limit),
                int(unstable),
                total,
                duplicates,
                now(),
                run["id"],
            ),
        )
        if source_limit:
            db.execute(
                "UPDATE switching_backfills SET error_code='publisher_page_limit' WHERE id=?",
                (run["id"],),
            )


def _access_block(db):
    if pending_requests(db, SERVICE):
        return "request_state_unresolved", None
    state = db.execute(
        "SELECT cooldown_until FROM switching_service_state WHERE service=?", (SERVICE,)
    ).fetchone()
    if state and state[0] > datetime.now(timezone.utc).timestamp():
        return "rate_limited", datetime.fromtimestamp(state[0], timezone.utc).isoformat()
    return None


def _block(db, run_id, code, retry_at=None):
    with db:
        db.execute(
            "UPDATE switching_backfills SET error_code=?,retry_at=?,checked_at=? WHERE id=?",
            (code, retry_at, now(), run_id),
        )


def run(
    db,
    config: dict,
    *,
    vendor: str | None = None,
    start_date: str,
    end_date: str,
    page_limit: int = 2,
    document_limit: int = 8,
) -> dict:
    """Resume a logical backfill without publication, retries or unbounded crawling.

    Bounds apply per vendor across all its configured seeds, not per seed. Dates
    are inclusive publisher filters when the route supports them; undated rows
    and documents are retained for later review, never discarded by guessing.
    """
    _validate(config, vendor, start_date, end_date, page_limit, document_limit)
    if db.in_transaction:
        raise ValueError("Finish current transaction before starting backfill")
    study = definition()
    digest = definition_sha256(study)
    for selected in VENDORS if vendor is None else (vendor,):
        seeds = [
            dict(s)
            for s in config.get("switching_sources", []) + config.get("archives", [])
            if s["vendor"] == selected
        ]
        if not seeds:
            _initialize(db, study, digest, selected, None, start_date, end_date)
            continue
        pages_left, documents_left = page_limit, document_limit
        for seed in seeds:
            run_id = _initialize(db, study, digest, selected, seed, start_date, end_date)
            run_row = dict(
                db.execute("SELECT * FROM switching_backfills WHERE id=?", (run_id,)).fetchone()
            )
            if selected == "cisco" and (block := _access_block(db)):
                _block(db, run_id, *block)
                break
            if run_row["retry_at"] and run_row["retry_at"] > now():
                break
            source = dict(
                db.execute(
                    "SELECT * FROM archive_sources WHERE id=?", (run_row["source_id"],)
                ).fetchone()
            )
            halted = False
            client = CiscoOpenVuln(db) if seed["kind"] == "openvuln" else None
            while pages_left and run_row["error_code"] != "publisher_page_limit":
                item = db.execute(
                    "SELECT i.*,p.ordinal FROM switching_backfill_pages p JOIN archive_items i ON i.id=p.item_id WHERE p.run_id=? AND p.evidence_id IS NULL ORDER BY p.ordinal,i.id LIMIT 1",
                    (run_id,),
                ).fetchone()
                if item is None:
                    break
                if item["state"] == "error" and (
                    item["attempts"] >= archive.MAX_ATTEMPTS or item["retry_after"] > now()
                ):
                    break
                pages_left -= 1
                try:
                    raw = (
                        client.get_json(item["url"]) if client else fetch(db, item["url"], selected)
                    )
                    run_row = dict(
                        db.execute(
                            "SELECT * FROM switching_backfills WHERE id=?", (run_id,)
                        ).fetchone()
                    )
                    if client:
                        found, links, total, terminal, limit = _cisco_page(
                            raw, seed, item["ordinal"], start_date, end_date
                        )
                        _commit_page(db, run_row, item, raw, found, links, total, terminal, limit)
                    else:
                        found, links, gaps = _public_page(raw, item["url"], seed)
                        _commit_page(
                            db, run_row, item, raw, found, links, None, not links, gaps=gaps
                        )
                except Exception as error:
                    db.rollback()
                    # Missing auth and unknown request outcomes are access blocks,
                    # not completed failed fetches. In particular, never recover
                    # or age out the transport's unresolved pending marker.
                    if not isinstance(error, CiscoAccessError) or error.code not in {
                        "auth_not_configured",
                        "request_state_unresolved",
                    }:
                        archive.fail(db, source, item, error)
                        if isinstance(error, CiscoAccessError) and error.retry_at is not None:
                            with db:
                                db.execute(
                                    "UPDATE archive_items SET retry_after=? WHERE id=?",
                                    (error.retry_at, item["id"]),
                                )
                    _block(db, run_id, failure_code(error), getattr(error, "retry_at", None))
                    halted = True
                    break
            if halted:
                # An API cooldown/unresolved outcome stops all vendor I/O this pass.
                break
            candidates = db.execute(
                "SELECT DISTINCT i.* FROM switching_backfill_documents e JOIN archive_items i ON i.id=e.item_id WHERE e.run_id=? AND (i.state='pending' OR (i.state='error' AND i.attempts<? AND i.retry_after<=?)) ORDER BY i.id LIMIT ?",
                (run_id, archive.MAX_ATTEMPTS, now(), documents_left),
            ).fetchall()
            for item in candidates:
                documents_left -= 1
                try:
                    archive.document(db, source, item)
                except Exception as error:
                    archive.fail(db, source, item, error)
    return manifest(db, study_id=study["id"])


def _date(value):
    try:
        return date.fromisoformat(value[:10]).isoformat() if isinstance(value, str) else None
    except ValueError:
        return None


def manifest(db, *, study_id: str) -> dict:
    """Sanitized operational receipt, deliberately independent of public schemas."""
    entries = []
    for run_row in db.execute(
        "SELECT * FROM switching_backfills WHERE study_id=? ORDER BY started_at,id", (study_id,)
    ):
        r = dict(run_row)
        identities = db.execute(
            "SELECT * FROM switching_backfill_entries WHERE run_id=? ORDER BY identity",
            (r["id"],),
        ).fetchall()
        documents = {state: 0 for state in ("pending", "done", "not_applicable", "error")}
        known_items = {}
        unknown_dates = 0
        identity_evidence = []
        retrieved = set()
        for item in identities:
            members = db.execute(
                "SELECT i.*,i.evidence_id AS document_evidence_id FROM switching_backfill_documents m JOIN archive_items i ON i.id=m.item_id WHERE m.run_id=? AND m.identity=? ORDER BY i.id",
                (r["id"], item["identity"]),
            ).fetchall()
            for member in members:
                known_items[member["id"]] = member
                if (
                    member["document_evidence_id"] is not None
                    or db.execute(
                        "SELECT 1 FROM evidence WHERE source_url IN (?,?) LIMIT 1",
                        (member["url"], member["resolved_url"]),
                    ).fetchone()
                ):
                    retrieved.add(member["id"])
            observations = [
                dict(o)
                for o in db.execute(
                    "SELECT o.publisher_revision AS revision,o.publisher_status AS status,o.published_at,o.source_locator,o.alternate_urls,e.sha256,e.source_url,e.observed_at AS retrieved_at FROM switching_backfill_observations o JOIN evidence e ON e.id=o.evidence_id JOIN switching_backfill_pages p ON p.run_id=o.run_id AND p.evidence_id=o.evidence_id WHERE o.run_id=? AND o.identity=? ORDER BY p.ordinal,o.source_locator",
                    (r["id"], item["identity"]),
                )
            ]
            for observation in observations:
                observation["alternate_urls"] = json.loads(observation["alternate_urls"])
            alternate_urls = list(
                dict.fromkeys(
                    url for observation in observations for url in observation["alternate_urls"]
                )
            )
            latest = observations[-1] if observations else {}
            published = latest.get("published_at", item["published_at"])
            normalized_identity = None
            status = latest.get("status", item["publisher_status"])
            revision = latest.get("revision", item["publisher_revision"])
            normalized_identities = []
            for member in members:
                if member["document_evidence_id"] is None:
                    continue
                normalized = db.execute(
                    "SELECT normalized FROM revisions WHERE evidence_id=? AND vendor=? ORDER BY id DESC LIMIT 1",
                    (member["document_evidence_id"], r["vendor"]),
                ).fetchone()
                if normalized:
                    record = json.loads(normalized[0])
                    if record.get("advisory_id") not in normalized_identities:
                        normalized_identities.append(record.get("advisory_id"))
                    if not _date(published):
                        published = record.get("published_at")
                    status = status if status is not None else record.get("document_status")
                    revision = revision if revision is not None else record.get("revision")
            if len(normalized_identities) == 1:
                normalized_identity = normalized_identities[0]
            unknown_dates += not bool(_date(published))
            identity_evidence.append(
                dict(
                    identity=item["identity"],
                    normalized_identity=normalized_identity,
                    normalized_identities=normalized_identities,
                    status=status,
                    revision=revision,
                    published_at=published,
                    evidence_id=item["evidence_id"],
                    source_locator=item["source_locator"],
                    alternate_urls=alternate_urls,
                    observations=observations,
                )
            )
        for item in known_items.values():
            documents[item["state"]] += 1
        issues = [
            row[0]
            for row in db.execute(
                "SELECT code FROM switching_backfill_issues WHERE run_id=? ORDER BY code",
                (r["id"],),
            )
        ]
        errors = sorted(
            set(
                [item["error_code"] for item in known_items.values() if item["error_code"]]
                + [code for code in issues if code != "pre_2022_history_not_enumerated"]
                + ([r["error_code"]] if r["error_code"] else [])
            )
        )
        pages = [
            dict(row)
            for row in db.execute(
                "SELECT i.url AS source_url,p.ordinal AS page,e.sha256,e.observed_at AS retrieved_at FROM switching_backfill_pages p JOIN archive_items i ON i.id=p.item_id JOIN evidence e ON e.id=p.evidence_id WHERE p.run_id=? ORDER BY p.ordinal,i.id",
                (r["id"],),
            )
        ]
        pending_pages = db.execute(
            "SELECT count(*) FROM switching_backfill_pages WHERE run_id=? AND evidence_id IS NULL",
            (r["id"],),
        ).fetchone()[0]
        state = (
            "not_configured"
            if r["source_id"] is None
            else "unstable"
            if r["unstable"]
            else "blocked"
            if r["error_code"]
            else "enumerated"
            if r["enumerated"]
            else "partial"
        )
        entries.append(
            dict(
                run_id=r["id"],
                vendor=r["vendor"],
                source_url=r["source_url"],
                source_kind=r["kind"],
                window=dict(start_date=r["start_date"], end_date=r["end_date"]),
                definition_sha256=r["definition_sha256"],
                enumeration_revision=r["enumeration_revision"],
                checkpoint=dict(next_page=r["next_page"], pending_pages=pending_pages),
                pages=dict(retained=len(pages), pending=pending_pages),
                coverage_state=state,
                expected_total=r["expected_total"],
                discovered_unique_identities=len(identities),
                duplicate_entries=r["duplicate_entries"],
                withdrawn_entries=sum(
                    (i["status"] or "").lower() == "withdrawn" for i in identity_evidence
                ),
                documents=documents,
                retrieved=len(retrieved),
                parsed=documents["done"] + documents["not_applicable"],
                parse_failed=sum(
                    i["state"] == "error" and i["error_code"] == "unsupported_or_invalid_document"
                    for i in known_items.values()
                ),
                retrieval_failed=sum(
                    i["state"] == "error"
                    and i["error_code"]
                    in {
                        "network_error",
                        "source_missing",
                        "redirect_target_missing",
                        "http_error",
                        "access_denied",
                        "edge_access_denied",
                        "rate_limited",
                        "access_verification_required",
                    }
                    for i in known_items.values()
                ),
                classified=0,
                classification_pending=len(identities),
                unknown_dates=unknown_dates,
                unknown_models=len(identities),
                exhausted_errors=sum(
                    i["state"] == "error" and i["attempts"] >= archive.MAX_ATTEMPTS
                    for i in known_items.values()
                ),
                errors=errors,
                retry_at=r["retry_at"],
                gaps=[c for c in issues if c == "pre_2022_history_not_enumerated"],
                page_evidence=pages,
                identity_evidence=identity_evidence,
                portfolio_completeness="not_established",
            )
        )
    return dict(study_id=study_id, entries=entries)
