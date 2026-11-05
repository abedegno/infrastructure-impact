"""Reprocess changed parsers or retained notice/unsupported sources without network IO."""

from ..plugins.registry import default_registry
from ..storage.archive_replays import record
from ..storage.repository import collection_result
from .errors import SourceNotRetained, failure_code
from .retained import retained_fetch


def reprocess_errors(db, source, limit):
    from .archive import document

    if type(limit) is not int or not 0 <= limit <= 200:
        raise ValueError("Parser replay limit must be an integer from 0 to 200")

    version = default_registry().fingerprint(source["vendor"])
    items = list(
        db.execute(
            "SELECT * FROM archive_items i WHERE source_id=? AND kind='document' AND "
            "(state='not_applicable' OR (state='error' AND error_code='unsupported_or_invalid_document')) AND "
            "(parser_version IS NULL OR parser_version<>? OR ((evidence_id IS NOT NULL OR EXISTS("
            "SELECT 1 FROM archive_parser_replays r WHERE r.item_id=i.id AND r.parser_version=i.parser_version AND r.outcome='not_retained')) "
            "AND evidence_id IS NOT COALESCE("
            "(SELECT h.evidence_id FROM http_cache h WHERE h.url=i.url),"
            "(SELECT e.id FROM evidence e WHERE e.source_url=i.url ORDER BY e.id DESC LIMIT 1)))) "
            "ORDER BY checked_at,id LIMIT ?",
            (source["id"], version, limit),
        )
    )
    result = dict(
        attempted=0, imported=0, recovered=0, not_applicable=0, still_unsupported=0, not_retained=0
    )
    for item in items:
        result["attempted"] += 1
        # Receipts are unique per parser version. A source-only transition uses
        # retained evidence/revisions and health diagnostics, preserving old receipts.
        parser_changed = item["parser_version"] != version
        receipt = (
            parser_changed
            and not db.execute(
                "SELECT 1 FROM archive_parser_replays WHERE item_id=? AND parser_version=?",
                (item["id"], version),
            ).fetchone()
        )
        attempted_evidence = db.execute(
            "SELECT COALESCE((SELECT evidence_id FROM http_cache WHERE url=?),"
            "(SELECT id FROM evidence WHERE source_url=? ORDER BY id DESC LIMIT 1))",
            (item["url"], item["url"]),
        ).fetchone()[0]
        try:
            changed, _ = document(
                db,
                source,
                item,
                fetcher=retained_fetch,
                reprocessed=True,
                record_replay=bool(receipt),
            )
            result["imported"] += changed
            state = db.execute(
                "SELECT state FROM archive_items WHERE id=?", (item["id"],)
            ).fetchone()[0]
            result["not_applicable" if state == "not_applicable" else "recovered"] += 1
        except Exception as error:
            outcome = (
                "not_retained" if isinstance(error, SourceNotRetained) else "still_unsupported"
            )
            with db:
                # Preserve attempts and retry_after: this was not another HTTP attempt.
                db.execute(
                    "UPDATE archive_items SET parser_version=?,evidence_id=COALESCE(?,evidence_id),"
                    "state='error',error_code=? WHERE id=?",
                    (
                        version,
                        attempted_evidence,
                        item["error_code"] if outcome == "not_retained" else failure_code(error),
                        item["id"],
                    ),
                )
                if receipt:
                    record(db, item["id"], version, outcome, error_code=failure_code(error))
                if outcome != "not_retained":
                    collection_result(
                        db,
                        source["vendor"],
                        item["url"],
                        "error",
                        "Retained capture remains unsupported; no network retry performed.",
                        failure_code(error),
                    )
            result[outcome] += 1
    return result
