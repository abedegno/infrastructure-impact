"""Recover unsupported retained documents after parser changes, without network IO."""

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
            "SELECT * FROM archive_items WHERE source_id=? AND kind='document' AND state='error' AND error_code='unsupported_or_invalid_document' AND (parser_version IS NULL OR parser_version<>?) ORDER BY checked_at,id LIMIT ?",
            (source["id"], version, limit),
        )
    )
    result = dict(
        attempted=0, imported=0, recovered=0, not_applicable=0, still_unsupported=0, not_retained=0
    )
    for item in items:
        result["attempted"] += 1
        try:
            changed, _ = document(db, source, item, fetcher=retained_fetch, reprocessed=True)
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
                    "UPDATE archive_items SET parser_version=? WHERE id=?", (version, item["id"])
                )
                record(db, item["id"], version, outcome, error_code=failure_code(error))
                if outcome != "not_retained":
                    collection_result(
                        db,
                        source["vendor"],
                        item["url"],
                        "error",
                        "Retained capture remains unsupported after a parser change; no network retry performed.",
                        failure_code(error),
                    )
            result[outcome] += 1
    return result
