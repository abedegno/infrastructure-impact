"""Reprocess changed parsers or retained notice/unsupported sources without network IO."""

import json

from ..plugins.registry import default_registry
from ..storage.archive_replays import record
from ..storage.repository import collection_result, evidence
from .errors import SourceNotRetained, failure_code
from .retained import retained_fetch


def current_evidence(db, url):
    """Use the same cache-first selection as retained_fetch, including reversions."""
    return db.execute(
        "SELECT COALESCE((SELECT e.id FROM http_cache h JOIN evidence e ON e.id=h.evidence_id WHERE h.url=?),"
        "(SELECT id FROM evidence WHERE source_url=? ORDER BY id DESC LIMIT 1))",
        (url, url),
    ).fetchone()[0]


def track_inputs(fetcher, inputs):
    def retrieve(db, url, vendor):
        # Keep a missing/challenged dependency too, even if the resolver raises
        # or chooses an available alternative. Only actually requested URLs count.
        inputs[url] = current_evidence(db, url)
        raw = fetcher(db, url, vendor)
        inputs[url] = evidence(db, raw, url)["id"]
        return raw

    return retrieve


def input_snapshot(item, inputs):
    # scope belongs to public discovery prose on pages; on documents it holds
    # only this internal, versioned input snapshot. Persist with the outcome in
    # the same transaction, never before it. No receipt/history rewrite.
    if not inputs or item["kind"] != "document":
        return item["scope"]
    return json.dumps(
        dict(version=1, kind="document", requested_url=item["url"], inputs=inputs),
        sort_keys=True,
    )


def inputs_changed(db, item):
    """None means legacy/invalid state: it cannot prove unchanged processing."""
    if item["kind"] != "document":
        return None
    try:
        state = json.loads(item["scope"])
    except (TypeError, ValueError):
        return None
    if (
        not isinstance(state, dict)
        or set(state) != {"version", "kind", "requested_url", "inputs"}
        or type(state["version"]) is not int
        or state["version"] != 1
        or state["kind"] != "document"
        or state["requested_url"] != item["url"]
        or not isinstance(state["inputs"], dict)
        or not state["inputs"]
        or any(
            not isinstance(url, str)
            or not url
            or (ev is not None and (type(ev) is not int or ev < 1))
            for url, ev in state["inputs"].items()
        )
    ):
        return None
    return any(current_evidence(db, url) != ev for url, ev in state["inputs"].items())


def reprocess_errors(db, source, limit):
    from .archive import document

    if type(limit) is not int or not 0 <= limit <= 200:
        raise ValueError("Parser replay limit must be an integer from 0 to 200")

    version = default_registry().fingerprint(source["vendor"])
    # A completed document resolution distinguishes an established source that
    # later returned a challenge from an initial transport/access failure. Keep
    # that transition eligible without admitting HTTP denials or changing backoff.
    # Legacy notice -> missing dependency failures had a null error code.
    items = db.execute(
        "SELECT * FROM archive_items i WHERE source_id=? AND kind='document' AND "
        "(state='not_applicable' OR (state='error' AND (error_code IN ('unsupported_or_invalid_document','retained_source_missing') OR "
        "((error_code='access_verification_required' OR error_code IS NULL) AND resolved_url IS NOT NULL AND evidence_id IS NOT NULL)))) AND "
        "(parser_version IS NULL OR parser_version<>? OR evidence_id IS NOT NULL OR EXISTS("
        "SELECT 1 FROM archive_parser_replays r WHERE r.item_id=i.id AND r.parser_version=i.parser_version AND r.outcome='not_retained')) "
        "ORDER BY checked_at,id",
        (source["id"], version),
    )
    result = dict(
        attempted=0, imported=0, recovered=0, not_applicable=0, still_unsupported=0, not_retained=0
    )
    for item in items:
        if result["attempted"] >= limit:
            break
        # Filter before spending the shared budget. Missing legacy snapshots get
        # one bounded attempt; evidence IDs from different URLs are never compared.
        if item["parser_version"] == version and inputs_changed(db, item) is False:
            continue
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
        attempted_evidence = current_evidence(db, item["url"])
        inputs = {}
        try:
            changed, _ = document(
                db,
                source,
                item,
                fetcher=retained_fetch,
                reprocessed=True,
                record_replay=bool(receipt),
                replay_inputs=inputs,
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
                    "state='error',error_code=?,scope=? WHERE id=?",
                    (
                        version,
                        attempted_evidence,
                        failure_code(error),
                        input_snapshot(item, inputs),
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
