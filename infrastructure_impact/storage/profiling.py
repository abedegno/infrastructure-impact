"""Aggregate vault accounting without returning documents, URLs or private values."""

from datetime import datetime, timezone

# Fixed application fields only. Unknown extension tables and values are not
# copied into an operational receipt, and identifiers never come from feed data.
PAYLOADS = {
    "evidence": ("raw",),
    "revisions": ("normalized",),
    "changes": ("details",),
    "documents": ("text",),
    "reference_documents": ("normalized",),
    "collection_runs": ("details",),
    "pipeline_runs": ("details",),
    "browser_captures": ("normalized",),
}


def storage_profile(db):
    """Measure logical payload bytes in one read transaction; never compact/delete."""
    owns_transaction = not db.in_transaction
    if owns_transaction:
        db.execute("BEGIN")
    try:
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        rows = []
        for table, fields in PAYLOADS.items():
            if table not in tables:
                continue
            columns = {r[1] for r in db.execute('PRAGMA table_info("' + table + '")')}
            sizes = {}
            for field in fields:
                if field in columns:
                    # TEXT length counts characters; BLOB casting measures bytes.
                    sizes[field] = db.execute(
                        'SELECT COALESCE(SUM(length(CAST("' + field + '" AS BLOB))),0) '
                        'FROM "' + table + '"'
                    ).fetchone()[0]
            rows.append(
                dict(
                    table=table,
                    rows=db.execute('SELECT COUNT(*) FROM "' + table + '"').fetchone()[0],
                    tracked_payload_bytes=sum(sizes.values()),
                    columns=sizes,
                )
            )
        sizes = {
            k: db.execute("PRAGMA " + k).fetchone()[0]
            for k in ("page_count", "page_size", "freelist_count")
        }
        return dict(
            schema_version=1,
            measured_at=datetime.now(timezone.utc).isoformat(),
            database_page_bytes=sizes["page_count"] * sizes["page_size"],
            free_page_bytes=sizes["freelist_count"] * sizes["page_size"],
            tables=sorted(rows, key=lambda r: (-r["tracked_payload_bytes"], r["table"])),
            method="Read-only aggregate accounting of fixed application payload columns. Logical byte totals count retained repetitions and exclude indexes, row overhead and unlisted columns; they are not physical per-table sizes. Source bodies, URLs, notes and review values are not returned. No snapshots, revisions or recovery history are removed.",
        )
    finally:
        if owns_transaction:
            db.rollback()
