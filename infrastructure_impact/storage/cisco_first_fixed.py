"""Dedicated durable logical queries, independent of the committed HTTP ledger."""

import json
from datetime import datetime, timezone


def enqueue(db, queries):
    with db:
        db.executemany(
            "INSERT OR IGNORE INTO cisco_first_fixed_queries(url,os_type,query_release,state) "
            "VALUES(?,'iosxe',?,'pending')",
            queries,
        )


def queries(db):
    return [
        dict(row)
        for row in db.execute("SELECT * FROM cisco_first_fixed_queries ORDER BY query_release,url")
    ]


def start(db, url):
    """Return the committed generation owned by this call, or None if claimed."""
    with db:
        row = db.execute(
            "UPDATE cisco_first_fixed_queries SET state='pending',started=1,attempt=attempt+1,"
            "error_code=NULL,retry_at=NULL,response_attempt=NULL,response_evidence_id=NULL,"
            "response_acknowledged_at=NULL,evidence_id=NULL,parser_revision=NULL,result_json=NULL "
            "WHERE url=? AND started=0 AND state!='success' RETURNING attempt",
            (url,),
        ).fetchone()
    return row[0] if row else None


def outcome(db, url, attempt, state, *, error_code=None, retry_at=None):
    """Only the current, nonterminal generation may release its claim."""
    with db:
        return (
            db.execute(
                "UPDATE cisco_first_fixed_queries SET state=?,started=0,error_code=?,retry_at=? "
                "WHERE url=? AND attempt=? AND started=1 AND state='pending'",
                (state, error_code, retry_at, url, attempt),
            ).rowcount
            == 1
        )


def unknown(db, url, attempt):
    # No non-owner releases a claim or changes the transport's pending marker.
    with db:
        db.execute(
            "UPDATE cisco_first_fixed_queries SET error_code='request_state_unresolved' "
            "WHERE url=? AND attempt=? AND started=1 AND state='pending' "
            "AND response_evidence_id IS NULL",
            (url, attempt),
        )


def acknowledge(db, url, attempt, evidence_id):
    """Caller invokes only AFTER get_json returned and exact URL/SHA matched.

    Capture IDs can predate the call because evidence deduplicates identical
    bytes. This distinct committed receipt binds successful return to generation.
    """
    with db:
        return (
            db.execute(
                "UPDATE cisco_first_fixed_queries SET response_attempt=attempt,"
                "response_evidence_id=?,response_acknowledged_at=?,error_code=NULL "
                "WHERE url=? AND attempt=? AND started=1 AND state='pending' "
                "AND response_evidence_id IS NULL "
                "AND EXISTS (SELECT 1 FROM evidence WHERE id=? AND source_url=?)",
                (
                    evidence_id,
                    datetime.now(timezone.utc).isoformat(),
                    url,
                    attempt,
                    evidence_id,
                    url,
                ),
            ).rowcount
            == 1
        )


def receipt(db, url, attempt):
    """Only an acknowledged completed call is recoverable, never URL-only bytes."""
    return db.execute(
        "SELECT e.* FROM cisco_first_fixed_queries q JOIN evidence e "
        "ON e.id=q.response_evidence_id AND e.source_url=q.url "
        "WHERE q.url=? AND q.attempt=? AND q.response_attempt=q.attempt "
        "AND q.response_acknowledged_at IS NOT NULL AND q.started=1 AND q.state='pending'",
        (url, attempt),
    ).fetchone()


def accepted(db, url, attempt, evidence_id, parser_revision, result):
    """Interpret only this acknowledged generation; stale terminal writes fail."""
    with db:
        return (
            db.execute(
                "UPDATE cisco_first_fixed_queries SET state='success',started=0,error_code=NULL,"
                "retry_at=NULL,evidence_id=?,parser_revision=?,result_json=? "
                "WHERE url=? AND attempt=? AND started=1 AND state='pending' "
                "AND response_attempt=attempt AND response_evidence_id=? "
                "AND response_acknowledged_at IS NOT NULL",
                (evidence_id, parser_revision, json.dumps(result), url, attempt, evidence_id),
            ).rowcount
            == 1
        )


def capture(db, url, digest):
    return db.execute(
        "SELECT * FROM evidence WHERE source_url=? AND sha256=?",
        (url, digest),
    ).fetchone()


def results(db):
    frames = []
    for row in db.execute(
        "SELECT q.*,e.source_url,e.sha256,e.observed_at FROM cisco_first_fixed_queries q "
        "JOIN evidence e ON e.id=q.evidence_id AND e.source_url=q.url "
        "WHERE q.state='success' AND q.response_attempt=q.attempt "
        "AND q.response_evidence_id=q.evidence_id AND q.response_acknowledged_at IS NOT NULL "
        "ORDER BY q.query_release"
    ):
        frames.append(
            {
                "source": {
                    "url": row["source_url"],
                    "sha256": row["sha256"],
                    "retrieved_at": row["observed_at"],
                    "evidence_id": row["evidence_id"],
                },
                "query_release": row["query_release"],
                "parser_revision": row["parser_revision"],
                **json.loads(row["result_json"]),
            }
        )
    return frames
