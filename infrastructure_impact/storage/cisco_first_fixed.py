"""Dedicated durable logical queries, independent of the committed HTTP ledger."""

import json


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
    """Commit a claim before entering any transport code; interrupted claims stay unknown."""
    with db:
        return (
            db.execute(
                "UPDATE cisco_first_fixed_queries SET started=1,error_code=NULL,retry_at=NULL "
                "WHERE url=? AND started=0 AND state!='success'",
                (url,),
            ).rowcount
            == 1
        )


def outcome(db, url, state, *, error_code=None, retry_at=None):
    with db:
        db.execute(
            "UPDATE cisco_first_fixed_queries SET state=?,started=0,error_code=?,retry_at=? "
            "WHERE url=?",
            (state, error_code, retry_at, url),
        )


def unknown(db, url):
    # Do not release another process's claim or the transport's pending marker.
    with db:
        db.execute(
            "UPDATE cisco_first_fixed_queries SET error_code='request_state_unresolved' "
            "WHERE url=? AND started=1",
            (url,),
        )


def accepted(db, url, evidence_id, parser_revision, result):
    """Evidence identity and interpretation become visible in the same commit."""
    with db:
        db.execute(
            "UPDATE cisco_first_fixed_queries SET state='success',started=0,error_code=NULL,"
            "retry_at=NULL,evidence_id=?,parser_revision=?,result_json=? WHERE url=?",
            (evidence_id, parser_revision, json.dumps(result), url),
        )


def capture(db, url, digest=None):
    sql = "SELECT * FROM evidence WHERE source_url=?"
    args = [url]
    if digest is not None:
        sql += " AND sha256=?"
        args.append(digest)
    return db.execute(sql + " ORDER BY id DESC LIMIT 1", args).fetchone()


def results(db):
    frames = []
    for row in db.execute(
        "SELECT q.*,e.source_url,e.sha256,e.observed_at FROM cisco_first_fixed_queries q "
        "JOIN evidence e ON e.id=q.evidence_id WHERE q.state='success' ORDER BY q.query_release"
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
