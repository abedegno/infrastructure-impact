"""Append-only offline parser recovery receipts, separate from HTTP observations."""

from .repository import now

METHOD = (
    "Recorded retained-capture normalization attempts since replay logging began. "
    "No network retries or reconstructed historical retrieval dates. A recovery "
    "validates retained bytes under a newer parser; current source availability "
    "and independent human review are not established. Failed attempts may lack "
    "linked selected-capture metadata. Latest ten recorded attempts are shown."
)


def record(
    db, item_id, parser_version, outcome, *, evidence_id=None, error_code=None, alternate_issues=0
):
    db.execute(
        "INSERT INTO archive_parser_replays(item_id,parser_version,checked_at,outcome,evidence_id,error_code,alternate_issues) VALUES(?,?,?,?,?,?,?)",
        (item_id, parser_version, now(), outcome, evidence_id, error_code, alternate_issues),
    )


def summary(db, source_id):
    result = dict(
        attempts=0,
        recovered=0,
        not_applicable=0,
        still_unsupported=0,
        not_retained=0,
        first_logged_at=None,
        latest_logged_at=None,
        examples=[],
        examples_truncated=False,
        method=METHOD,
    )
    if (
        source_id is None
        or not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='archive_parser_replays'"
        ).fetchone()
    ):
        return result
    for row in db.execute(
        "SELECT r.outcome,count(*) AS total,min(r.checked_at) AS first,max(r.checked_at) AS last FROM archive_parser_replays r JOIN archive_items i ON i.id=r.item_id WHERE i.source_id=? GROUP BY r.outcome",
        (source_id,),
    ):
        result[row["outcome"]] = row["total"]
        result["attempts"] += row["total"]
        result["first_logged_at"] = min(filter(None, (result["first_logged_at"], row["first"])))
        result["latest_logged_at"] = max(filter(None, (result["latest_logged_at"], row["last"])))
    result["examples"] = [
        dict(row)
        for row in db.execute(
            "SELECT i.url AS requested_url,r.parser_version,r.checked_at,r.outcome,r.error_code,r.alternate_issues,e.source_url,e.sha256 AS source_sha256,e.observed_at AS source_observed_at FROM archive_parser_replays r JOIN archive_items i ON i.id=r.item_id LEFT JOIN evidence e ON e.id=r.evidence_id WHERE i.source_id=? ORDER BY r.id DESC LIMIT 10",
            (source_id,),
        )
    ]
    result["examples_truncated"] = result["attempts"] > 10
    return result
