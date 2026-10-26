"""Successful retrieval checks are distinct from content and semantic revisions."""

from .repository import now

METHOD = "Successful HTTP retrieval checks after access-response screening; document validity and component analysis are separate. Logging starts with the first recorded check. Earlier unlogged checks and historical public availability remain unknown. Different raw fingerprints do not establish semantic or security changes."


def observe(db, vendor, url, evidence_id, http_status):
    if (
        isinstance(http_status, bool)
        or not isinstance(http_status, int)
        or not (200 <= http_status < 300 or http_status == 304)
    ):
        raise ValueError("Only successful HTTP responses or cache validation may be observed")
    row = db.execute("SELECT source_url FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not row or row[0] != url:
        raise ValueError("Retrieval observation must reference evidence from the same URL")
    with db:
        cursor = db.execute(
            "INSERT INTO source_observations(vendor,source_url,checked_at,evidence_id,http_status) VALUES(?,?,?,?,?)",
            (vendor, url, now(), evidence_id, http_status),
        )
    return cursor.lastrowid


def history(db, vendor, url, limit=12):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("Observation history limit must be from 1 to 100")
    result = dict(
        logged_checks=0,
        distinct_fingerprints=0,
        same_as_previous_checks=0,
        http_304_checks=0,
        first_logged_check_at=None,
        last_logged_check_at=None,
        checks=[],
        checks_truncated=False,
        method=METHOD,
    )
    if not db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_observations'"
    ).fetchone():
        return result  # Read-only pre-migration archives have no invented check history.
    sequence = "WITH sequence AS (SELECT o.*,lag(evidence_id) OVER (ORDER BY id) AS previous_evidence_id FROM source_observations o WHERE vendor=? AND source_url=?) "
    summary = db.execute(
        sequence
        + "SELECT count(*) AS n,count(DISTINCT evidence_id) AS distinct_n,coalesce(sum(evidence_id=previous_evidence_id),0) AS same_n,coalesce(sum(http_status=304),0) AS cached_n,min(checked_at) AS first_at,max(checked_at) AS last_at FROM sequence",
        (vendor, url),
    ).fetchone()
    result.update(
        logged_checks=summary["n"],
        distinct_fingerprints=summary["distinct_n"],
        same_as_previous_checks=summary["same_n"],
        http_304_checks=summary["cached_n"],
        first_logged_check_at=summary["first_at"],
        last_logged_check_at=summary["last_at"],
        checks_truncated=summary["n"] > limit,
    )
    for row in db.execute(
        sequence
        + "SELECT s.*,e.sha256 FROM sequence s JOIN evidence e ON e.id=s.evidence_id ORDER BY s.id DESC LIMIT ?",
        (vendor, url, limit),
    ):
        result["checks"].append(
            dict(
                checked_at=row["checked_at"],
                source_sha256=row["sha256"],
                http_status=row["http_status"],
                content_state="first_logged_capture"
                if row["previous_evidence_id"] is None
                else "same_as_previous_capture"
                if row["evidence_id"] == row["previous_evidence_id"]
                else "different_from_previous_capture",
            )
        )
    return result
