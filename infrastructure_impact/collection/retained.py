"""Read-only source resolution from previously retained official captures."""

from ..source_policy import allowed
from .errors import SourceNotRetained, check_access_response


def retained_fetch(db, url, vendor):
    if not allowed(url, vendor):
        raise ValueError("Retained triage source outside vendor routes")
    row = db.execute(
        "SELECT e.raw FROM http_cache h JOIN evidence e ON e.id=h.evidence_id WHERE h.url=?", (url,)
    ).fetchone()
    if row is None:
        row = db.execute(
            "SELECT raw FROM evidence WHERE source_url=? ORDER BY id DESC LIMIT 1", (url,)
        ).fetchone()
    if row is None:
        raise SourceNotRetained("Source bytes are not retained")
    check_access_response(row["raw"])
    return row["raw"]
