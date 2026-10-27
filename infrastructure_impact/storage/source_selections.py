"""Evidence-backed representation choices; no cross-format exposure inference."""

from ..source_policy import allowed
from .repository import evidence, now


def retain(db, vendor, requested_url, selection):
    views = (selection.selected,) + selection.alternatives
    if not allowed(requested_url, vendor) or any(
        not allowed(v.url, vendor) for v in views + selection.unavailable
    ):
        raise ValueError("Source selection outside reviewed vendor routes")
    with db:
        retained = [evidence(db, v.raw, v.url, v.format) for v in views]
        cursor = db.execute(
            "INSERT INTO source_selections(vendor,requested_url,observed_at,reason,selected_evidence_id) VALUES(?,?,?,?,?)",
            (vendor, requested_url, now(), selection.reason, retained[0]["id"]),
        )
        for view, ev in zip(views, retained):
            db.execute(
                "INSERT INTO source_selection_views(selection_id,evidence_id,source_format,adapter_version,assessments) VALUES(?,?,?,?,?)",
                (cursor.lastrowid, ev["id"], view.format, view.adapter_version, view.assessments),
            )
        for view in selection.alternatives:
            db.execute(
                "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details,error_code) VALUES(?,?,?,?,?,?)",
                (
                    vendor,
                    view.url,
                    now(),
                    "ok",
                    "Alternative representation retained and parsed for source comparison",
                    None,
                ),
            )
        for issue in selection.unavailable:
            db.execute(
                "INSERT INTO source_selection_issues(selection_id,source_url,error_code) VALUES(?,?,?)",
                (cursor.lastrowid, issue.url, issue.error_code),
            )
            db.execute(
                "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details,error_code) VALUES(?,?,?,?,?,?)",
                (
                    vendor,
                    issue.url,
                    now(),
                    "error",
                    "Alternative representation unavailable; reviewed selected source retained",
                    issue.error_code,
                ),
            )


def latest(db):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='source_selections'").fetchone():
        return []
    result = []
    for selection in db.execute(
        "SELECT * FROM source_selections WHERE id IN (SELECT MAX(id) FROM source_selections GROUP BY vendor,requested_url) ORDER BY vendor,requested_url"
    ):
        views = []
        for row in db.execute(
            "SELECT v.*,e.source_url,e.sha256,e.observed_at FROM source_selection_views v JOIN evidence e ON e.id=v.evidence_id WHERE v.selection_id=? ORDER BY v.id",
            (selection["id"],),
        ):
            views.append(
                {
                    "source_url": row["source_url"],
                    "source_sha256": row["sha256"],
                    "source_observed_at": row["observed_at"],
                    "source_format": row["source_format"],
                    "adapter_version": row["adapter_version"],
                    "normalized_statements": row["assessments"],
                    "selected": row["evidence_id"] == selection["selected_evidence_id"],
                }
            )
        result.append(
            {
                "vendor": selection["vendor"],
                "requested_url": selection["requested_url"],
                "selected_at": selection["observed_at"],
                "reason": selection["reason"],
                "views": views,
                "unavailable": [
                    dict(row)
                    for row in db.execute(
                        "SELECT source_url,error_code FROM source_selection_issues WHERE selection_id=? ORDER BY id",
                        (selection["id"],),
                    )
                ],
                "meaning": "Reviewed representation choice. Statement counts are not unique products, affectedness rates or proof of equivalent scope. Source differences do not establish intent.",
            }
        )
    return result
