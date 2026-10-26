"""Public metadata for locally observed revisions, with separate publisher dates."""

import json
from collections import deque


def evidence_timeline(db, max_revisions=5000, max_events=5000):
    rows = list(
        db.execute(
            "SELECT r.*,e.sha256 FROM revisions r JOIN evidence e ON e.id=r.evidence_id ORDER BY r.id DESC LIMIT ?",
            (max_revisions + 1,),
        )
    )
    truncated = len(rows) > max_revisions
    rows = list(reversed(rows[:max_revisions]))
    first = {
        (r["vendor"], r["advisory_id"]): r["first_id"]
        for r in db.execute(
            "SELECT vendor,advisory_id,MIN(id) AS first_id FROM revisions GROUP BY vendor,advisory_id"
        )
    }
    changes = {}
    if rows:
        for row in db.execute(
            "SELECT revision_id,kind,details FROM changes WHERE revision_id>=? AND revision_id<=? ORDER BY id",
            (rows[0]["id"], rows[-1]["id"]),
        ):
            changes.setdefault(row["revision_id"], []).append(
                (row["kind"], json.loads(row["details"]))
            )
    events = deque(maxlen=max_events)
    events_seen = 0
    previous = {}
    for row in rows:
        record = json.loads(row["normalized"])
        key = (row["vendor"], row["advisory_id"])
        prior = previous.get(key, {})
        kinds = [kind for kind, _ in changes.get(row["id"], []) if kind != "cve_reference_added"]
        kind = (
            "first_observed"
            if row["id"] == first[key]
            else kinds[0]
            if kinds
            else "source_view_change"
            if prior and prior.get("source_url") != row["source_url"]
            else "parser_reinterpretation"
            if prior and prior.get("adapter_version") != record.get("adapter_version")
            else "source_refresh"
            if prior
            else "earlier_history_outside_window"
        )
        for cid in sorted(set(record.get("cves", [])) | set(prior.get("cves", []))):
            claims = [a for a in record.get("assessments", []) if a["cve_id"] == cid]
            fields = set()
            added = False
            for change_kind, details in changes.get(row["id"], []):
                if change_kind == "cve_reference_added":
                    added = cid in details.get("cves", [])
                elif isinstance(details, list):
                    fields.update(d["field"] for d in details if d.get("cve_id", cid) == cid)
            events_seen += 1
            events.append(
                dict(
                    event_id=f"revision-{row['id']}-{cid}",
                    revision_id=row["id"],
                    evidence_id=row["evidence_id"],
                    vendor=row["vendor"],
                    advisory_id=row["advisory_id"],
                    cve_id=cid,
                    observed_at=row["observed_at"],
                    kind="source_revision"
                    if kind == "assessment_revision" and "assessment" not in fields
                    else kind,
                    source_url=row["source_url"],
                    source_sha256=row["sha256"],
                    publisher_published_at=record.get("published_at"),
                    publisher_updated_at=record.get("updated_at"),
                    publisher_reported_fix_date=record.get("reported_fix_date"),
                    publisher_fix_date_scope="document_shared"
                    if len(record.get("cves", [])) > 1
                    else "single_cve_document",
                    statuses=sorted({a["status"] for a in claims}),
                    previous_statuses=sorted(
                        {a["status"] for a in prior.get("assessments", []) if a["cve_id"] == cid}
                    )
                    if prior
                    else None,
                    product_count=len({a["product"] for a in claims}),
                    reference_present=cid in record.get("cves", []),
                    cve_reference_added=added,
                    change_fields=sorted(fields),
                    document_status=record.get("document_status", "unknown"),
                )
            )
        previous[key] = record
    return dict(
        schema_version=1,
        history_truncated=truncated,
        events_truncated=events_seen > max_events,
        event_limit=max_events,
        revision_limit=max_revisions,
        revisions_included=len(rows),
        events=list(reversed(events)),
        method="Ordered by local revision observation, not publisher date. Publisher dates are retained claims and can be revised. Reported fix dates have document scope, not verified availability. Parser and source-view changes remain distinct. A removed reference is not unaffectedness or concealment.",
    )


def select_timeline(document, cohort, vendor=None):
    selected = set(cohort)
    return {
        **document,
        "events": [
            e
            for e in document.get("events", [])
            if e["cve_id"] in selected and (vendor is None or e["vendor"] == vendor)
        ],
    }
