"""Evidence-linked research questions; no automatic exposure or intent verdicts."""

import json
import re
from datetime import datetime

from jsonschema import Draft202012Validator

from ..collection.transport import allowed
from ..domain import validator
from ..settings import PACKAGE
from .comparison import parse_date


def casefiles(data, definition=None):
    if definition is None:
        definition = json.loads((PACKAGE / "resources/disclosure-cases.json").read_text())
    schema = json.loads((PACKAGE / "schemas/disclosure-case-definition-v1.json").read_text())
    Draft202012Validator(schema, format_checker=validator().format_checker).validate(definition)
    if len({c["id"] for c in definition["cases"]}) != len(definition["cases"]):
        raise ValueError("Case IDs must be unique")
    cases = []
    for case in definition["cases"]:
        vendor = case["vendor"]
        for url in case["advisory_urls"] + case["release_source_leads"]:
            if not allowed(url, vendor):
                raise ValueError("Case file requires official vendor HTTPS sources")
        records = [
            r
            for r in data["records"]
            if r["vendor"] == vendor
            and r["source_url"] in case["advisory_urls"]
            and set(case["cve_ids"]) & set(r["cves"])
            and r.get("document_status") != "draft"
        ]
        claims = [
            a
            for r in records
            for a in r["assessments"]
            if a["cve_id"] in case["cve_ids"]
            and re.search(case["product_pattern"], a["product"], re.I)
            and all(pair in a.get("product_context", []) for pair in case.get("claim_context", []))
        ]
        evidence = [
            dict(
                role="publisher_advisory_or_resolved_issues",
                source_url=r["source_url"],
                source_sha256=r["sha256"],
                evidence_id=r["evidence_id"],
                observed_at=r.get("source_observed_at"),
                publisher_published_at=r.get("published_at"),
                publisher_reported_fix_date=r.get("reported_fix_date"),
            )
            for r in records
        ]
        gaps = []
        for record in records:
            published = parse_date(record.get("published_at"))
            fixed = parse_date(record.get("reported_fix_date"))
            if published and fixed and fixed < published:
                gaps.append(
                    dict(
                        days=round((published - fixed).total_seconds() / 86400, 2),
                        source_sha256=record["sha256"],
                        basis="Both dates are publisher claims in the same document; not independent release availability or first-ever disclosure",
                    )
                )
        linked_events = [
            e["event_id"]
            for e in data.get("timeline", {}).get("events", [])
            if e["vendor"] == vendor
            and e["cve_id"] in case["cve_ids"]
            and e["source_url"] in case["advisory_urls"]
        ]
        checks = [
            dict(
                source_url=h["source_url"],
                outcome=h["outcome"],
                error_code=h.get("error_code"),
                checked_at=h["checked_at"],
            )
            for h in data.get("health", [])
            if h["vendor"] == vendor
            and h["source_url"] in case["advisory_urls"] + case["release_source_leads"]
        ]
        histories = [
            d
            for d in data.get("publisher_history", {}).get("documents", [])
            if d["vendor"] == vendor and d["source_url"] in case["release_source_leads"]
        ]
        offsets = []
        prior_documents = []
        for history in histories:
            initials = [e for e in history["events"] if e["kind"] == "initial_document_release"]
            if len(initials) != 1:
                continue
            initial = initials[0]["publisher_date"]
            for event in history["events"]:
                for cid in sorted(set(event["cve_ids"]) & set(case["cve_ids"])):
                    if (
                        event["kind"] == "cve_references_added"
                        and event["publisher_date"] >= initial
                    ):
                        offsets.append(
                            dict(
                                cve_id=cid,
                                initial_document_date=initial,
                                reference_added_date=event["publisher_date"],
                                days=(
                                    datetime.fromisoformat(event["publisher_date"])
                                    - datetime.fromisoformat(initial)
                                ).days,
                                source_url=history["source_url"],
                                source_sha256=history["source_sha256"],
                                basis="Publisher-reported documentation chronology in one currently retained document; not independent release availability or a silent fix.",
                            )
                        )
            for record in records:
                product_pattern = case.get("prior_advisory_product_pattern")
                applicable = [
                    a
                    for a in record["assessments"]
                    if product_pattern
                    and re.search(product_pattern, a["product"])
                    and a["cve_id"] in case["cve_ids"]
                ]
                if not applicable:
                    continue
                try:
                    # A labelled calendar claim; never infer UTC or eligible timing.
                    published = datetime.fromisoformat(
                        record["published_at"].replace("Z", "+00:00")
                    )
                except (ValueError, TypeError, AttributeError):
                    continue
                if published.date().isoformat() < initial:
                    # Keep product labels bound to the assessment CVE. A shared
                    # source remains one identity, with separately selectable rows.
                    for cid in sorted({a["cve_id"] for a in applicable}):
                        prior_documents.append(
                            dict(
                                source_url=record["source_url"],
                                source_sha256=record["sha256"],
                                publisher_published_at=record["published_at"],
                                date_basis="publisher_calendar_claim_timezone_unspecified"
                                if published.tzinfo is None
                                else "publisher_calendar_claim_timezone_qualified",
                                cve_ids=[cid],
                                product_labels=sorted(
                                    {a["product"] for a in applicable if a["cve_id"] == cid}
                                ),
                                interpretation="An earlier-dated vendor advisory is counter-evidence to inferring nondisclosure from the release-note edit. Its historical availability and first-ever disclosure remain unverified.",
                            )
                        )
        cases.append(
            dict(
                **case,
                status="incomplete_evidence",
                finding="no_concealment_finding",
                reviewed_at=definition["reviewed_at"],
                review_method=definition["review_method"],
                selected_cve_ids=case["cve_ids"],
                exposure=dict(
                    by_cve=[
                        {
                            "cve_id": cid,
                            "observed_statuses": sorted(
                                {a["status"] for a in claims if a["cve_id"] == cid}
                            ),
                            "statement_count": sum(a["cve_id"] == cid for a in claims),
                        }
                        for cid in case["cve_ids"]
                    ],
                    publisher_statement_retained=bool(claims),
                    observed_statuses=sorted({a["status"] for a in claims}),
                    statement_count=len(claims),
                    prior_affectedness_inferred=False,
                ),
                evidence=evidence,
                reported_date_gaps=gaps,
                publisher_document_histories=histories,
                reported_documentation_offsets=offsets,
                earlier_dated_vendor_documents=prior_documents,
                release_source_state="documentation_history_retained_availability_unverified"
                if histories
                else "leads_only_not_verified"
                if case["release_source_leads"]
                else "not_identified",
                independent_release_availability_verified=False,
                earliest_disclosure_established=False,
                timeline_event_ids=linked_events[:20],
                timeline_links_truncated=len(linked_events) > 20,
                source_checks=checks,
            )
        )
    return dict(
        schema_version=1,
        cases=cases,
        method="Case files link retained publisher statements, current documentation histories and earlier-dated vendor documents to research gaps and alternative explanations. Uncollected source leads are not evidence. Publisher dates do not verify historical availability. Browser captures and private review notes are excluded. No automated verification, prior affectedness or intent inference.",
    )


def select_casefiles(document, cohort, vendor=None):
    cohort = set(cohort)
    cases = []
    for case in document.get("cases", []):
        selected = sorted(cohort & set(case["cve_ids"]))
        if not selected or (vendor is not None and case["vendor"] != vendor):
            continue
        rows = [r for r in case["exposure"]["by_cve"] if r["cve_id"] in selected]
        count = sum(r["statement_count"] for r in rows)
        cases.append(
            {
                **case,
                "selected_cve_ids": selected,
                "reported_documentation_offsets": [
                    o
                    for o in case.get("reported_documentation_offsets", [])
                    if o["cve_id"] in selected
                ],
                "earlier_dated_vendor_documents": [
                    {**d, "cve_ids": sorted(set(d["cve_ids"]) & set(selected))}
                    for d in case.get("earlier_dated_vendor_documents", [])
                    if set(d["cve_ids"]) & set(selected)
                ],
                "publisher_document_histories": [
                    {
                        **d,
                        "events": [
                            e
                            for e in d["events"]
                            if not e["cve_ids"] or set(e["cve_ids"]) & set(selected)
                        ],
                    }
                    for d in case.get("publisher_document_histories", [])
                ],
                "exposure": {
                    **case["exposure"],
                    "by_cve": rows,
                    "statement_count": count,
                    "publisher_statement_retained": bool(count),
                    "observed_statuses": sorted({s for r in rows for s in r["observed_statuses"]}),
                },
                "timeline_event_ids": [
                    e
                    for e in case["timeline_event_ids"]
                    if any(e.endswith("-" + cid) for cid in selected)
                ],
            }
        )
    return {**document, "cases": cases}
