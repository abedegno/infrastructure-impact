"""Whole-publication coverage and review gaps, without comparative security rates."""

from .comparison import parse_date


def vendor_gaps(data):
    profiles = {v["vendor"]: v for v in data.get("catalogue", {}).get("vendors", [])}
    audits = {v["vendor"]: v for v in data.get("source_audit", {}).get("vendors", [])}
    cases = data.get("extraction_validation", {}).get("cases", [])
    vendors = []
    for vendor, name in data["vendors"].items():
        records = [r for r in data["records"] if r["vendor"] == vendor]
        checks = [
            h for h in data.get("health", []) if h["vendor"] == vendor and h["outcome"] == "error"
        ]
        reviewed = [c for c in cases if c["vendor"] == vendor]
        unresolved = [
            dict(id=c["id"], cve_id=c["cve_id"], source_url=c["source_url"], outcome=c["outcome"])
            for c in reviewed
            if c["outcome"] not in {"pass", "reviewed_scope_match_source_changed"}
        ]
        archives = audits.get(vendor, {}).get("archives", [])
        vendors.append(
            dict(
                vendor=vendor,
                name=name,
                advisories=len(records),
                metadata_only_advisories=sum(not r["assessments"] for r in records),
                without_cve_advisories=sum(not r["cves"] for r in records),
                without_cve_sources=[
                    dict(title=r["title"], source_url=r["source_url"], source_sha256=r["sha256"])
                    for r in records
                    if not r["cves"]
                ][:100],
                without_cve_sources_truncated=sum(not r["cves"] for r in records) > 100,
                freshness=profiles.get(vendor, {}).get("freshness", "not_checked"),
                configured_sources=len(profiles.get(vendor, {}).get("sources", [])),
                source_error_count=len(checks),
                source_errors=[
                    dict(
                        source_url=c["source_url"],
                        error_code=c.get("error_code") or "unknown_error",
                        checked_at=c["checked_at"],
                    )
                    for c in checks[:100]
                ],
                source_errors_truncated=len(checks) > 100,
                archive_pending=sum(
                    a[k]["pending"] for a in archives for k in ["pages", "documents"]
                ),
                archive_failed=sum(a[k]["error"] for a in archives for k in ["pages", "documents"]),
                review_total=len(reviewed),
                review_raw_passes=sum(c["outcome"] == "pass" for c in reviewed),
                review_section_matches=sum(
                    c["outcome"] == "reviewed_scope_match_source_changed" for c in reviewed
                ),
                review_unresolved=unresolved,
                portfolio_completeness="not_established",
                coverage=coverage_matrix_row(
                    profiles.get(vendor, {}), audits.get(vendor, {}), records, checks
                ),
            )
        )
    result = dict(
        schema_version=1,
        scope="whole_publication",
        independent_human_review_completed=False,
        vendors=vendors,
        method="Latest retained check per source URL, archive queue counts and purposive source-review assertions across the whole publication. These counts do not measure vendor security, disclosure completeness or a representative error rate. Metadata-only summaries and security notices without CVE identifiers do not establish product exposure or concealment. Human review remains pending; a section match is separate from a raw-byte pass.",
    )

    validate_report(result)
    return result


def validate_report(value):
    import json

    from jsonschema import Draft202012Validator, FormatChecker

    from ..settings import PACKAGE

    Draft202012Validator(
        json.loads((PACKAGE / "schemas/vendor-gaps-v1.json").read_text()),
        format_checker=FormatChecker(),
    ).validate(value)


def coverage_matrix_row(profile, audit, records, checks):
    """Project explicit coverage fields, separating publisher dates from collection."""
    dates = sorted(
        [r["published_at"] for r in records if parse_date(r.get("published_at"))], key=parse_date
    )
    formats = sorted({r["source_format"] for r in records})
    access_codes = {"access_verification_required", "edge_access_denied"}
    return dict(
        declared_product_families=list(profile.get("product_families", [])),
        declared_history_scope=profile.get("history_scope", "Coverage profile not declared"),
        declared_gaps=list(profile.get("known_gaps", [])),
        capabilities=list(profile.get("capabilities", [])),
        configured_sources=[
            dict(
                source_url=s["url"],
                role=s["role"],
                kind=s.get("kind", "document"),
                per_pass_limit=s.get("document_limit", s.get("limit")),
            )
            for s in profile.get("sources", [])
        ],
        observed_formats=[
            dict(format=f, advisories=sum(r["source_format"] == f for r in records))
            for f in formats
        ],
        publisher_date_range=dict(
            earliest=dates[0] if dates else None, latest=dates[-1] if dates else None
        ),
        documents_without_publisher_date=sum(
            not parse_date(r.get("published_at")) for r in records
        ),
        archives=[
            dict(
                source_url=a["source_url"],
                kind=a["kind"],
                page_limit=a["page_limit"],
                document_limit=a["document_limit"],
                pages={k: a["pages"][k] for k in ["pending", "done", "not_applicable", "error"]},
                documents={
                    k: a["documents"][k] for k in ["pending", "done", "not_applicable", "error"]
                },
                known_queue_exhausted=a["known_queue_exhausted"],
                publisher_date_range={
                    k: a["publisher_date_range"][k] for k in ["earliest", "latest"]
                },
            )
            for a in audit.get("archives", [])
        ],
        unsupported_sources=sum(
            c.get("error_code") == "unsupported_or_invalid_document" for c in checks
        ),
        other_error_sources=sum(
            c.get("error_code") not in access_codes | {"unsupported_or_invalid_document"}
            for c in checks
        ),
        access_blocked_sources=sum(c.get("error_code") in access_codes for c in checks),
    )
