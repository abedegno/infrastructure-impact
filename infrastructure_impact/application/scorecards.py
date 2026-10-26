"""Coverage-aware evidence summaries; no security score or fleet denominator."""

from collections import Counter

from .comparison import parse_date


def empty_case(cid):
    return dict(
        cve_id=cid,
        statuses=[],
        product_labels=[],
        statement_count=0,
        cve_specific_statements=0,
        shared_bulletin_statements=0,
        coverage_state="not_checked",
        source_urls=[],
    )


def summarize_cases(cases):
    return dict(
        cohort_size=len(cases),
        with_statement=sum(bool(c["statement_count"]) for c in cases),
        without_statement=sum(not c["statement_count"] for c in cases),
        explicit_unknown=sum("unknown" in c["statuses"] for c in cases),
        status_counts={
            status: sum(status in c["statuses"] for c in cases)
            for status in (
                "affected",
                "partially_mitigated",
                "unaffected",
                "fixed",
                "investigating",
                "unknown",
                "recommended",
                "conflicting",
            )
        },
    )


def scorecards(records, coverage, catalogue, health, cohort, vendors, at):
    checks = {(h["vendor"], h["source_url"]): h for h in health}
    covered = {(c["vendor"], c["cve_id"]): c for c in coverage}
    profiles = {p["vendor"]: p for p in catalogue.get("vendors", [])}
    at = parse_date(at)
    cards = []
    for vendor, name in vendors.items():
        profile = profiles.get(vendor, {})
        sources = []
        seen = set()
        for source in profile.get("sources", []):
            url = source["url"]
            if url in seen:
                continue
            seen.add(url)
            check = checks.get((vendor, url))
            checked = parse_date(check["checked_at"]) if check else None
            stale = bool(
                checked
                and (at - checked).total_seconds() > profile.get("stale_after_hours", 36) * 3600
            )
            outcome = "not_checked" if not check else check["outcome"]
            sources.append(
                dict(
                    source_url=url,
                    role=source["role"],
                    outcome=outcome,
                    checked_at=check["checked_at"] if check else None,
                    stale=stale,
                    error_code=check.get("error_code") if check else None,
                )
            )
        cases = []
        included = [
            r for r in records if r["vendor"] == vendor and r.get("document_status") != "draft"
        ]
        for cid in sorted(set(cohort)):
            claims = [a for r in included for a in r["assessments"] if a["cve_id"] == cid]
            cases.append(
                dict(
                    cve_id=cid,
                    statuses=sorted({a["status"] for a in claims}),
                    product_labels=sorted({a["product"] for a in claims}),
                    statement_count=len(claims),
                    cve_specific_statements=sum(a["scope"] == "cve_specific" for a in claims),
                    shared_bulletin_statements=sum(a["scope"] == "bulletin_shared" for a in claims),
                    coverage_state=covered.get((vendor, cid), {}).get("state", "not_checked"),
                    source_urls=sorted({r["source_url"] for r in included if cid in r["cves"]}),
                )
            )
        cards.append(
            dict(
                vendor=vendor,
                name=name,
                product_families=profile.get("product_families", []),
                known_gaps=profile.get("known_gaps", []),
                history_scope=profile.get("history_scope", "Not declared"),
                configured_sources=sources,
                additional_source_errors=[
                    {
                        "source_url": h["source_url"],
                        "checked_at": h["checked_at"],
                        "error_code": h.get("error_code"),
                    }
                    for h in health
                    if h["vendor"] == vendor
                    and h["source_url"] not in seen
                    and h["outcome"] == "error"
                ],
                source_outcomes=dict(Counter(s["outcome"] for s in sources)),
                stale_sources=sum(s["stale"] for s in sources),
                cases=cases,
                **summarize_cases(cases),
            )
        )
    return dict(
        schema_version=1,
        cohort=sorted(set(cohort)),
        vendors=cards,
        method="Overlapping distinct-CVE states in a selected cohort. Source health describes configured URLs, not tested product coverage. Draft documents excluded. No vendor security score, installed-base denominator or inferred affectedness.",
    )


def select_scorecards(document, cohort):
    cohort = sorted(set(cohort))
    cards = []
    for card in document.get("vendors", []):
        by_id = {c["cve_id"]: c for c in card["cases"]}
        cases = [by_id.get(cid, empty_case(cid)) for cid in cohort]
        cards.append({**card, "cases": cases, **summarize_cases(cases)})
    return {**document, "cohort": cohort, "vendors": cards}
