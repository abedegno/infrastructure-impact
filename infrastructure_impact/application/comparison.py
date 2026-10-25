"""Cohort-based descriptive counts; not vendor security or disclosure rankings."""

from collections.abc import Mapping
from datetime import datetime, timezone


def compare(records, cohort=None, vendors=None):
    if isinstance(vendors, Mapping):
        names = vendors
    else:
        from ..plugins.registry import default_registry

        names = default_registry().names()
    cohort = sorted(set(cohort if cohort is not None else (c for r in records for c in r["cves"])))
    # Interim advisories contain useful investigation states; drafts alone are excluded.
    excluded = [r for r in records if r.get("document_status") == "draft"]
    records = [r for r in records if r.get("document_status") != "draft"]
    rows = []
    for vendor in vendors if vendors is not None else names:
        claims = [
            a
            for r in records
            if r["vendor"] == vendor
            for a in r["assessments"]
            if a["cve_id"] in cohort
        ]
        by_cve = {cid: [a for a in claims if a["cve_id"] == cid] for cid in cohort}
        assessed = [
            cid
            for cid, aa in by_cve.items()
            if any(a["status"] not in ("unknown", "recommended") for a in aa)
        ]

        def count(status):
            return sum(any(a["status"] == status for a in aa) for aa in by_cve.values())

        rows.append(
            {
                "vendor": vendor,
                "name": names.get(vendor, vendor),
                "cohort_size": len(cohort),
                "has_imported_advisories": any(r["vendor"] == vendor for r in records),
                "assessed_cves": len(assessed),
                "no_assessment_in_dataset": len(cohort) - len(assessed),
                "affected_cves": sum(
                    any(a["status"] in ("affected", "partially_mitigated") for a in aa)
                    for aa in by_cve.values()
                ),
                "unaffected_cves": count("unaffected"),
                "investigating_cves": count("investigating"),
                "fixed_cves": count("fixed"),
                "explicit_affected_cves": sum(
                    any(a["status"] == "affected" and a["scope"] == "cve_specific" for a in aa)
                    for aa in by_cve.values()
                ),
                "shared_bulletin_affected_cves": sum(
                    any(a["status"] == "affected" and a["scope"] == "bulletin_shared" for a in aa)
                    for aa in by_cve.values()
                ),
                "product_labels": len({a["product"] for a in claims}),
                "conflicting_cves": count("conflicting"),
            }
        )
    return {
        "cohort": cohort,
        "vendors": rows,
        "draft_advisories_excluded": len(excluded),
        "method": "Distinct CVEs in this selected cohort with at least one documented product statement. States can overlap across products. Shared-bulletin applicability is labelled separately. No inferred dependency matches are counted.",
        "limitations": [
            "Bounded feed samples and curated historical cases are not a representative vendor population.",
            "No fleet size, installed base, total product portfolio, or tested component denominator is available.",
            "No assessment in this dataset does not mean unaffected, undisclosed, or hidden.",
            "Counts measure observed disclosures and assessments, not underlying vendor security quality.",
        ],
    }


def parse_date(value):
    if not value:
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if "T" in value and d.tzinfo is None:
            return None  # A publisher-local timestamp cannot establish a UTC time difference.
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d
    except (ValueError, AttributeError):
        return None


def advisory_delays(records, upstream):
    from ..plugins.registry import default_registry

    results = []
    for cid, info in upstream.items():
        start = parse_date(info.get("published_at"))
        if not start:
            continue
        for vendor in default_registry().names():
            matches = [
                r
                for r in records
                if r["vendor"] == vendor and cid in r["cves"] and parse_date(r.get("published_at"))
            ]
            if not matches:
                continue
            r = min(matches, key=lambda x: parse_date(x["published_at"]))
            results.append(
                {
                    "vendor": vendor,
                    "cve_id": cid,
                    "days": round(
                        (parse_date(r["published_at"]) - start).total_seconds() / 86400, 2
                    ),
                    "advisory_date": r["published_at"],
                    "upstream_date": info["published_at"],
                    "advisory_source": r["source_url"],
                    "upstream_source": info["source_url"],
                    "meaning": "Earliest dated advisory in this collected sample relative to upstream CVE publication; not proof of vendor notification or first-ever disclosure.",
                }
            )
    return results
