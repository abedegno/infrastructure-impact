"""Purposive cross-component benchmark. Missing evidence is never unaffectedness."""

COHORT = {
    "CVE-2021-44228": "Log4j",
    "CVE-2022-3602": "OpenSSL",
    "CVE-2022-3786": "OpenSSL",
    "CVE-2023-48795": "OpenSSH",
    "CVE-2024-6387": "OpenSSH",
    "CVE-2023-38545": "curl",
    "CVE-2023-38546": "curl",
    "CVE-2022-0847": "Linux",
    "CVE-2024-1086": "Linux",
    "CVE-2026-109618": "PHP",
    "CVE-2026-109619": "PHP",
}


def coverage(db, records, cohort=None):
    from ..storage.repository import VENDORS

    ids = sorted(cohort if cohort is not None else COHORT)
    # Index checks are persisted separately from advisory/product assessments.
    result = []
    for vendor in VENDORS:
        for cid in ids:
            matches = [r for r in records if r["vendor"] == vendor and cid in r["cves"]]
            checks = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM coverage_checks WHERE vendor=? AND cve_id=?", (vendor, cid)
                )
            ]
            claims = [
                a
                for r in matches
                if r.get("document_status") != "draft"
                for a in r["assessments"]
                if a["cve_id"] == cid
            ]
            status = (
                "assessment_available"
                if any(a["status"] not in ("unknown", "recommended") for a in claims)
                else "advisory_located_no_resolved_assessment"
                if matches
                else "advisory_reference_located"
                if any(c["outcome"] == "match" for c in checks)
                else "index_checked_no_match"
                if any(c["outcome"] == "no_match" for c in checks)
                else "source_unavailable"
                if checks
                else "not_checked"
            )
            result.append(
                {
                    "vendor": vendor,
                    "cve_id": cid,
                    "component": COHORT.get(cid),
                    "state": status,
                    "advisory_sources": sorted({r["source_url"] for r in matches}),
                    "checks": checks,
                }
            )
    return result
