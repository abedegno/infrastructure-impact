"""Purposive cross-component benchmark. Missing evidence is never unaffectedness."""

import json

from ..settings import PACKAGE

COHORT = json.loads((PACKAGE / "resources/benchmark-cohort.json").read_text())


def coverage(db, records, cohort=None):
    from ..storage.repository import VENDORS

    return coverage_from_checks(
        records,
        [dict(r) for r in db.execute("SELECT * FROM coverage_checks")],
        cohort=cohort if cohort is not None else COHORT,
        vendors=VENDORS,
    )


def coverage_from_checks(records, checks, *, cohort, vendors):
    """Recompute claim-derived coverage using independent retained check facts."""
    ids = sorted(cohort)
    facts = checks
    # Index checks are persisted separately from advisory/product assessments.
    result = []
    for vendor in vendors:
        for cid in ids:
            matches = [r for r in records if r["vendor"] == vendor and cid in r["cves"]]
            checks = [c for c in facts if c["vendor"] == vendor and c["cve_id"] == cid]
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
