"""A single cohort-selection and CSV contract for HTTP and static exports."""

import csv
import io
import json

from .application.casefiles import select_casefiles
from .application.comparison import compare
from .application.eligibility import eligibility
from .application.kev import select_report
from .application.research_dossiers import select_research_dossiers
from .application.scorecards import select_scorecards
from .application.timeline import select_timeline

FIELDS = [
    "cve_id",
    "vendor",
    "advisory_id",
    "product",
    "status",
    "scope",
    "versions",
    "remediations",
    "source_url",
    "observed_at",
    "sha256",
    "kev_status",
    "kev_date_added",
    "kev_due_date",
    "kev_required_action",
    "kev_ransomware_use",
    "kev_forensic_triage",
    "kev_source_url",
    "kev_source_sha256",
    "kev_checked_at",
    "kev_evaluated_at",
    "publication_id",
    "publication_generated_at",
]


def select(
    data,
    cohort=None,
    *,
    start=None,
    end=None,
    products=None,
    group=None,
    vendor=None,
    kev_only=False,
    evaluated_at=None,
):
    cohort = sorted(set(cohort if cohort is not None else data["all_cves"]))
    kev = select_report(data.get("kev"), cohort, kev_only=kev_only, evaluated_at=evaluated_at)
    if data.get("kev") is None:
        kev["publication"] = data.get("publication")
        kev["generated_at"] = data.get("generated_at", kev["generated_at"])
    cohort = kev["selection"]["effective_cve_ids"]
    selected = {
        **data,
        "kev": kev,
        "comparison": compare(data["records"], cohort, vendors=data["vendors"]),
        "comparison_eligibility": eligibility(
            data, cohort, start=start, end=end, products=products, group=group
        )
        if data.get("generated_at")
        else {},
        "scorecards": select_scorecards(data.get("scorecards", {}), cohort),
        "timeline": select_timeline(data.get("timeline", {}), cohort),
        "casefiles": select_casefiles(data.get("casefiles", {}), cohort),
        "coverage": [
            next(
                (p for p in data["coverage"] if p["vendor"] == vendor and p["cve_id"] == cid),
                {
                    "vendor": vendor,
                    "cve_id": cid,
                    "state": "not_checked",
                    "checks": [],
                    "advisory_sources": [],
                },
            )
            for cid in cohort
            for vendor in data["vendors"]
        ],
        "delays": [],
    }

    if "research_dossiers" in data:
        selected["research_dossiers"] = select_research_dossiers(
            data["research_dossiers"], cohort, vendor
        )
    return selected


def assessment_export(data):
    cohort = set(data["comparison"]["cohort"])
    return {
        **data,
        "records": [
            {**r, "assessments": [a for a in r["assessments"] if a["cve_id"] in cohort]}
            for r in data["records"]
            if cohort.intersection(r["cves"])
        ],
    }


def csv_export(data):
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=FIELDS)
    writer.writeheader()
    for record in assessment_export(data)["records"]:
        for assessment in record["assessments"]:
            row = {field: assessment.get(field, record.get(field, "")) for field in FIELDS}
            report = data.get("kev") or {}
            entry = report.get("entries", {}).get(assessment["cve_id"], {})
            row.update(
                kev_status=report.get("selection", {})
                .get("membership", {})
                .get(assessment["cve_id"], "unknown"),
                kev_date_added=entry.get("dateAdded"),
                kev_due_date=entry.get("dueDate"),
                kev_required_action=entry.get("requiredAction"),
                kev_ransomware_use=entry.get("knownRansomwareCampaignUse"),
                kev_forensic_triage=entry.get("forensicTriage"),
                kev_source_url=report.get("source", {}).get("catalogue_url", ""),
                kev_source_sha256=(report.get("catalogue") or {}).get("sha256", ""),
                kev_checked_at=report.get("source", {}).get("checked_at"),
                kev_evaluated_at=report.get("evaluated_at", ""),
                publication_id=(data.get("publication") or {}).get("id", ""),
                publication_generated_at=data.get("generated_at", ""),
            )
            for key, value in row.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
                if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
                    value = "'" + value
                row[key] = value
            writer.writerow(row)
    return stream.getvalue()
