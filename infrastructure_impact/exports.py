"""A single cohort-selection and CSV contract for HTTP and static exports."""

import csv
import io
import json

from .application.casefiles import select_casefiles
from .application.comparison import compare
from .application.eligibility import eligibility
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
]


def select(data, cohort=None, *, start=None, end=None, products=None, group=None, vendor=None):
    cohort = sorted(set(cohort if cohort is not None else data["all_cves"]))
    selected = {
        **data,
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
            for key, value in row.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value)
                if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
                    value = "'" + value
                row[key] = value
            writer.writerow(row)
    return stream.getvalue()
