"""A single cohort-selection and CSV contract for HTTP and static exports."""

import csv
import io
import json

from .application.comparison import compare
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


def select(data, cohort=None):
    cohort = sorted(set(cohort if cohort is not None else data["all_cves"]))
    selected = set(cohort)
    return {
        **data,
        "comparison": compare(data["records"], cohort, vendors=data["vendors"]),
        "scorecards": select_scorecards(data.get("scorecards", {}), cohort),
        "timeline": select_timeline(data.get("timeline", {}), cohort),
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
        "delays": [d for d in data["delays"] if d["cve_id"] in selected],
    }


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
