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
        "research": {
            k: v for k, v in data.get("research", {}).items() if k != "current_evidence_input"
        },
        "records": [
            {**r, "assessments": [a for a in r["assessments"] if a["cve_id"] in cohort]}
            for r in data["records"]
            if cohort.intersection(r["cves"])
        ],
    }


def csv_export(data, *, _fields=None):
    stream = io.StringIO()
    fields = _fields or FIELDS
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for record in assessment_export(data)["records"]:
        for assessment in record["assessments"]:
            row = {field: assessment.get(field, record.get(field, "")) for field in fields}
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


RETAINED_FIELDS = [
    "record_scope",
    "disposition",
    "reason",
    "reason_text",
    "decision_id",
    "target_key",
    "policy_id",
    "policy_version",
    "policy_fingerprint",
]


def retained_assessment_export(data) -> dict:
    """Explicit excluded-latest export; every assessment carries its decision provenance."""
    from .application.current_evidence import unavailable_report
    from .application.current_views import validate_partition

    report = data.get("current_evidence") or unavailable_report(
        publication=data.get("publication"), generated_at=data["generated_at"]
    )
    if report["availability"] == "available":
        validate_partition(data)
    decisions = {d["decision_id"]: d for d in report["decisions"]}
    records = []
    for wrapper in data.get("retained_advisories", []):
        decision = decisions[wrapper["decision_id"]]
        metadata = {k: decision[k] for k in RETAINED_FIELDS if k != "record_scope"}
        metadata["record_scope"] = wrapper["record_scope"]
        r = wrapper["record"]
        records.append(
            {**r, **metadata, "assessments": [{**a, **metadata} for a in r["assessments"]]}
        )
    return {
        "schema_version": 1,
        "publication": data.get("publication"),
        "generated_at": data["generated_at"],
        "current_evidence": report,
        "record_scope": "retained_latest_excluded",
        "records": records,
    }


def retained_csv_export(data) -> str:
    exported = retained_assessment_export(data)
    return csv_export(
        {
            **exported,
            "kev": data.get("kev"),
            "comparison": {"cohort": sorted({c for r in exported["records"] for c in r["cves"]})},
        },
        _fields=FIELDS + RETAINED_FIELDS,
    )


SWITCHING_FIELDS = [
    "publication_id",
    "publication_generated_at",
    "definition_id",
    "definition_version",
    "definition_sha256",
    "vendor",
    "scope_level",
    "window",
    "period_start",
    "period_end",
    "totals_basis",
    "observed_advisories",
    "affected_advisories",
    "observed_cves",
    "affected_cves",
    "remediation_events",
    "bundled_events",
    "unbundled_publications",
    "draft_advisories",
    "model_unresolved_claims",
    "conditional_cves",
    "conditionality_unclassified_cves",
    "severity_version",
    "severity_provider",
    "severity_origin",
    "severity_preferred",
    "severity_band",
    "severity_count",
    "kev_basis",
    "kev_availability",
    "kev_listed",
    "kev_unknown",
    "coverage_state",
    "coverage_observed_advisories",
    "coverage_expected_advisories",
    "coverage_issues",
    "source_window_states",
]


def switching_csv(report: dict) -> str:
    """Summary facets; repeated observed totals are explicitly nonadditive."""

    def cell(value):
        value = (
            "" if value is None else str(value).lower() if isinstance(value, bool) else str(value)
        )
        if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
            value = "'" + value
        return '"' + value.replace('"', '""') + '"'

    lines = [",".join(SWITCHING_FIELDS)]
    for row in report["rows"]:
        c, k, coverage = row["counts"], row["kev"], row["coverage"]
        issues = sorted(
            {
                issue
                for source in coverage["sources"]
                for issue in source["issues"] + source.get("enumeration", {}).get("gaps", [])
            }
        )
        common = [
            (report["publication"] or {}).get("id"),
            report["generated_at"],
            report["definition"]["id"],
            report["definition"]["version"],
            report["selection"]["definition_sha256"],
            row["vendor"],
            row["scope_level"],
            row["window"],
            row["period_start"],
            row["period_end"],
            "repeated_totals_nonadditive",
            c["advisories"],
            c["affected_advisories"],
            c["cves"],
            c["affected_cves"],
            c["remediation_events"],
            c["bundled_events"],
            c["unbundled_publications"],
            c["draft_advisories"],
            c["model_unresolved_claims"],
            c["conditional_cves"],
            c["conditionality_unclassified_cves"],
        ]
        for facet in row["severity"] or [dict(band="Unknown", count=0)]:
            values = (
                common
                + [
                    facet.get(key)
                    for key in ("version", "provider", "origin", "preferred", "band", "count")
                ]
                + [
                    "documented_affected_cves",
                    k["availability"],
                    k["listed_count"],
                    k["unknown_count"],
                    coverage["state"],
                    coverage["observed_advisories"],
                    coverage["expected_advisories"],
                    ";".join(issues),
                    ";".join(
                        sorted(
                            {
                                source.get("enumeration", {}).get("coverage_state", source["state"])
                                for source in coverage["sources"]
                            }
                        )
                    ),
                ]
            )
            lines.append(",".join(cell(v) for v in values))
    return "\r\n".join(lines)
