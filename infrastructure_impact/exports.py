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

    if "draft_advisories_count" in data:
        selected["comparison"]["draft_advisories_excluded"] = data["draft_advisories_count"]
        for row in selected["comparison"]["vendors"]:
            row["has_imported_advisories"] = row["vendor"] in data["non_draft_record_vendors"]
    if "research_dossiers" in data:
        selected["research_dossiers"] = select_research_dossiers(
            data["research_dossiers"], cohort, vendor
        )
    return selected


def assessment_export(data):
    cohort = set(data["comparison"]["cohort"])
    return {
        **{k: v for k, v in data.items() if k != "retained_advisories"},
        "research": {
            k: v
            for k, v in data.get("research", {}).items()
            if k not in ("current_evidence_input", "score_input")
        },
        "records": [
            {**r, "assessments": [a for a in r["assessments"] if a["cve_id"] in cohort]}
            for r in data["records"]
            if cohort.intersection(r["cves"])
        ],
    }


def _utf8_cost(value):
    return sum(
        1 if ord(c) < 128 else 2 if ord(c) < 2048 else 3 if ord(c) < 65536 else 4 for c in value
    )


def csv_export(data, *, _fields=None, max_bytes=None):
    fields = _fields or FIELDS
    if max_bytes is not None:
        from .publication_codec import Budget

        budget = Budget(max_bytes)
        for row in _assessment_csv_rows(data, fields, max_bytes):
            budget.charge(len(fields) - 1 + 2, len(fields) - 1 + 2)
            for key in fields:
                value = "" if row[key] is None else str(row[key])
                cost = _utf8_cost(value) + value.count('"')
                if any(c in value for c in ',"\r\n'):
                    cost += 2
                budget.charge(cost, cost)
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=fields)
    for row in _assessment_csv_rows(data, fields, max_bytes):
        writer.writerow(row)
    return stream.getvalue()


def _assessment_csv_rows(data, fields, max_bytes=None):
    yield dict(zip(fields, fields))
    cohort = set(data["comparison"]["cohort"])
    for record in data["records"]:
        if not cohort.intersection(record["cves"]):
            continue
        for assessment in record["assessments"]:
            if assessment["cve_id"] not in cohort:
                continue
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
                    if max_bytes is not None:
                        from .publication_codec import Budget, charge_value

                        charge_value(value, Budget(max_bytes), ascii=False)
                    value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
                if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
                    value = "'" + value
                row[key] = value
            yield row


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


def _csv_cell(value):
    value = "" if value is None else str(value).lower() if isinstance(value, bool) else str(value)
    if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        value = "'" + value
    return '"' + value.replace('"', '""') + '"'


def csv_table(fields, rows, *, max_bytes=None):
    """Render repeatable row mappings using the shared spreadsheet cell policy.

    Reserve the complete UTF-8 output before retaining any serialized lines.
    """
    if max_bytes is not None:
        from .publication_codec import Budget

        budget = Budget(max_bytes)
        size = len(",".join(fields).encode("utf-8"))
        budget.charge(size, size)
        for row in rows():
            budget.charge(2 + len(fields) - 1, 2 + len(fields) - 1)
            for field in fields:
                value = _csv_cell(row.get(field))
                cost = _utf8_cost(value)
                budget.charge(cost, cost)
    return "\r\n".join(
        [
            ",".join(fields),
            *(",".join(_csv_cell(row.get(field)) for field in fields) for row in rows()),
        ]
    )


def switching_csv(report: dict, *, max_bytes=None) -> str:
    """Summary facets; repeated observed totals are explicitly nonadditive."""

    if max_bytes is not None:
        from .publication_codec import Budget

        budget = Budget(max_bytes)
        size = sum(len(field) for field in SWITCHING_FIELDS) + len(SWITCHING_FIELDS) - 1
        budget.charge(size, size)
        for values in _switching_csv_rows(report):
            budget.charge(2 + len(values) - 1, 2 + len(values) - 1)
            for value in values:
                value = (
                    ""
                    if value is None
                    else str(value).lower()
                    if isinstance(value, bool)
                    else str(value)
                )
                cost = 2 + _utf8_cost(value) + value.count('"')
                if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(
                    ("\t", "\r", "\n")
                ):
                    cost += 1
                budget.charge(cost, cost)
    lines = [",".join(SWITCHING_FIELDS)]
    for values in _switching_csv_rows(report):
        lines.append(",".join(_csv_cell(v) for v in values))
    return "\r\n".join(lines)


def _switching_csv_rows(report):
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
            yield values
