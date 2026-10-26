"""Explicit comparable-cohort requirements, without vendor rates or rankings."""

import json

from ..settings import PACKAGE
from .eligibility import calendar_date
from .families import definition, statements


def case_evidence(record, claim, start, end):
    published = calendar_date(record.get("published_at"))
    return dict(
        source_url=record["source_url"],
        source_sha256=record["sha256"],
        observed_at=record.get("source_observed_at"),
        publisher_date_claim=record.get("published_at"),
        period_state="undated_excluded"
        if not published
        else "included"
        if start <= published.isoformat() <= end
        else "outside_period_excluded",
        product=claim["product"],
        platforms=list(claim.get("platforms", [])),
        version_scope=[
            json.dumps(v, sort_keys=True, ensure_ascii=False) for v in claim.get("versions", [])
        ],
        evidence_locator=claim.get("evidence_locator"),
        status=claim["status"],
        scope=claim["scope"],
    )


def readiness(data):
    policy = json.loads((PACKAGE / "resources/comparison-plans.json").read_text())
    catalog = {f["id"]: f for f in definition()["families"]}
    family_rows = {f["id"]: f for f in data["family_completeness"]["families"]}
    cohort = sorted(set(data["benchmark_cohort"]))
    end = calendar_date(data["generated_at"])
    plans = []
    for plan in policy["plans"]:
        rows = []
        for identity in plan["families"]:
            if identity not in family_rows:
                continue
            family = catalog[identity]
            found = statements(data, family)
            included = [
                (r, a)
                for r, a in found
                if calendar_date(r.get("published_at"))
                and policy["period_start"]
                <= calendar_date(r["published_at"]).isoformat()
                <= end.isoformat()
            ]
            cases = []
            for cid in cohort:
                claims = [a for _, a in included if a["cve_id"] == cid]
                explicit = {a["status"] for a in claims if a["scope"] == "cve_specific"}
                # Separate products/ranges may legitimately have affected and unaffected
                # statements; absent reviewed linkage cannot settle equivalence.
                disposition = (
                    "unresolved"
                    if "conflicting" in explicit or {"affected", "unaffected"} <= explicit
                    else "explicit_assessment"
                    if explicit & {"affected", "unaffected", "partially_mitigated"}
                    else "unresolved"
                    if explicit
                    else "shared_only"
                    if claims
                    else "unknown"
                )
                cases.append(
                    dict(
                        cve_id=cid,
                        state=disposition,
                        statuses=sorted({a["status"] for a in claims}),
                        statement_count=len(claims),
                        evidence=[
                            case_evidence(r, a, policy["period_start"], end.isoformat())
                            for r, a in found
                            if a["cve_id"] == cid
                        ][:20],
                        evidence_truncated=sum(a["cve_id"] == cid for _, a in found) > 20,
                    )
                )
            blockers = [
                "family_inventory_denominator_missing",
                "cross_vendor_product_equivalence_unverified",
                "independent_human_review_pending",
                "cohort_not_representative",
            ]
            if any(c["state"] != "explicit_assessment" for c in cases):
                blockers.append("cohort_assessment_gaps")
            if any(not calendar_date(r.get("published_at")) for r, _ in found):
                blockers.append("undated_statements_excluded")
            if family_rows[identity]["vendor_source_errors"]:
                blockers.append("vendor_source_errors")
            if family_rows[identity]["state"] == "unknown":
                blockers.append("family_evidence_missing")
            if any(t["state"] == "unknown" for t in family_rows[identity]["train_references"]):
                blockers.append("selected_train_reference_gaps")
            rows.append(
                dict(
                    family_id=identity,
                    vendor=family["vendor"],
                    name=family["name"],
                    state="blocked",
                    reason_codes=blockers,
                    cases=cases,
                    explicit_cases=sum(c["state"] == "explicit_assessment" for c in cases),
                    unknown_or_unresolved_cases=sum(
                        c["state"] != "explicit_assessment" for c in cases
                    ),
                    undated_statements_excluded=sum(
                        not calendar_date(r.get("published_at")) for r, _ in found
                    ),
                    comparison_rate=None,
                )
            )
        plans.append(
            dict(
                **plan,
                protocol=policy["protocol"],
                state="blocked",
                cohort=cohort,
                period=dict(
                    start=policy["period_start"],
                    end=end.isoformat(),
                    basis="latest_retained_statement_grouped_by_initial_advisory_date_not_as_of_reconstruction",
                ),
                members=rows,
                rate_comparison="suppressed",
                requirements=[
                    dict(
                        code="explicit_cve_specific_assessments",
                        state="met"
                        if rows and all(r["unknown_or_unresolved_cases"] == 0 for r in rows)
                        else "incomplete",
                    ),
                    dict(code="family_inventory_denominators", state="missing"),
                    dict(code="product_and_deployment_equivalence", state="unverified"),
                    dict(code="representative_independent_cohort_design", state="unverified"),
                    dict(code="independent_human_review", state="pending"),
                ],
            )
        )
    return dict(
        schema_version=1,
        plan_version=policy["plan_version"],
        scope="predeclared_reference_cohort",
        cohort_design=policy["cohort_design"],
        plans=plans,
        eligible_comparisons=[],
        method="Descriptive evidence readiness only. Missing, shared, undated and conflicting scope cannot become negative vendor observations. Initial advisory dates are not individual CVE disclosure dates. Status counts are not rates; complete case cells alone cannot establish representative sampling, equivalent deployments, inventories, release availability or independent review. No vendor security ranking is produced.",
    )
