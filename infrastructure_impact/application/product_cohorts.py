"""Explicit product/build research targets; references never become inventories."""

import json
from hashlib import sha256

from jsonschema import Draft202012Validator, FormatChecker

from ..settings import PACKAGE
from ..source_policy import allowed
from .families import definition as family_definition


def fingerprint(value):
    fields = {k: v for k, v in value.items() if k != "definition_sha256"}
    return sha256(
        json.dumps(fields, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def definition(value=None):
    value = (
        value
        if value is not None
        else json.loads((PACKAGE / "resources/product-cohorts.json").read_text())
    )
    schema = json.loads((PACKAGE / "schemas/product-cohort-definition-v1.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    if value["definition_sha256"] != fingerprint(value):
        raise ValueError("Product cohort definition fingerprint mismatch")
    families = {f["id"]: f for f in family_definition()["families"]}
    identities = set()
    cohort_ids = set()
    for cohort in value["cohorts"]:
        if cohort["id"] in cohort_ids:
            raise ValueError("Duplicate cohort identity")
        cohort_ids.add(cohort["id"])
        if cohort["period"]["start"] > cohort["period"]["end"]:
            raise ValueError("Cohort period must be ordered")
        for unit in cohort["units"]:
            if unit["id"] in identities or unit["family_id"] not in families:
                raise ValueError("Duplicate unit or unknown family")
            identities.add(unit["id"])
            vendor = families[unit["family_id"]]["vendor"]
            if any(not allowed(url, vendor) for url in unit["component_sources"]):
                raise ValueError("Cohort sources require the family's official HTTPS policy")
            support = unit["support_window"]
            if support and support["start"] > support["end"]:
                raise ValueError("Support window must be ordered")
    return value


def product_cohorts(data, spec=None):
    spec = definition(spec)
    families = {f["id"]: f for f in family_definition()["families"]}
    sources = data.get("fix_leads", {}).get("sources", [])
    checks = {(c["vendor"], c["source_url"]): c for c in data.get("health", [])}
    cohorts = []
    for cohort in spec["cohorts"]:
        rows = []
        for unit in cohort["units"]:
            family = families[unit["family_id"]]
            vendor = family["vendor"]
            # Exact reviewed source bindings, never vendor-wide or label-prefix joins.
            found = [
                s
                for s in sources
                if s["vendor"] == vendor
                and s["source_url"] in unit["component_sources"]
                and s["analysis_state"] == "scoped"
                and s["components"]
            ]
            evidence = [
                dict(
                    source_url=s["source_url"],
                    source_sha256=s["current_evidence"]["source_sha256"],
                    observed_at=s["current_evidence"]["observed_at"],
                    component_scope=s["component_scope"],
                    components=s["components"],
                    locators=s.get("component_locators", []),
                    latest_retrieval_matches_analyzed_snapshot=s.get(
                        "latest_retrieval_matches_analyzed_snapshot"
                    ),
                )
                for s in found
            ]
            missing = [
                field + "_target_unspecified"
                for field in (
                    "release_train",
                    "firmware_build",
                    "hardware_model",
                    "deployment",
                    "support_window",
                )
                if unit[field] is None
            ]
            if unit["service"]["enabled"] is None:
                missing.append("service_configuration_unspecified")
            if not evidence:
                missing.append("no_bound_component_reference")
            # Even a completely populated target remains a plan. Non-null target
            # fields cannot certify inventory, build variants, lifecycle or review.
            missing += [
                "product_build_inventory_unverified",
                "backports_and_build_variants_unverified",
                "historical_support_and_observation_alignment_unverified",
                "cross_vendor_equivalence_unverified",
                "independent_human_review_pending",
            ]
            source_checks = []
            for url in unit["component_sources"]:
                check = checks.get((vendor, url), {})
                source_checks.append(
                    dict(
                        source_url=url,
                        outcome=check.get("outcome", "not_checked"),
                        checked_at=check.get("checked_at"),
                        error_code=check.get("error_code"),
                    )
                )
            rows.append(
                dict(
                    target=unit,
                    vendor=vendor,
                    name=family["name"],
                    state="blocked",
                    missing_dimensions=missing,
                    component_evidence=evidence,
                    source_checks=source_checks,
                    build_inventory_denominator=None,
                    comparison_rate=None,
                )
            )
        cohorts.append(
            dict(
                id=cohort["id"],
                name=cohort["name"],
                period=cohort["period"],
                units=rows,
                selected_scope_units=len(rows),
                confirmed_build_denominator=None,
                state="blocked",
            )
        )
    coverage = []
    for vendor in sorted(data["vendors"]):
        found = [s for s in sources if s["vendor"] == vendor]
        count = sum(s["analysis_state"] == "scoped" and bool(s["components"]) for s in found)
        coverage.append(
            dict(
                vendor=vendor,
                analyzed_sources=len(found),
                sources_with_component_references=count,
                source_errors=sum(
                    c["vendor"] == vendor and c["outcome"] == "error"
                    for c in data.get("health", [])
                ),
                state="references_only" if count else "no_component_references_retained",
            )
        )
    return dict(
        schema_version=1,
        definition=spec,
        cohorts=cohorts,
        component_source_coverage=coverage,
        independent_human_review_completed=False,
        ranking_supported=False,
        method="Frozen retrospective product-scope plans, separate from CVE enrollment. A selected unit is a research target, not a deployed device, complete vendor portfolio or independent vulnerability event. Exact source bindings supply literal component references only; branch/build/service/support targets do not verify inventory or applicability. Unbound sources remain visible in vendor coverage but cannot fill a different family's unit. Counts describe selected scopes, not exposure denominators. No vendor rate, security ranking, historical exposure or concealment inference is supported.",
    )
