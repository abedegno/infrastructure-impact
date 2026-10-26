"""Shared-period evidence eligibility, never an inferred vendor security ranking.

Latest retained product statements are grouped by initial advisory publication
calendar date. This is not an as-of reconstruction: a CVE may have been added
later. Date-pair offsets describe document metadata, never first disclosure,
notification, exploitation, or verified fix availability.
"""

import json
import re
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache

from jsonschema import Draft202012Validator, FormatChecker

from ..settings import PACKAGE

DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z")
STATUSES = (
    "affected",
    "partially_mitigated",
    "unaffected",
    "fixed",
    "investigating",
    "unknown",
    "recommended",
    "conflicting",
)


def timestamp(value):
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        return None
    parts = [int(v) for v in value[11:19].split(":")]
    if parts[0] > 23 or parts[1] > 59 or parts[2] > 59:
        return None
    if not value.endswith("Z") and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def calendar_date(value):
    if isinstance(value, str) and DATE.fullmatch(value):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    instant = timestamp(value)
    return instant.date() if instant else None


def controls(data, start=None, end=None, products=None):
    as_at = timestamp(data.get("generated_at"))
    if not as_at:
        raise ValueError("Comparison requires a timezone-qualified publication timestamp")
    end = as_at.date().isoformat() if end is None else end
    if not isinstance(end, str) or not DATE.fullmatch(end) or not calendar_date(end):
        raise ValueError("Comparison end must be a valid YYYY-MM-DD date")
    end_date = calendar_date(end)
    start = (end_date - timedelta(days=364)).isoformat() if start is None else start
    if not isinstance(start, str) or not DATE.fullmatch(start) or not calendar_date(start):
        raise ValueError("Comparison start must be a valid YYYY-MM-DD date")
    if not date(1900, 1, 1) <= calendar_date(start) <= end_date <= as_at.date():
        raise ValueError(
            "Comparison period must be ordered, after 1899 and no later than publication"
        )
    products = {} if products is None else products
    if (
        not isinstance(products, dict)
        or len(json.dumps(products, ensure_ascii=False, separators=(",", ":")).encode()) > 4096
    ):
        raise ValueError("Product selection must be an object of at most 4096 UTF-8 bytes")
    for vendor, labels in products.items():
        if vendor not in data["vendors"] or not isinstance(labels, list) or len(labels) > 20:
            raise ValueError("Unknown vendor or invalid product selection")
        available = {
            a["product"]
            for r in data["records"]
            if r["vendor"] == vendor and r.get("document_status") != "draft"
            for a in r["assessments"]
        }
        if any(not isinstance(label, str) or label not in available for label in labels):
            raise ValueError("Product selectors must use exact retained publisher labels")
    return as_at, start, end, {v: sorted(set(labels)) for v, labels in sorted(products.items())}


def eligibility(data, cohort=None, *, start=None, end=None, products=None):
    as_at, start, end, products = controls(data, start, end, products)
    cohort = sorted(set(data.get("all_cves", []) if cohort is None else cohort))
    selected = set(cohort)
    profiles = {v["vendor"]: v for v in data.get("catalogue", {}).get("vendors", [])}
    audits = {v["vendor"]: v for v in data.get("source_audit", {}).get("vendors", [])}
    upstream = data.get("upstream", {})
    vendors = []
    for vendor, name in data["vendors"].items():
        profile, audit = profiles.get(vendor, {}), audits.get(vendor, {})
        available = sorted(
            {
                a["product"]
                for r in data["records"]
                if r["vendor"] == vendor and r.get("document_status") != "draft"
                for a in r["assessments"]
            }
        )
        labels = products.get(vendor, available)
        label_set = set(labels)
        pool = {cid: [] for cid in cohort}
        included = {cid: [] for cid in cohort}
        exclusions = dict(
            draft=0, outside_period=0, unusable_publication_date=0, future_timestamp=0
        )
        advisory_ids = set()
        for record in data["records"]:
            if record["vendor"] != vendor:
                continue
            if record.get("document_status") == "draft":
                if any(
                    a["cve_id"] in selected
                    and (vendor not in products or a["product"] in label_set)
                    for a in record["assessments"]
                ):
                    exclusions["draft"] += 1
                continue
            claims = [
                a
                for a in record["assessments"]
                if a["cve_id"] in selected and a["product"] in label_set
            ]
            if not claims:
                continue
            for claim in claims:
                pool[claim["cve_id"]].append((record, claim))
            published = calendar_date(record.get("published_at"))
            if not published:
                exclusions["unusable_publication_date"] += 1
            elif not start <= published.isoformat() <= end:
                exclusions["outside_period"] += 1
            elif (
                timestamp(record.get("published_at")) and timestamp(record["published_at"]) > as_at
            ):
                exclusions["future_timestamp"] += 1
            else:
                advisory_ids.add(record["advisory_id"])
                for claim in claims:
                    included[claim["cve_id"]].append((record, claim))
        cases = []
        for cid in cohort:
            statements = included[cid]
            claims = [a for _, a in statements]
            reasons = []
            if not statements:
                reasons.append("no_statement_in_period_and_scope")
            if any(not calendar_date(r.get("published_at")) for r, _ in pool[cid]):
                reasons.append("undated_statement_excluded")
            if any(a["status"] == "conflicting" for a in claims):
                reasons.append("conflicting_statement")
            observations = []
            by_document = {
                (r["advisory_id"], r["source_url"]): r
                for r, a in statements
                if a["scope"] == "cve_specific"
            }
            if not by_document:
                reasons.append("no_cve_specific_statement_in_period")
            reference = upstream.get(cid, {})
            upstream_time = timestamp(reference.get("published_at"))
            if not upstream_time or upstream_time > as_at:
                reasons.append("upstream_timestamp_unusable")
            upstream_provenance = bool(
                reference.get("source_url", "").startswith("https://")
                and re.fullmatch(r"[a-f0-9]{64}", reference.get("sha256") or "")
            )
            if not upstream_provenance:
                reasons.append("upstream_provenance_missing")
            for _, record in sorted(by_document.items()):
                published_time = timestamp(record.get("published_at"))
                if not published_time:
                    if "vendor_timestamp_not_precise" not in reasons:
                        reasons.append("vendor_timestamp_not_precise")
                    continue
                vendor_provenance = bool(
                    record.get("source_url", "").startswith("https://")
                    and re.fullmatch(r"[a-f0-9]{64}", record.get("sha256") or "")
                )
                if not vendor_provenance:
                    reasons.append("vendor_provenance_missing")
                if (
                    not upstream_provenance
                    or not vendor_provenance
                    or not upstream_time
                    or upstream_time > as_at
                    or "conflicting_statement" in reasons
                ):
                    continue
                observations.append(
                    dict(
                        advisory_id=record["advisory_id"],
                        advisory_source=record["source_url"],
                        advisory_sha256=record.get("sha256"),
                        advisory_date=record["published_at"],
                        upstream_source=reference.get("source_url"),
                        upstream_sha256=reference.get("sha256"),
                        upstream_date=reference["published_at"],
                        offset_seconds=int(published_time.timestamp())
                        - int(upstream_time.timestamp()),
                    )
                )
            cases.append(
                dict(
                    cve_id=cid,
                    statuses=sorted({a["status"] for a in claims}),
                    explicit_statuses=sorted(
                        {a["status"] for a in claims if a["scope"] == "cve_specific"}
                    ),
                    shared_statuses=sorted(
                        {a["status"] for a in claims if a["scope"] == "bulletin_shared"}
                    ),
                    product_labels=sorted({a["product"] for a in claims}),
                    statement_count=len(claims),
                    publication_observations=observations,
                    timing_reasons=sorted(set(reasons)),
                    first_disclosure_days=None,
                    verified_fix_delay_days=None,
                )
            )
        sources = {s["url"] for s in profile.get("sources", [])}
        checks = {h["source_url"]: h for h in data.get("health", []) if h["vendor"] == vendor}
        stale = sum(
            not timestamp(checks.get(url, {}).get("checked_at"))
            or timestamp(checks[url]["checked_at"]) > as_at
            or (as_at - timestamp(checks[url]["checked_at"])).total_seconds()
            > profile.get("stale_after_hours", 36) * 3600
            for url in sources
        )
        errors = [
            {k: h.get(k) for k in ("source_url", "checked_at", "error_code")}
            for url, h in sorted(checks.items())
            if h["outcome"] == "error"
        ]
        archives = [
            dict(
                source_url=a["source_url"],
                kind=a["kind"],
                pages={
                    state: a.get("pages", {}).get(state, 0)
                    for state in ("pending", "done", "not_applicable", "error")
                },
                documents={
                    state: a.get("documents", {}).get(state, 0)
                    for state in ("pending", "done", "not_applicable", "error")
                },
                known_queue_exhausted=bool(a.get("known_queue_exhausted")),
                discovery_link_gaps=a.get("discovery_link_gaps", 0),
                observed_scopes=a.get("observed_scopes", []),
            )
            for a in audit.get("archives", [])
        ]
        review = audit.get("archive_source_review")
        review = (
            {k: review.get(k) for k in ("status", "source_url", "scope", "configured")}
            if review
            else None
        )
        pending = sum(
            a.get("pages", {}).get("pending", 0) + a.get("documents", {}).get("pending", 0)
            for a in archives
        )
        failed = sum(
            a.get("pages", {}).get("error", 0) + a.get("documents", {}).get("error", 0)
            for a in archives
        )
        counts = dict(
            cohort_size=len(cohort),
            advisories_in_period=len(advisory_ids),
            cves_with_statement=sum(bool(c["statement_count"]) for c in cases),
            no_statement=sum(not c["statement_count"] for c in cases),
            explicit_affected=sum(
                bool({"affected", "partially_mitigated"} & set(c["explicit_statuses"]))
                for c in cases
            ),
            shared_affected=sum(
                bool({"affected", "partially_mitigated"} & set(c["shared_statuses"])) for c in cases
            ),
            explicit_unaffected=sum("unaffected" in c["explicit_statuses"] for c in cases),
            no_cve_specific_exposure_assessment=sum(
                not {"affected", "partially_mitigated", "unaffected"} & set(c["explicit_statuses"])
                for c in cases
            ),
            **{status: sum(status in c["statuses"] for c in cases) for status in STATUSES},
        )
        blockers = [
            "portfolio_denominator_missing",
            "cross_vendor_product_equivalence_unverified",
            "cve_statement_date_unverified",
            "independent_fix_availability_and_linkage_unverified",
        ]
        if pending:
            blockers.append("backfill_pending")
        if failed:
            blockers.append("backfill_failed")
        if not archives:
            blockers.append("no_configured_archive")
        if any(not a.get("known_queue_exhausted") for a in archives):
            blockers.append("archive_scope_incomplete")
        if errors:
            blockers.append("source_errors_retained")
        if stale or not sources:
            blockers.append("source_checks_stale_or_missing")
        if exclusions["unusable_publication_date"]:
            blockers.append("undated_statements_excluded")
        if not labels:
            blockers.append("empty_product_scope")
        vendors.append(
            dict(
                vendor=vendor,
                name=name,
                product_scope=dict(
                    mode="explicit_labels" if vendor in products else "all_retained_labels",
                    labels=labels,
                    declared_families=profile.get("product_families", []),
                ),
                counts=counts,
                excluded_advisories=exclusions,
                eligibility=dict(
                    descriptive_counts_usable=counts["cves_with_statement"] > 0,
                    rate_comparison="suppressed",
                    first_disclosure_comparison="suppressed",
                    fix_timing_comparison="suppressed",
                    reason_codes=sorted(blockers),
                ),
                source_coverage=dict(
                    configured_urls=len(sources),
                    stale_or_unchecked_urls=stale,
                    errors=errors,
                    history_scope=profile.get("history_scope", "Not declared"),
                    known_gaps=profile.get("known_gaps", []),
                    archive_review=review,
                    archives=archives,
                    backfill_pending=pending,
                    backfill_failed=failed,
                    portfolio_completeness="not_established",
                ),
                cases=cases,
            )
        )
    return dict(
        schema_version=1,
        cohort=cohort,
        period=dict(
            start=start, end=end, basis="initial_advisory_publication_calendar_date", inclusive=True
        ),
        product_selection=products,
        vendors=vendors,
        method="Latest retained non-draft product statements grouped by initial advisory publication date. Timezone-qualified timestamps use UTC dates; date-only values keep their calendar date. Missing or timezone-unspecified timestamps are excluded. This is not an as-of reconstruction or a date of individual CVE disclosure.",
        metric_policy=dict(
            sample_counts="qualified_descriptive_evidence",
            vendor_rates="suppressed_without_comparable_portfolio_denominators",
            first_disclosure="suppressed_without_verified_cve_statement_dates_and_history",
            fix_delay="suppressed_without_independent_fix_availability_and_product_cve_linkage",
            publication_offsets="paired_document_metadata_only_not_disclosure_response_time",
        ),
    )


@lru_cache(maxsize=1)
def report_validator():
    schema = json.loads((PACKAGE / "schemas/comparison-eligibility-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())
