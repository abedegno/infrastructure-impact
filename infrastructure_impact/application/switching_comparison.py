"""Pure descriptive set reducers; retained statements are not deployed exposure."""

import copy
import re
from datetime import date, datetime, timedelta, timezone

from . import kev as kev_reports
from . import switching_evidence as contracts

VENDORS = ("cisco", "aruba", "arista")
SCOPES = ("os_family", "model_qualified")
METHOD = (
    "Distinct observed identities, not prevalence or a security ranking. OS-family and model-qualified "
    "contexts overlap; CVE sets across years and severity facets are nonadditive. Initial publisher "
    "dates determine disclosures; explicit bundles use their own initial dates. Conditional statements "
    "do not establish deployed configuration. General context notes do not establish prerequisites; absent conditionality is unclassified. Scores are provider-reported, not independently rescored. "
    "No timing, fix-delay, causal, equivalence or no-difference inference. Coverage describes source "
    "observation windows, not historical period completeness. The observation-end year is partial."
)


def day(value):
    """Date-only retains its calendar day; zoned timestamps use the UTC day."""
    if value is None:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return date.fromisoformat(value).isoformat()
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("A publication timestamp needs a timezone")
    return parsed.astimezone(timezone.utc).date().isoformat()


def severity_band(version, value):
    if value is None or type(value) not in (int, float) or not 0 <= value <= 10:
        return "Unknown"
    if version not in ("2.0", "3.0", "3.1", "4.0"):
        return "Unknown"
    if version != "2.0" and value == 0:
        return "None"
    if value < 4:
        return "Low"
    if value < 7:
        return "Medium"
    if value < 9 or version == "2.0":
        return "High"
    return "Critical"


def _bounds(definition, end, window):
    start, cutoff = definition["start_date"], definition["cutoff_date"]
    if window == "undated":
        return None, None
    if window == "pre":
        return start, min(end, (date.fromisoformat(cutoff) - timedelta(days=1)).isoformat())
    if window == "post":
        return cutoff, end
    if window == "all":
        return start, end
    if (
        not isinstance(window, str)
        or not re.fullmatch(r"\d{4}", window)
        or not 2021 <= int(window) <= int(end[:4])
    ):
        raise ValueError("Window must be all, pre, post, undated or an observed year >=2021")
    return max(start, window + "-01-01"), min(end, window + "-12-31")


def _in_window(value, start, end, window):
    return (
        (window in ("all", "undated"))
        if value is None
        else window != "undated" and start <= value <= end
    )


def _explicit(c):
    return (
        c["status"] == "affected"
        and c["scope"] == "cve_specific"
        and c["cve_id"] is not None
        and (c["publisher"]["status"] or "").casefold() != "draft"
    )


def _fix(c, r):
    return (
        r["category"] == "vendor_fix"
        and r.get("availability") == "vendor_reports_fixed"
        and (
            (c["product_id"] in r["product_ids"] if c["product_id"] else False)
            or r.get("scope_binding") is not None
        )
    )


def _events(claims):
    events = {}
    for c in claims:
        if not _explicit(c) or not any(_fix(c, r) for r in c["remediations"]):
            continue
        bundle = c["bundle"]
        identity = (
            ("bundle:" + bundle["publisher_id"]) if bundle else ("unbundled:" + c["advisory_id"])
        )
        key = c["vendor"] + ":" + identity
        publication = day(bundle["published_at"] if bundle else c["initial_published_at"])
        e = events.setdefault(
            key,
            dict(
                event_id=key,
                kind="bundle" if bundle else "unbundled",
                publisher_id=bundle["publisher_id"] if bundle else c["advisory_id"],
                dates=set(),
                claim_ids=set(),
                advisory_ids=set(),
                cve_ids=set(),
            ),
        )
        e["dates"].add(publication)
        for field, value in [
            ("claim_ids", c["claim_id"]),
            ("advisory_ids", c["advisory_id"]),
            ("cve_ids", c["cve_id"]),
        ]:
            e[field].add(value)
    result = []
    for e in events.values():
        dates = e.pop("dates")
        # Contradictory initial dates never become two events or choose a favorable period.
        e["published_at"] = next(iter(dates)) if len(dates) == 1 else None
        e["issues"] = (
            ["event_publication_date_conflicting"]
            if len(dates) > 1
            else ["event_publication_date_missing"]
            if None in dates
            else []
        )
        result.append({k: sorted(v) if isinstance(v, set) else v for k, v in e.items()})
    return sorted(result, key=lambda e: e["event_id"])


def _row(report, vendor, scope, window, requested, evaluated):
    start, end = _bounds(report["definition"], report["observation_end"], window)
    family = {t["family"] for t in report["definition"]["targets"] if t["vendor"] == vendor}
    candidates = [
        c
        for c in report["inputs"]["evidence"]["claims"]
        if c["vendor"] == vendor
        and c["family"] in family
        and (scope == "os_family" or c["scope_level"] == "model_qualified")
        and (requested is None or c["cve_id"] in requested)
    ]
    # Initial dates outside the registered observation period are excluded even
    # when an update or later bundle publication falls inside it.
    candidates = [
        c
        for c in candidates
        if day(c["initial_published_at"]) is None
        or report["definition"]["start_date"]
        <= day(c["initial_published_at"])
        <= report["observation_end"]
    ]
    claims = [
        c for c in candidates if _in_window(day(c["initial_published_at"]), start, end, window)
    ]
    active = [c for c in claims if (c["publisher"]["status"] or "").casefold() != "draft"]
    affected = [c for c in active if _explicit(c)]

    def ids(rows, field):
        return sorted({c[field] for c in rows if c[field] is not None})

    events = [e for e in _events(candidates) if _in_window(e["published_at"], start, end, window)]
    facets = {}
    for c in affected:
        for s in c["scores"] or [
            dict(version=None, value=None, provider=None, origin=None, preferred=None)
        ]:
            key = (
                s.get("version"),
                s.get("provider"),
                s.get("origin"),
                s.get("preferred"),
                severity_band(
                    s.get("version"),
                    s.get("value") if s.get("validation") != "incomplete" else None,
                ),
            )
            facets.setdefault(key, set()).add(c["cve_id"])
    severity = [
        dict(
            version=k[0],
            provider=k[1],
            origin=k[2],
            preferred=k[3],
            band=k[4],
            cve_ids=sorted(v),
            count=len(v),
        )
        for k, v in facets.items()
    ]
    severity.sort(key=lambda f: contracts._json(f))
    ratings = {}
    for c in active:
        for rating in c.get("vendor_severity", []):
            key = (rating["rating"], rating["scheme"], rating["namespace"])
            ratings.setdefault(key, set()).add(c["advisory_id"])
    vendor_severity = [
        dict(
            rating=k[0],
            scheme=k[1],
            namespace=k[2],
            scope="advisory",
            advisory_ids=sorted(v),
            count=len(v),
        )
        for k, v in ratings.items()
    ]
    vendor_severity.sort(key=lambda f: contracts._json(f))
    statuses = {}
    for c in active:
        bucket = statuses.setdefault((c["status"], c["scope"]), [])
        bucket.append(c)
    buckets = [
        dict(
            status=k[0],
            scope=k[1],
            claim_ids=ids(v, "claim_id"),
            cve_ids=ids(v, "cve_id"),
            count=len(ids(v, "cve_id")),
        )
        for k, v in sorted(statuses.items())
    ]
    coverage = [c for c in report["inputs"]["evidence"]["coverage"] if c["vendor"] == vendor]
    # These are source-window facts. They cannot establish historical/year totals.
    sources = sorted(coverage, key=lambda c: contracts._json(c))
    affected_ids = ids(affected, "cve_id")
    k = kev_reports.select_report(report["inputs"]["kev"], affected_ids, evaluated_at=evaluated)
    membership = k["selection"]["membership"]
    listed = sorted(cid for cid in affected_ids if membership[cid] == "listed")
    unknown = sorted(cid for cid in affected_ids if membership[cid] == "unknown")
    advisory_ids = ids(active, "advisory_id")
    selected_cves = sorted(
        set(ids(claims, "cve_id")) | {cid for e in events for cid in e["cve_ids"]}
    )
    claim_ids = ids(claims, "claim_id")
    conditional = ids([c for c in affected if c.get("conditional_affected") is True], "cve_id")
    counts = dict(
        advisories=len(advisory_ids),
        cves=len(selected_cves),
        claims=len(claim_ids),
        affected_cves=len(affected_ids),
        conditional_cves=len(conditional),
        conditionality_unclassified_cves=len(
            ids([c for c in affected if c.get("conditional_affected") is None], "cve_id")
        ),
        draft_advisories=len(
            ids(
                [c for c in claims if (c["publisher"]["status"] or "").casefold() == "draft"],
                "advisory_id",
            )
        ),
        remediation_events=len(events),
        bundled_events=sum(e["kind"] == "bundle" for e in events),
        unbundled_publications=sum(e["kind"] == "unbundled" for e in events),
        fixed_only_claims=sum(c["status"] == "fixed" for c in active),
        planned_fix_claims=sum(
            any(r.get("availability") == "planned" for r in c["remediations"]) for c in active
        ),
        workaround_claims=sum(
            any(r["category"] == "workaround" for r in c["remediations"]) for c in active
        ),
        model_unresolved_claims=sum(c["scope_level"] != "model_qualified" for c in active),
    )
    return dict(
        row_id=f"{vendor}:{scope}:{window}",
        vendor=vendor,
        scope_level=scope,
        window=window,
        period_start=start,
        period_end=end,
        date_basis="initial_publisher_date_utc_day",
        event_date_basis="explicit_bundle_initial_else_advisory_initial",
        advisory_ids=advisory_ids,
        cve_ids=selected_cves,
        claim_ids=claim_ids,
        affected_cve_ids=affected_ids,
        conditional_cve_ids=conditional,
        event_ids=[e["event_id"] for e in events],
        events=events,
        counts=counts,
        status_buckets=buckets,
        severity=severity,
        vendor_severity=vendor_severity,
        kev=dict(
            availability=k["source"]["availability"],
            listed_cve_ids=listed,
            unknown_cve_ids=unknown,
            listed_count=len(listed),
            unknown_count=len(unknown),
            denominator=len(affected_ids),
        ),
        coverage=dict(
            state="partial" if sources else "unknown",
            expected_advisories=None,
            observed_advisories=len(advisory_ids),
            basis="retained_source_windows_not_period_completeness",
            sources=sources,
        ),
        denominators=dict(
            affected_cves=len(affected_ids),
            observed_advisories=len(advisory_ids),
            expected_advisories=None,
        ),
        issues=sorted(
            set(
                report["inputs"]["evidence"]["issues"]
                + ["period_coverage_unknown", "sets_nonadditive"]
                + (["model_binding_unresolved"] if counts["model_unresolved_claims"] else [])
            )
        ),
    )


def build_report(
    evidence: dict,
    kev: dict,
    *,
    definition: dict,
    publication: dict | None,
    generated_at: str,
    observation_end: str,
) -> dict:
    contracts.validate_evidence(evidence, publication=publication, generated_at=generated_at)
    contracts._validate_definition(definition)
    if evidence["definition_sha256"] != contracts.definition_sha256(definition):
        raise ValueError("Evidence and comparison definitions differ")
    if (
        day(observation_end) != observation_end
        or observation_end < definition["start_date"]
        or observation_end > day(generated_at)
    ):
        raise ValueError("Observation end must be an observed date on or after study start")
    kev_reports.validate_report(kev)
    if kev["publication"] != publication or kev["generated_at"] != generated_at:
        raise ValueError("KEV and evidence must share their enclosing generation")
    report = dict(
        schema_version=1,
        publication=copy.deepcopy(publication),
        generated_at=generated_at,
        evaluated_at=generated_at,
        availability="available",
        definition=copy.deepcopy(definition),
        observation_end=observation_end,
        selection={},
        rows=[],
        sources=[],
        issues=[],
        method=METHOD,
        inputs=dict(evidence=copy.deepcopy(evidence), kev=copy.deepcopy(kev)),
    )
    return _select_report(report, evaluated_at=generated_at)


def select_report(
    report: dict | None,
    *,
    vendor: str | None = None,
    scope_level: str = "os_family",
    window: str = "all",
    cve_ids: list[str] | None = None,
    evaluated_at: str | None = None,
    publication: dict | None = None,
    generated_at: str | None = None,
) -> dict:
    if isinstance(report, dict) and isinstance(report.get("inputs"), dict):
        contracts.validate_comparison(report)
    return _select_report(
        report,
        vendor=vendor,
        scope_level=scope_level,
        window=window,
        cve_ids=cve_ids,
        evaluated_at=evaluated_at,
        publication=publication,
        generated_at=generated_at,
    )


def _select_report(
    report,
    *,
    vendor=None,
    scope_level="os_family",
    window="all",
    cve_ids=None,
    evaluated_at=None,
    publication=None,
    generated_at=None,
):
    """Recompute from typed immutable inputs, never from already-filtered rows."""
    if vendor is not None and vendor not in VENDORS:
        raise ValueError("Unknown study vendor")
    if scope_level not in SCOPES:
        raise ValueError("Unknown scope level")
    if cve_ids is not None and (
        type(cve_ids) is not list
        or any(not isinstance(c, str) or not kev_reports.CVE.fullmatch(c) for c in cve_ids)
    ):
        raise ValueError("CVE selection must be null or a list of canonical CVE IDs")
    evaluation = evaluated_at or datetime.now(timezone.utc).isoformat()
    kev_reports._timestamp(evaluation)
    available = (
        isinstance(report, dict)
        and report.get("schema_version") == 1
        and isinstance(report.get("inputs"), dict)
    )
    if available:
        result = copy.deepcopy(report)
    else:
        definition = contracts.definition()
        origin = generated_at or (report or {}).get("generated_at") or evaluation
        result = dict(
            schema_version=1,
            publication=copy.deepcopy(
                publication if publication is not None else (report or {}).get("publication")
            ),
            generated_at=origin,
            evaluated_at=evaluation,
            availability="unavailable",
            definition=definition,
            observation_end=day(origin),
            inputs=None,
            rows=[],
            sources=[],
            issues=["comparison_unavailable"],
            method=METHOD,
        )
    _bounds(result["definition"], result["observation_end"], window)
    requested = sorted(set(cve_ids)) if cve_ids is not None else None
    vendors = [vendor] if vendor else list(VENDORS)
    result["evaluated_at"] = evaluation
    result["rows"] = (
        [_row(result, v, scope_level, window, requested, evaluation) for v in vendors]
        if available
        else []
    )
    effective = sorted({cid for row in result["rows"] for cid in row["cve_ids"]})
    result["selection"] = dict(
        requested_vendor=vendor,
        effective_vendors=vendors,
        scope_level=scope_level,
        requested_window=window,
        effective_windows=[r["row_id"] for r in result["rows"]],
        requested_cve_ids=requested,
        effective_cve_ids=effective,
        definition_sha256=contracts.definition_sha256(result["definition"]),
    )
    if available:
        # Full provenance remains in typed inputs; selected row sources are an explicit allowlist.
        used = {i for row in result["rows"] for i in row["claim_ids"]} | {
            i for row in result["rows"] for e in row["events"] for i in e["claim_ids"]
        }
        sources = []

        def collect(node):
            if isinstance(node, dict):
                if set(node) == {"source_url", "source_sha256", "retrieved_at", "source_locator"}:
                    sources.append(node)
                else:
                    for value in node.values():
                        collect(value)
            elif isinstance(node, list):
                for value in node:
                    collect(value)

        for c in result["inputs"]["evidence"]["claims"]:
            if c["claim_id"] in used:
                collect(c)
        result["sources"] = list({contracts.definition_sha256(s): s for s in sources}.values())
        result["sources"].sort(key=contracts._json)
    contracts._validate(result, "switching-comparison-v1.json")
    return result


def validate_semantics(report):
    """Detect tampered derived counts/identities without recursively selecting."""
    selection = report["selection"]
    if report["method"] != METHOD:
        raise ValueError("Comparison method does not match this reducer")
    if (
        not report["definition"]["start_date"]
        <= report["observation_end"]
        <= day(report["generated_at"])
    ):
        raise ValueError("Comparison observation end is outside its generation")
    _bounds(report["definition"], report["observation_end"], selection["requested_window"])
    requested = selection["requested_cve_ids"]
    if requested is not None and requested != sorted(set(requested)):
        raise ValueError("Requested CVEs must be sorted and unique")
    if selection["effective_vendors"] != (
        [selection["requested_vendor"]] if selection["requested_vendor"] else list(VENDORS)
    ):
        raise ValueError("Effective vendors differ from requested scope")
    if selection["definition_sha256"] != contracts.definition_sha256(report["definition"]):
        raise ValueError("Selection definition differs")
    if report["availability"] == "unavailable":
        if (
            report["inputs"] is not None
            or report["rows"]
            or report["sources"]
            or selection["effective_windows"]
            or selection["effective_cve_ids"]
        ):
            raise ValueError("Unavailable reports cannot synthesize observations")
        return
    inputs = report["inputs"]
    contracts.validate_evidence(
        inputs["evidence"], publication=report["publication"], generated_at=report["generated_at"]
    )
    if inputs["evidence"]["definition_sha256"] != selection["definition_sha256"]:
        raise ValueError("Evidence and selection definitions differ")
    kev_reports.validate_report(inputs["kev"])
    if (
        inputs["kev"]["publication"] != report["publication"]
        or inputs["kev"]["generated_at"] != report["generated_at"]
    ):
        raise ValueError("Comparison inputs have different generations")
    expected = [
        _row(
            report,
            v,
            selection["scope_level"],
            selection["requested_window"],
            selection["requested_cve_ids"],
            report["evaluated_at"],
        )
        for v in selection["effective_vendors"]
    ]
    if (
        report["rows"] != expected
        or selection["effective_windows"] != [r["row_id"] for r in expected]
        or selection["effective_cve_ids"] != sorted({cid for r in expected for cid in r["cve_ids"]})
    ):
        raise ValueError("Comparison derived identities/counts disagree with retained inputs")
