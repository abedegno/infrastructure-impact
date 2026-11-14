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


class _Construction:
    """Per-selection allocation allowance, separate from exact final output cost.

    Reference-only candidate lists charge their slots, not copies of full claim
    facts. Newly constructed memberships and containers charge before growth.
    Repeated temporary structures make this allowance conservative.
    """

    def __init__(self, budget=None):
        self.budget = budget

    def value(self, value):
        if self.budget is not None:
            from ..publication_codec import charge_value

            if isinstance(value, ReducerClaim):
                self.budget.charge(1, 1)
            elif isinstance(value, set):
                self.budget.charge(2 + max(0, len(value) - 1), 2 + max(0, len(value) - 1))
                for item in value:
                    self.value(item)
            else:
                charge_value(value, self.budget)

    def text(self, parts):
        if self.budget is not None:
            from ..publication_codec import string_cost

            self.budget.charge(
                2 + sum(string_cost(p) - 2 for p in parts),
                2 + sum(string_cost(p, True) - 2 for p in parts),
            )
        return "".join(parts)

    def array(self, values):
        if self.budget is not None:
            self.budget.charge(2, 2)
        result = []
        for value in values:
            if self.budget is not None:
                self.budget.charge(bool(result), bool(result))
            self.value(value)
            result.append(value)
        return result

    def unique(self, values):
        result = set()
        for value in values:
            if value not in result:
                self.value(value)
                result.add(value)
        return result

    def object(self, pairs):
        from ..publication_codec import string_cost

        if self.budget is not None:
            self.budget.charge(2, 2)
        result = {}
        for key, value in pairs:
            if self.budget is not None:
                self.budget.charge(
                    string_cost(key) + 1 + bool(result), string_cost(key, True) + 1 + bool(result)
                )
            self.value(value)
            result[key] = value
        return result


def _events(claims, build=None):
    build = build or _Construction()
    events = {}
    for c in claims:
        if not _explicit(c) or not any(_fix(c, r) for r in c["remediations"]):
            continue
        bundle = c["bundle"]
        identity = (
            build.text(("bundle:", bundle["publisher_id"]))
            if bundle
            else build.text(("unbundled:", c["advisory_id"]))
        )
        key = build.text((c["vendor"], ":", identity))
        publication = day(bundle["published_at"] if bundle else c["initial_published_at"])
        if key not in events:
            build.value(key)
            events[key] = build.object(
                (
                    ("event_id", key),
                    ("kind", "bundle" if bundle else "unbundled"),
                    ("publisher_id", bundle["publisher_id"] if bundle else c["advisory_id"]),
                    ("dates", set()),
                    ("claim_ids", set()),
                    ("advisory_ids", set()),
                    ("cve_ids", set()),
                )
            )
        e = events[key]
        if publication not in e["dates"]:
            build.value(publication)
            e["dates"].add(publication)
        for field, value in [
            ("claim_ids", c["claim_id"]),
            ("advisory_ids", c["advisory_id"]),
            ("cve_ids", c["cve_id"]),
        ]:
            if value not in e[field]:
                build.value(value)
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
        result.append(
            build.object((k, sorted(v) if isinstance(v, set) else v) for k, v in e.items())
        )
    return sorted(result, key=lambda e: e["event_id"])


def _row(report, vendor, scope, window, requested, evaluated, *, build=None):
    build = build or _Construction()
    start, end = _bounds(report["definition"], report["observation_end"], window)
    family = build.unique(
        (t["family"] for t in report["definition"]["targets"] if t["vendor"] == vendor)
    )
    candidates = build.array(
        (
            c
            for c in report["inputs"]["evidence"]["claims"]
            if c["vendor"] == vendor
            and c["family"] in family
            and (scope == "os_family" or c["scope_level"] == "model_qualified")
            and (requested is None or c["cve_id"] in requested)
        )
    )
    # Initial dates outside the registered observation period are excluded even
    # when an update or later bundle publication falls inside it.
    candidates = build.array(
        (
            c
            for c in candidates
            if day(c["initial_published_at"]) is None
            or report["definition"]["start_date"]
            <= day(c["initial_published_at"])
            <= report["observation_end"]
        )
    )
    claims = build.array(
        (c for c in candidates if _in_window(day(c["initial_published_at"]), start, end, window))
    )
    active = build.array(
        (c for c in claims if (c["publisher"]["status"] or "").casefold() != "draft")
    )
    affected = build.array((c for c in active if _explicit(c)))

    def ids(rows, field):
        return sorted(build.unique((c[field] for c in rows if c[field] is not None)))

    events = build.array(
        (e for e in _events(candidates, build) if _in_window(e["published_at"], start, end, window))
    )
    facets = {}
    for c in affected:
        # Retained unresolved/shared context is inspectable evidence, not a
        # score attribution. Only the explicit matching CVE may supply a facet.
        scores = build.array(
            (s for s in c["scores"] if s["scope"] == "cve_specific" and s["cve_id"] == c["cve_id"])
        )
        for s in scores or [
            build.object(
                (
                    ("version", None),
                    ("value", None),
                    ("provider", None),
                    ("origin", None),
                    ("preferred", None),
                )
            )
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
            if key not in facets:
                build.value(key)
                build.value([])
                facets[key] = set()
            values = facets[key]
            if c["cve_id"] not in values:
                build.value(c["cve_id"])
                values.add(c["cve_id"])
    severity = build.array(
        (
            build.object(
                (
                    ("version", k[0]),
                    ("provider", k[1]),
                    ("origin", k[2]),
                    ("preferred", k[3]),
                    ("band", k[4]),
                    ("cve_ids", sorted(v)),
                    ("count", len(v)),
                )
            )
            for k, v in facets.items()
        )
    )
    severity.sort(key=lambda f: contracts._json(f))
    ratings = {}
    for c in active:
        for rating in c.get("vendor_severity", []):
            key = (rating["rating"], rating["scheme"], rating["namespace"])
            if key not in ratings:
                build.value(key)
                build.value([])
                ratings[key] = set()
            values = ratings[key]
            if c["advisory_id"] not in values:
                build.value(c["advisory_id"])
                values.add(c["advisory_id"])
    vendor_severity = build.array(
        (
            build.object(
                (
                    ("rating", k[0]),
                    ("scheme", k[1]),
                    ("namespace", k[2]),
                    ("scope", "advisory"),
                    ("advisory_ids", sorted(v)),
                    ("count", len(v)),
                )
            )
            for k, v in ratings.items()
        )
    )
    vendor_severity.sort(key=lambda f: contracts._json(f))
    statuses = {}
    for c in active:
        key = (c["status"], c["scope"])
        if key not in statuses:
            build.value(key)
            build.value([])
            statuses[key] = []
        bucket = statuses[key]
        build.value(c)
        bucket.append(c)
    buckets = build.array(
        (
            build.object(
                (
                    ("status", k[0]),
                    ("scope", k[1]),
                    ("claim_ids", ids(v, "claim_id")),
                    ("cve_ids", ids(v, "cve_id")),
                    ("count", len(ids(v, "cve_id"))),
                )
            )
            for k, v in sorted(statuses.items())
        )
    )
    coverage = build.array(
        (c for c in report["inputs"]["evidence"]["coverage"] if c["vendor"] == vendor)
    )
    # These are source-window facts. They cannot establish historical/year totals.
    sources = sorted(coverage, key=lambda c: contracts._json(c))
    affected_ids = ids(affected, "cve_id")
    # The shared KEV reducer isolates its immutable report with deepcopy.
    # Reserve that copy and the selected membership expansion before calling it.
    build.value(report["inputs"]["kev"])
    if build.budget is not None:
        for cid in affected_ids:
            build.value(cid)
            build.budget.charge(32, 32)
    k = kev_reports.select_report(report["inputs"]["kev"], affected_ids, evaluated_at=evaluated)
    membership = k["selection"]["membership"]
    listed = sorted(cid for cid in affected_ids if membership[cid] == "listed")
    unknown = sorted(cid for cid in affected_ids if membership[cid] == "unknown")
    advisory_ids = ids(active, "advisory_id")
    selected_cves = sorted(
        set(ids(claims, "cve_id")) | build.unique((cid for e in events for cid in e["cve_ids"]))
    )
    claim_ids = ids(claims, "claim_id")
    conditional = ids(
        build.array((c for c in affected if c.get("conditional_affected") is True)), "cve_id"
    )
    counts = build.object(
        (
            ("advisories", len(advisory_ids)),
            ("affected_advisories", len(ids(affected, "advisory_id"))),
            ("cves", len(selected_cves)),
            ("claims", len(claim_ids)),
            ("affected_cves", len(affected_ids)),
            ("conditional_cves", len(conditional)),
            (
                "conditionality_unclassified_cves",
                len(
                    ids(
                        build.array((c for c in affected if c.get("conditional_affected") is None)),
                        "cve_id",
                    )
                ),
            ),
            (
                "draft_advisories",
                len(
                    ids(
                        build.array(
                            (
                                c
                                for c in claims
                                if (c["publisher"]["status"] or "").casefold() == "draft"
                            )
                        ),
                        "advisory_id",
                    )
                ),
            ),
            ("remediation_events", len(events)),
            ("bundled_events", sum((e["kind"] == "bundle" for e in events))),
            ("unbundled_publications", sum((e["kind"] == "unbundled" for e in events))),
            ("fixed_only_claims", sum((c["status"] == "fixed" for c in active))),
            (
                "planned_fix_claims",
                sum(
                    (
                        any((r.get("availability") == "planned" for r in c["remediations"]))
                        for c in active
                    )
                ),
            ),
            (
                "workaround_claims",
                sum(
                    (
                        any((r["category"] == "workaround" for r in c["remediations"]))
                        for c in active
                    )
                ),
            ),
            (
                "model_unresolved_claims",
                sum((c["scope_level"] != "model_qualified" for c in active)),
            ),
        )
    )
    return build.object(
        (
            ("row_id", f"{vendor}:{scope}:{window}"),
            ("vendor", vendor),
            ("scope_level", scope),
            ("window", window),
            ("period_start", start),
            ("period_end", end),
            ("date_basis", "initial_publisher_date_utc_day"),
            ("event_date_basis", "explicit_bundle_initial_else_advisory_initial"),
            ("advisory_ids", advisory_ids),
            ("affected_advisory_ids", ids(affected, "advisory_id")),
            ("cve_ids", selected_cves),
            ("claim_ids", claim_ids),
            ("affected_cve_ids", affected_ids),
            ("conditional_cve_ids", conditional),
            ("event_ids", build.array((e["event_id"] for e in events))),
            ("events", events),
            ("counts", counts),
            ("status_buckets", buckets),
            ("severity", severity),
            ("vendor_severity", vendor_severity),
            (
                "kev",
                build.object(
                    (
                        ("availability", k["source"]["availability"]),
                        ("listed_cve_ids", listed),
                        ("unknown_cve_ids", unknown),
                        ("listed_count", len(listed)),
                        ("unknown_count", len(unknown)),
                        ("denominator", len(affected_ids)),
                    )
                ),
            ),
            (
                "coverage",
                build.object(
                    (
                        ("state", "partial" if sources else "unknown"),
                        ("expected_advisories", None),
                        ("observed_advisories", len(advisory_ids)),
                        ("basis", "retained_source_windows_not_period_completeness"),
                        ("sources", sources),
                    )
                ),
            ),
            (
                "denominators",
                build.object(
                    (
                        ("affected_cves", len(affected_ids)),
                        ("observed_advisories", len(advisory_ids)),
                        ("expected_advisories", None),
                    )
                ),
            ),
            (
                "issues",
                sorted(
                    set(
                        report["inputs"]["evidence"]["issues"]
                        + ["period_coverage_unknown", "sets_nonadditive"]
                        + (
                            ["model_binding_unresolved"]
                            if counts["model_unresolved_claims"]
                            else []
                        )
                    )
                ),
            ),
        )
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
    return _build_report(
        evidence,
        kev,
        definition=definition,
        publication=publication,
        generated_at=generated_at,
        observation_end=observation_end,
    )


def _project_comparison(inputs, kev, *, definition, publication, generated_at, observation_end):
    evidence, report, _ = _project_comparison_with_proof(
        inputs,
        kev,
        definition=definition,
        publication=publication,
        generated_at=generated_at,
        observation_end=observation_end,
    )
    return evidence, report


def _project_comparison_with_proof(
    inputs, kev, *, definition, publication, generated_at, observation_end
):
    """V2-only fresh projection/build composition; no proof crosses invocations."""
    evidence, proof = contracts._project_with_proof(
        inputs, publication=publication, generated_at=generated_at
    )
    result = _build_report(
        evidence,
        kev,
        definition=definition,
        publication=publication,
        generated_at=generated_at,
        observation_end=observation_end,
        evidence_proof=proof,
    )
    proof.require(evidence, publication=publication, generated_at=generated_at)
    return evidence, result, proof


def _build_report(
    evidence: dict,
    kev: dict,
    *,
    definition: dict,
    publication: dict | None,
    generated_at: str,
    observation_end: str,
    evidence_proof=None,
) -> dict:
    contracts._require_evidence(
        evidence,
        publication=publication,
        generated_at=generated_at,
        evidence_proof=evidence_proof,
    )
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
    validated_inputs_json = (
        contracts._json(dict(evidence=evidence, kev=kev)) if evidence_proof is not None else None
    )
    report = dict(
        schema_version=1,
        publication=publication,
        generated_at=generated_at,
        evaluated_at=generated_at,
        availability="available",
        definition=definition,
        observation_end=observation_end,
        selection={},
        rows=[],
        sources=[],
        issues=[],
        method=METHOD,
        # Isolate the small generation snapshots before the whole-report copy:
        # deepcopy otherwise preserves caller aliases between publications.
        inputs=dict(
            evidence={**evidence, "publication": copy.deepcopy(evidence["publication"])},
            kev={**kev, "publication": copy.deepcopy(kev["publication"])},
        ),
    )
    # _select_report makes the sole isolated copy before constructing output.
    return _select_report(
        report,
        evaluated_at=generated_at,
        validated_inputs_json=validated_inputs_json,
    )


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
    validated_inputs_json = None
    if isinstance(report, dict) and (
        isinstance(report.get("inputs"), dict)
        or report.get("schema_version") == 1
        and "availability" in report
    ):
        contracts.validate_comparison(report)
        if report["inputs"] is not None:
            # Call-local value proof: never reuse a previous call's validation.
            validated_inputs_json = contracts._json(report["inputs"])
    return _select_report(
        report,
        vendor=vendor,
        scope_level=scope_level,
        window=window,
        cve_ids=cve_ids,
        evaluated_at=evaluated_at,
        publication=publication,
        generated_at=generated_at,
        validated_inputs_json=validated_inputs_json,
    )


def _select_summaries(report, selections, *, evaluated_at):
    """Eager native v2 batch with one fresh, complete source validation."""
    contracts.validate_comparison(report)
    source_proof = contracts._fingerprint(report)
    results = []
    for options in selections:
        if contracts._fingerprint(report) != source_proof:
            raise ValueError("Native comparison source changed while selecting")
        selected = _select_summary(report, **options, evaluated_at=evaluated_at)
        if contracts._fingerprint(report) != source_proof:
            raise ValueError("Native comparison source changed while selecting")
        results.append(selected)
    return results


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
    validated_inputs_json=None,
):
    """Recompute from typed immutable inputs, never from already-filtered rows."""
    evaluation = _selection_evaluation(vendor, scope_level, cve_ids, evaluated_at)
    available = (
        isinstance(report, dict)
        and report.get("schema_version") == 1
        and isinstance(report.get("inputs"), dict)
    )
    if available:
        result = copy.deepcopy(report)
    else:
        result = _unavailable_selection(report, evaluation, publication, generated_at)
    _populate_selection(result, vendor, scope_level, window, cve_ids, evaluation)
    _validate_selection_output(result, validated_inputs_json)
    return result


def _unavailable_selection(report, evaluation, publication=None, generated_at=None):
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
    return result


def _selection_evaluation(vendor, scope_level, cve_ids, evaluated_at):
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
    return evaluation


def _select_summary(
    report, *, vendor=None, scope_level="os_family", window="all", cve_ids=None, evaluated_at=None
):
    """Select only an isolated summary inside the eager, source-guarded native batch.

    The batch freshly validates the complete source. Borrow its inputs only for
    synchronous reduction; summary() copies every returned field independently.
    No borrowed input or source reference can escape this helper.
    """
    evaluation = _selection_evaluation(vendor, scope_level, cve_ids, evaluated_at)
    if isinstance(report["inputs"], dict):
        result = {k: v for k, v in report.items() if k not in ("rows", "sources", "selection")}
        result.update(rows=[], sources=[])
    else:
        result = _unavailable_selection(report, evaluation)
    _populate_selection(result, vendor, scope_level, window, cve_ids, evaluation)
    return summary(result)


def _populate_selection(result, vendor, scope_level, window, cve_ids, evaluation):
    """Shared options, bounds, rows, identities and provenance for both outputs."""
    available = isinstance(result.get("inputs"), dict)
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
        result["sources"] = _selected_sources(result["inputs"]["evidence"], result["rows"])


def _validate_selection_output(result, validated_inputs_json):
    """Compose full input validation with validation of every generated field.

    Public selection proves inputs through fresh full comparison validation.
    The private v2 builder proves them through fresh evidence and KEV validation
    plus definition/context checks; its proof predates every isolation copy.
    Other callers retain full output validation. The byte comparison is type-aware
    (unlike Python equality, where True == 1) and also rejects any deepcopy/reducer
    mutation. The nullable proxy is only for checking the other fields against
    the original schema; the returned report keeps its complete isolated inputs.
    """
    if validated_inputs_json is None:
        contracts._validate(result, "switching-comparison-v1.json")
        return
    if contracts._json(result["inputs"]) != validated_inputs_json:
        raise ValueError("Retained comparison inputs changed while selecting")
    contracts._validate({**result, "inputs": None}, "switching-comparison-v1.json")


def _selected_sources(evidence, rows, *, build=None):
    """Exact nested provenance; deduplicate before growing the selected collection."""
    build = build or _Construction()
    used = build.unique(i for row in rows for i in row["claim_ids"])
    for row in rows:
        for event in row["events"]:
            for identity in event["claim_ids"]:
                if identity not in used:
                    build.value(identity)
                    used.add(identity)
    sources = {}

    def retain(source):
        if set(source) != set(contracts._SOURCE_FIELDS) or any(
            type(source[field]) is not str for field in contracts._SOURCE_FIELDS
        ):
            raise ValueError("Expected a closed four-string Source")
        key = tuple(source[field] for field in contracts._SOURCE_FIELDS)
        if key not in sources:
            identity = contracts.definition_sha256(source)
            build.value(identity)
            build.value(source)
            sources[key] = source

    def collect(node):
        if isinstance(node, dict):
            if set(node) == {"source_url", "source_sha256", "retrieved_at", "source_locator"}:
                retain(node)
            else:
                for value in node.values():
                    collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)

    for claim in evidence["claims"]:
        if claim["claim_id"] in used:
            if isinstance(claim, ReducerClaim):
                for source in claim.sources:
                    retain(source)
            else:
                collect(claim)
    return sorted(sources.values(), key=contracts._json)


def validate_semantics(report):
    """Detect tampered derived counts/identities without recursively selecting."""
    return _validate_semantics(report)


def _validate_semantics(report, *, evidence_proof=None):
    """Detect tampered derived counts/identities without recursively selecting."""
    if evidence_proof is not None and type(evidence_proof) is not contracts._ValidatedEvidence:
        raise TypeError("Expected a fresh validated evidence capability")
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
        if evidence_proof is not None:
            raise ValueError("Evidence capability requires complete comparison inputs")
        return
    inputs = report["inputs"]
    if inputs is None:
        raise ValueError("Available comparison requires complete immutable inputs")
    if evidence_proof is None:
        contracts._validate_evidence_semantics(
            inputs["evidence"],
            publication=report["publication"],
            generated_at=report["generated_at"],
        )
    else:
        contracts._require_evidence(
            inputs["evidence"],
            publication=report["publication"],
            generated_at=report["generated_at"],
            evidence_proof=evidence_proof,
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

    if report["sources"] != _selected_sources(inputs["evidence"], expected):
        raise ValueError("Selected source provenance differs from contributing claims")


def summary(report):
    """Explicit non-hydratable summary; never a malformed full report."""
    result = {k: copy.deepcopy(v) for k, v in report.items() if k != "inputs"}
    result["representation"] = "summary"
    contracts._validate(result, "switching-summary-v1.json")
    return result


def query_options(query, observation_end):
    """Validate the independent public query; omission means full study."""
    if set(query) - {"vendor", "scope", "window", "cves", "format"} or any(
        len(v) != 1 or not v[0] for v in query.values()
    ):
        raise ValueError("Unknown, duplicate or blank study parameter")
    values = {k: v[0] for k, v in query.items()}
    vendor = values.get("vendor")
    scope = values.get("scope", "os_family")
    window = values.get("window", "all")
    if vendor is not None and vendor not in VENDORS or scope not in SCOPES:
        raise ValueError("Invalid study scope")
    _bounds(contracts.definition(), observation_end, window)
    ids = values["cves"].split(",") if "cves" in values else None
    if ids is not None and (
        len(ids) != len(set(ids)) or any(not kev_reports.CVE.fullmatch(c) for c in ids)
    ):
        raise ValueError("Invalid canonical CVE selection")
    output = values.get("format", "json")
    if output not in ("json", "csv"):
        raise ValueError("Invalid study format")
    return dict(vendor=vendor, scope_level=scope, window=window, cve_ids=ids), output


class ReducerClaim:
    """Private facts needed by the shared row reducer; never a v1 claim DTO.

    Construct only after full claim shape, identity and source validation. Every
    nested source is retained separately, including sources in unused context.
    """

    __slots__ = ("fields", "sources")

    def __init__(self, fields, sources):
        self.fields, self.sources = fields, sources

    @classmethod
    def from_validated(cls, claim, *, budget=None):
        from ..publication_codec import Budget, charge_value, string_cost

        budget = budget if budget is not None else Budget(128_000_000)
        # [fields, sources], including the sources array. Charge before growth.
        budget.charge(5, 5)
        sources = []

        def pick(node, keys):
            present = tuple(k for k in keys if k in node)
            budget.charge(2 + max(0, len(present) - 1), 2 + max(0, len(present) - 1))
            for key in present:
                budget.charge(string_cost(key) + 1, string_cost(key, True) + 1)
                charge_value(node[key], budget)
            return {k: node[k] for k in present}

        def property_key(key):
            budget.charge(string_cost(key) + 2, string_cost(key, True) + 2)

        def visit(node):
            if isinstance(node, dict):
                if set(node) == {"source_url", "source_sha256", "retrieved_at", "source_locator"}:
                    budget.charge(bool(sources), bool(sources))
                    charge_value(node, budget)
                    sources.append(node)
                else:
                    for value in node.values():
                        visit(value)
            elif isinstance(node, list):
                for value in node:
                    visit(value)

        visit(claim)
        fields = pick(
            claim,
            (
                "claim_id",
                "vendor",
                "advisory_id",
                "cve_id",
                "product_id",
                "family",
                "scope_level",
                "status",
                "scope",
                "initial_published_at",
                "conditional_affected",
            ),
        )
        property_key("publisher")
        fields["publisher"] = pick(claim["publisher"], ("status",))
        property_key("bundle")
        if claim["bundle"] is None:
            budget.charge(4, 4)
            fields["bundle"] = None
        else:
            fields["bundle"] = pick(claim["bundle"], ("publisher_id", "published_at"))
        for name, keys in [
            ("remediations", ("category", "availability", "product_ids", "scope_binding")),
            (
                "scores",
                (
                    "scope",
                    "cve_id",
                    "version",
                    "value",
                    "provider",
                    "origin",
                    "preferred",
                    "validation",
                ),
            ),
            ("vendor_severity", ("rating", "scheme", "namespace")),
        ]:
            if name in claim:
                property_key(name)
                budget.charge(2, 2)
                values = []
                for row in claim[name]:
                    budget.charge(bool(values), bool(values))
                    values.append(pick(row, keys))
                fields[name] = values
        return cls(fields, sources)

    def __getitem__(self, key):
        return self.fields[key]

    def get(self, key, default=None):
        return self.fields.get(key, default)


def select_reducer_claims(
    overview, claims, coverage, issues, kev, options, *, evaluated_at, max_bytes=128_000_000
):
    """Apply the same pure row/event reducer to validated private projections."""
    vendor = options.get("vendor")
    scope = options.get("scope_level", "os_family")
    window = options.get("window", "all")
    ids = options.get("cve_ids")
    if set(options) - {"vendor", "scope_level", "window", "cve_ids"}:
        raise ValueError("Unknown study selection option")
    if vendor is not None and vendor not in VENDORS:
        raise ValueError("Unknown study vendor")
    if scope not in SCOPES:
        raise ValueError("Unknown scope level")
    if ids is not None and (
        type(ids) is not list
        or any(not isinstance(c, str) or not kev_reports.CVE.fullmatch(c) for c in ids)
    ):
        raise ValueError("CVE selection must be null or a list of canonical CVE IDs")
    kev_reports._timestamp(evaluated_at)
    _bounds(overview["definition"], overview["observation_end"], window)
    from ..publication_codec import Budget

    budget = Budget(max_bytes)
    build = _Construction(Budget(max_bytes))
    requested = sorted(build.unique(ids)) if ids is not None else None
    vendors = [vendor] if vendor else list(VENDORS)
    evidence = dict(claims=claims, coverage=coverage, issues=issues)
    context = dict(
        definition=overview["definition"],
        observation_end=overview["observation_end"],
        inputs=dict(evidence=evidence, kev=kev),
    )
    header = (
        (k, v)
        for k, v in overview.items()
        if k
        not in (
            "detail_ranges",
            "rows",
            "schema_version",
            "representation",
            "selection",
            "evaluated_at",
            "sources",
        )
    )
    result = build.object(header)
    result = copy.deepcopy(result)
    rows = []
    for v in vendors:
        row = _row(context, v, scope, window, requested, evaluated_at, build=build)
        rows.append(row)
    sources = _selected_sources(evidence, rows, build=build)
    selection = build.object(
        (
            ("requested_vendor", vendor),
            ("effective_vendors", vendors),
            ("scope_level", scope),
            ("requested_window", window),
            ("effective_windows", build.array(r["row_id"] for r in rows)),
            ("requested_cve_ids", requested),
            ("effective_cve_ids", sorted(build.unique(c for r in rows for c in r["cve_ids"]))),
            ("definition_sha256", contracts.definition_sha256(overview["definition"])),
        )
    )
    # Charge the final outer object before constructing it, with one exact budget.
    pairs = list(result.items()) + [
        ("schema_version", 1),
        ("representation", "summary"),
        ("rows", rows),
        ("evaluated_at", evaluated_at),
        ("sources", sources),
        ("selection", selection),
    ]
    result = _Construction(budget).object(pairs)
    contracts._validate(result, "switching-summary-v1.json")
    return result
