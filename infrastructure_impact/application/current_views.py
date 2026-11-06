"""Pure assembly of current analytics, with explicitly retained audit evidence."""

import copy

from .evidence_identity import record_key


def validate_partition(data, *, require_targets=False):
    """Validate public references without executing a private policy hook."""
    from .current_evidence import validate_report

    report = data["current_evidence"]
    validate_report(report, publication=data.get("publication"), generated_at=data["generated_at"])
    if report["availability"] != "available":
        raise ValueError("New publications require available current-evidence decisions")
    current = data["records"]
    retained = data.get("retained_advisories", [])
    keys = [record_key(r) for r in current] + [record_key(w["record"]) for w in retained]
    if len(set(keys)) != len(keys):
        raise ValueError("Duplicate retained/current identity")
    decisions = {d["decision_id"]: d for d in report["decisions"]}
    used = set()
    for wrapper in retained:
        if require_targets and "target_key" not in wrapper:
            raise ValueError("Published retained wrapper requires explicit target reference")
        decision = decisions.get(wrapper.get("decision_id"))
        key = record_key(wrapper["record"])
        if (
            decision is None
            or wrapper.get("record_scope") != "retained_latest_excluded"
            or decision["target_key"] != key
            or wrapper.get("target_key", key) != key
            or decision["vendor"] != wrapper["record"]["vendor"]
        ):
            raise ValueError("Invalid retained decision reference")
        used.add(decision["decision_id"])
    if used != set(decisions) or report["counts"] != {
        "current": len(current),
        "excluded": len(retained),
        "retained_total": len(keys),
    }:
        raise ValueError("Inconsistent current-evidence partition")


def rebuild(data: dict, partition_result: dict) -> dict:
    """Rebuild every current reducer from one partition; leave audit facts intact."""
    from .casefiles import casefiles
    from .cohort import coverage_from_checks
    from .comparison import compare
    from .component_studies import component_studies
    from .disclosure_review import disclosure_review
    from .eligibility import eligibility
    from .evaluation import evaluate
    from .extraction_validation import review_packet, validation_report
    from .families import completeness
    from .fix_leads import leads
    from .product_cohorts import product_cohorts
    from .product_groups import product_groups
    from .readiness import readiness
    from .research_dossiers import research_dossiers
    from .scorecards import scorecards
    from .vendor_gaps import vendor_gaps

    data = copy.deepcopy(
        {
            **data,
            **partition_result,
            "research": {
                k: v for k, v in data.get("research", {}).items() if k != "current_evidence_input"
            },
        }
    )
    records = data["records"]
    retained = data["retained_advisories"]
    for wrapper in retained:
        wrapper["target_key"] = record_key(wrapper["record"])
    validate_partition(data)
    union = records + [w["record"] for w in retained]
    data["evidence_scopes"] = {
        "records": "current",
        "retained_advisories": "retained_latest_excluded",
        "changes": "retained_history",
        "timeline": "retained_history",
        "source_audit": "retained_evidence",
        "review_packet": "retained_review_context",
        "publisher_history": "retained_history",
    }
    data["all_cves"] = sorted({c for r in records for c in r["cves"]})
    data["retained_cves"] = sorted({c for r in union for c in r["cves"]})
    data["counts"].update(
        advisories=len(records),
        current=len(records),
        excluded=len(retained),
        retained_total=len(union),
    )
    cohort = data.get("comparison", {}).get("cohort", data["benchmark_cohort"])
    data["comparison"] = compare(records, cohort, vendors=data["vendors"])
    scope = sorted(set(data["all_cves"]) | set(data["benchmark_cohort"]) | set(cohort))
    facts = [check for row in data.get("coverage", []) for check in row.get("checks", [])]
    data["coverage"] = coverage_from_checks(records, facts, cohort=scope, vendors=data["vendors"])
    for row in data.get("catalogue", {}).get("vendors", []):
        row["advisories"] = sum(r["vendor"] == row["vendor"] for r in records)
    data["scorecards"] = scorecards(
        records,
        data["coverage"],
        data["catalogue"],
        data["health"],
        scope,
        data["vendors"],
        data["generated_at"],
    )
    data["benchmark"] = evaluate(records, retained_advisories=retained)
    data["extraction_validation"] = validation_report(
        records, scopes=data.get("reviewed_source_scopes", []), retained_advisories=retained
    )
    data["review_packet"] = review_packet(union)

    # Preserve independently owned alternate/source-only representations. Only
    # an exact excluded owner can remove a research claim or score source.
    def current_source(value):
        source = value.get("source") or {}
        if (
            value.get("source_url") is not None
            and source.get("source_url") is not None
            and value["source_url"] != source["source_url"]
        ):
            raise ValueError("Ambiguous current research source ownership")
        owner_url = (
            value["vendor"],
            value["advisory_id"],
            value.get("source_url") or source.get("source_url"),
        )
        candidates = [
            w["record"]
            for w in retained
            if (w["record"]["vendor"], w["record"]["advisory_id"], w["record"]["source_url"])
            == owner_url
        ]
        if not candidates:
            return True
        digest = source.get("source_sha256")
        if digest is None:
            raise ValueError("Ambiguous current research source ownership")
        excluded = [r for r in candidates if r["sha256"] == digest]
        if not excluded:
            return True
        matching = [
            r
            for r in records
            if (r["vendor"], r["advisory_id"], r["source_url"]) == owner_url
            and r["sha256"] == digest
        ]
        if not matching:
            return False
        # Native switching and score evidence use text revision references.
        revision = value.get("revision")
        if revision is None:
            revisions = {c.get("revision") for c in value.get("claims", [])}
            if len(revisions) == 1:
                revision = next(iter(revisions))
        if revision is None:
            raise ValueError("Ambiguous current research source ownership")
        current_match = any(str(r["revision_id"]) == revision for r in matching)
        excluded_match = any(str(r["revision_id"]) == revision for r in excluded)
        if current_match != excluded_match:
            return current_match
        raise ValueError("Ambiguous current research source ownership")

    research = data.get("research", {})
    switching = research.get("switching_input")
    if switching is None:
        switching = data.get("switching_evidence")
        if switching is None and "switching_comparison" in data:
            switching = data["switching_comparison"].get("inputs", {}).get("evidence")
            if switching is None:
                raise ValueError(
                    "Cached switching summary requires complete current evidence inputs"
                )
        if switching is not None:
            from jsonschema import ValidationError

            from .switching_evidence import validate_evidence

            try:
                validate_evidence(switching)
            except (ValidationError, ValueError, TypeError, KeyError):
                raise ValueError(
                    "Cached switching evidence requires a complete valid contract"
                ) from None
            research["switching_input"] = switching
    # Every public switching result is regenerated below the projection boundary.
    data.pop("switching_evidence", None)
    data.pop("switching_comparison", None)
    if switching is not None:
        switching["claims"] = [c for c in switching.get("claims", []) if current_source(c)]
        if "score_availability" in switching:
            switching["score_availability"] = [
                a for a in switching["score_availability"] if current_source(a)
            ]
    score_input = research.get("score_input")
    if score_input is not None:
        score_input["advisories"] = [
            a for a in score_input.get("advisories", []) if current_source(a)
        ]
    for name, reducer in (
        ("vendor_gaps", vendor_gaps),
        ("casefiles", casefiles),
        ("product_groups", product_groups),
        ("comparison_eligibility", lambda d: eligibility(d, cohort)),
        ("family_completeness", completeness),
        ("comparison_readiness", readiness),
        ("fix_leads", leads),
        ("component_studies", component_studies),
        ("product_cohorts", product_cohorts),
        ("disclosure_review", disclosure_review),
        ("research_dossiers", research_dossiers),
    ):
        data[name] = reducer(data)
    return data
