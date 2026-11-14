"""Typed, source-pinned supplementary checks; never independent human review.

Caller supplies public normalized records, compact analysis, and the explicit
chronology replay rows. This helper never opens storage, fetches, or infers facts.
"""

import json
from importlib.resources import files

from ..adapters import arista_sa0137
from .arista_chronology_repair import validate_cases


def report(records, *, compiled=None, chronology_rows=()):
    from . import switching_analysis

    if compiled is not None:
        switching_analysis.validate_report(compiled)
    resource = files("infrastructure_impact").joinpath("resources/cisco-disclosure-validation.json")
    expected = json.loads(resource.read_text())["cases"][0]
    owned = [
        r
        for r in records
        if r["vendor"] == "cisco"
        and r["advisory_id"] == expected["advisory_id"]
        and r["sha256"] == expected["sha256"]
    ]
    cases = []

    def add(case_id, vendor, kind, available, passed, sources, reason):
        cases.append(
            dict(
                id=case_id,
                vendor=vendor,
                kind=kind,
                outcome="unavailable" if not available else "pass" if passed else "fail",
                reason=reason,
                sources=sources,
                human_review="pending",
            )
        )

    receipts = [
        dict(url=r["source_url"], sha256=r["sha256"], retrieved_at=r["source_observed_at"])
        for r in owned
    ]
    metadata = owned[0].get("disclosure_metadata") if len(owned) == 1 else None
    add(
        "cisco-hardening-disclosure",
        "cisco",
        "disclosure_metadata",
        metadata is not None,
        metadata is not None
        and metadata["initial_published_at"] == expected["initial_published_at"]
        and {r["cve_id"]: r["cwe_id"] for r in metadata["umbrella_cves"]} == expected["cwe_by_cve"]
        and metadata["highest_cvss_wording"] == expected["highest_cvss_wording"]
        and metadata["bug_count"] is None
        and metadata["bug_count_status"] == "not_disclosed",
        receipts,
        "Pinned umbrella ownership, publisher initial date, highest-score wording and undisclosed bug count",
    )
    fixes = owned[0].get("first_fixed", []) if len(owned) == 1 else []
    targets = {v for f in fixes if f["method"] == "stated_table" for v in f["fixed_versions"]}
    add(
        "cisco-hardening-first-fixed",
        "cisco",
        "first_fixed_targets",
        bool(fixes),
        targets == {"17.9.10", "17.12.8", "17.15.6", "17.18.4", "17.18.4a", "26.1.2"}
        and any(
            f["disposition"] == "migrate" and f["train_expression"] == "17.8 and earlier"
            for f in fixes
        ),
        receipts,
        "Five stated train rows, alternative 17.18 targets, and explicit migration range",
    )
    claims = (
        []
        if compiled is None
        else [
            c
            for c in switching_analysis.claim_facets(compiled)
            if c["vendor"] == "arista"
            and c["advisory_id"] == arista_sa0137.ID
            and c["source"]["source_url"] == arista_sa0137.URL
            and c["source"]["source_sha256"]
            == "21540eabc1c78ff4d0a6122ff5b03e103017b4e9ef38551712936f26f64d5c7d"
        ]
    )
    # Parser/selection owns the exact reviewed source; no title or family-to-model join.
    source_receipts = list(
        {json.dumps(c["source"], sort_keys=True): c["source"] for c in claims}.values()
    )
    affected = [c for c in claims if c["status"] == "affected" and c["scope"] == "cve_specific"]
    add(
        "arista-sa137-model-scope",
        "arista",
        "model_binding",
        bool(claims),
        {c["cve_id"] for c in affected} == set(arista_sa0137.CVES)
        and all(c["scope_level"] != "model_qualified" for c in affected),
        source_receipts,
        "Family affected CVE is retained; no resolved campus affected-model claim",
    )
    entries = (
        []
        if compiled is None
        else [
            e
            for e in compiled["kev_reconciliation"]["entries"]
            if e["mapping"]["vendor"] == "arista" and e["cve_id"] in arista_sa0137.CVES
        ]
    )
    add(
        "arista-sa137-kev",
        "arista",
        "kev_reconciliation",
        bool(entries) and bool(claims),
        len(entries) == 1
        and entries[0]["claim_state"] == "documented_affected"
        and entries[0]["historically_listed"] is True,
        source_receipts,
        "Retained historical KEV listing and family affectedness; current membership and campus model scope remain separate",
    )
    cases[-1]["observed"] = dict(
        historically_listed=entries[0]["historically_listed"] if len(entries) == 1 else None,
        current_membership=entries[0]["membership"] if len(entries) == 1 else None,
        current_availability=compiled["kev_reconciliation"]["availability"] if compiled else None,
        claim_state=entries[0]["claim_state"] if len(entries) == 1 else None,
    )
    for case in validate_cases(chronology_rows):
        row = next((r for r in chronology_rows if r["number"] == case["number"]), None)
        add(
            "arista-date-" + str(case["number"]),
            "arista",
            "publisher_date",
            case["automated_validation"] in {"passed", "failed"},
            case["automated_validation"] == "passed",
            []
            if row is None
            else [dict(kind=k, sha256=v) for k, v in row["source_hashes"].items()],
            case["automated_validation"],
        )
    vendors = []
    for vendor in ("cisco", "aruba", "arista"):
        selected = [c for c in cases if c["vendor"] == vendor]
        vendors.append(
            dict(
                vendor=vendor,
                cases=len(selected),
                evaluated=sum(c["outcome"] != "unavailable" for c in selected),
                passed=sum(c["outcome"] == "pass" for c in selected),
                failed=sum(c["outcome"] == "fail" for c in selected),
                unavailable=sum(c["outcome"] == "unavailable" for c in selected),
                coverage="available" if selected else "no_pinned_source_cases",
            )
        )
    return dict(
        schema_version=1,
        method="typed-source-facts-v1",
        independent_human_review_completed=False,
        cases=cases,
        vendor_results=vendors,
        global_accuracy=None,
        limitations=[
            "Purposive pinned cases, not a vendor accuracy estimate.",
            "Unavailable cases do not enter the evaluated denominator.",
            "These checks supplement, and do not replace, claim extraction validation.",
        ],
    )


def main():
    """Explicit immutable public inputs only; no default database or acquisition."""
    import argparse
    import hashlib
    from datetime import UTC, datetime
    from pathlib import Path

    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--records-input", type=Path, required=True)
    parser.add_argument("--analysis", type=Path)
    parser.add_argument("--chronology", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipts = []

    def read(path):
        if path is None:
            return None
        raw = path.read_bytes()
        receipts.append(dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest()))
        return json.loads(raw)

    records = read(args.records_input)
    compiled = read(args.analysis)
    chronology = read(args.chronology)
    result = report(
        records["records"],
        compiled=compiled,
        chronology_rows=[] if chronology is None else chronology["rows"],
    )
    result["evaluated_at"] = datetime.now(UTC).isoformat()
    result["input_receipts"] = receipts
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
