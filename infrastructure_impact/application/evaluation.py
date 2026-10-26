"""Evaluate declared, primary-source-reviewed expectations without circular labels."""

import json
import re

from ..settings import PACKAGE


def evaluate(records, *, definition=None):
    if definition is None:
        definition = json.loads((PACKAGE / "resources/benchmark-cases.json").read_text())
    results = []
    for case in definition["cases"]:
        sources = [
            r
            for r in records
            if r["vendor"] == case["vendor"] and r["source_url"] == case["source_url"]
        ]
        claims = [
            (r, a)
            for r in sources
            for a in r["assessments"]
            if a["cve_id"] == case["cve_id"]
            and re.search(case["product_pattern"], a["product"], re.I)
            and all(pair in a.get("product_context", []) for pair in case.get("claim_context", []))
            and (
                not case.get("claim_version_contains")
                or case["claim_version_contains"] in json.dumps(a["versions"])
            )
        ]

        def agrees(a):
            return (
                a["status"] == case["expected_status"]
                and (not case.get("expected_scope") or a["scope"] == case["expected_scope"])
                and (
                    not case.get("version_contains")
                    or case["version_contains"] in json.dumps(a["versions"])
                )
            )

        forbidden = [a for _, a in claims if a["status"] in case.get("forbidden_statuses", [])]
        outcome = (
            "source_missing"
            if not sources
            else "product_scope_missing"
            if not claims
            else "forbidden_claim"
            if forbidden
            else "pass"
            if any(agrees(a) for _, a in claims)
            else "disagreement"
        )
        results.append(
            {
                **case,
                "outcome": outcome,
                "source_fingerprints": sorted({r["sha256"] for r in sources}),
                "forbidden_claim_count": len(forbidden),
                "observed_statuses": sorted({a["status"] for _, a in claims}),
            }
        )
    passed = sum(r["outcome"] == "pass" for r in results)
    return {
        "schema_version": 1,
        "cases": results,
        "total": len(results),
        "passed": passed,
        "agreement_on_declared_cases": passed / len(results),
        "negative_boundaries": sum(bool(c.get("forbidden_statuses")) for c in results),
        "forbidden_claim_count": sum(c["forbidden_claim_count"] for c in results),
        "global_precision": None,
        "limitations": definition["limitations"],
    }
