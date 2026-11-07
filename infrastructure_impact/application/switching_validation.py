"""Independent switching extraction sample; automated results never imply human review."""

import json
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker

from ..source_policy import allowed
from . import extraction_validation

VENDORS = ("cisco", "aruba", "arista")
# Missing categories are not invented examples and do not enter pass rates.
MISSING = {
    "cisco": ["draft", "planned_fix", "model_qualified"],
    "aruba": ["explicit_bundle", "draft", "planned_fix", "model_qualified"],
    "arista": ["explicit_bundle", "draft", "planned_fix", "in_period_model_qualified"],
}


def definition():
    package = files("infrastructure_impact")
    result = json.loads(package.joinpath("resources/switching-extraction-review.json").read_text())
    schema = json.loads(package.joinpath("schemas/extraction-review-v1.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    if len({c["id"] for c in result["cases"]}) != len(result["cases"]):
        raise ValueError("Switching case IDs must be unique")
    if any(
        c["vendor"] not in VENDORS or not allowed(c["source_url"], c["vendor"])
        for c in result["cases"]
    ):
        raise ValueError("Switching review needs official study vendor sources")
    return result


def report(records: list[dict], scopes: list[dict], *, retained_advisories=()) -> dict:
    result = extraction_validation.validation_report(
        records, review=definition(), scopes=scopes, retained_advisories=retained_advisories
    )
    result["study"] = "campus-branch-switching"
    result["vendor_results"] = []
    for vendor in VENDORS:
        cases = [c for c in result["cases"] if c["vendor"] == vendor]
        failures = [
            dict(id=c["id"], outcome=c["outcome"])
            for c in cases
            if c["outcome"] not in ("pass", "reviewed_scope_match_source_changed")
        ]
        result["vendor_results"].append(
            dict(
                vendor=vendor,
                sample_cases=len(cases),
                minimum_cases=5,
                sample_requirement_met=len(cases) >= 5,
                full_byte_matches=sum(c["outcome"] == "pass" for c in cases),
                scoped_matches=sum(
                    c["outcome"] == "reviewed_scope_match_source_changed" for c in cases
                ),
                failures=failures,
                missing_categories=MISSING[vendor],
                validation_complete=False,
            )
        )
    result["limitations"] += [
        "Missing categories are reported independently of observed case outcomes; no global precision or completeness is estimated.",
        "Arista 0056 is an out-of-period 2020 boundary control, not a 2021 disclosure.",
        "Cisco source-only HTML and bundle membership need the separate retained-source evidence replay; core assessment cases alone do not validate those links.",
    ]
    return result


def packet(records: list[dict]) -> dict:
    result = extraction_validation.review_packet(records, review=definition())
    result["study"] = "campus-branch-switching"
    result["instructions"] = result["instructions"].replace(
        "extraction-validation.json", "switching-validation.json"
    )
    result["packet_sha256"] = extraction_validation.packet_sha256(result)
    return result
