"""Independent switching extraction sample; automated results never imply human review."""

import json
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from ..source_policy import allowed
from . import extraction_validation
from .source_selections import public_selections

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


def _alternate_contexts(selections, records):
    """Fail closed on optional malformed metadata; never treat it as claims."""
    contexts = {}
    if not isinstance(selections, (list, tuple)):
        return contexts
    for selection in selections:
        try:
            choices = public_selections([selection], records)
        except (AttributeError, KeyError, TypeError, ValueError, ValidationError):
            continue
        for choice in choices:
            selected = next(v for v in choice["views"] if v["selected"])
            unavailable = {issue["source_url"] for issue in choice["unavailable"]}
            for view in choice["views"]:
                if view["selected"] or view["source_url"] in unavailable:
                    continue
                key = (
                    choice["vendor"],
                    view["source_url"],
                    view["source_sha256"],
                    selected["source_url"],
                    selected["source_sha256"],
                )
                contexts[key] = dict(
                    state="retained_unselected_representation",
                    source_url=view["source_url"],
                    source_sha256=view["source_sha256"],
                    selected_source_url=selected["source_url"],
                    selected_source_sha256=selected["source_sha256"],
                )
    return contexts


def report(
    records: list[dict], scopes: list[dict], *, retained_advisories=(), source_selections=()
) -> dict:
    result = extraction_validation.validation_report(
        records, review=definition(), scopes=scopes, retained_advisories=retained_advisories
    )
    contexts = _alternate_contexts(
        source_selections, records + [w["record"] for w in retained_advisories]
    )
    for case in result["cases"]:
        key = case["vendor"], case["source_url"], case["source_sha256"]
        if case["outcome"] != "source_missing":
            continue
        exact = sorted(k for k in contexts if k[:3] == key)
        if exact:
            case["source_context"] = contexts[exact[0]]
            continue
        # Same-URL metadata explains availability without supporting the reviewed bytes.
        revisions = {
            (
                digest,
                context["selected_source_url"],
                context["selected_source_sha256"],
            )
            for (vendor, url, digest, _, _), context in contexts.items()
            if (vendor, url) == key[:2]
        }
        if revisions:
            case["source_context"] = dict(
                state="retained_unselected_different_revision",
                source_url=case["source_url"],
                reviewed_source_sha256=case["source_sha256"],
                available_revisions=[
                    dict(
                        available_source_sha256=digest,
                        selected_source_url=url,
                        selected_source_sha256=selected_digest,
                    )
                    for digest, url, selected_digest in sorted(revisions)
                ],
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


def rebuild(data):
    """Project owned digest fields and recompute study results from current inputs."""
    import re

    records = data["records"]
    retained = data.get("retained_advisories", [])
    union = records + [w["record"] for w in retained]
    known = {(r["source_url"], r["sha256"]) for r in union}
    fields = ("source_url", "source_sha256", "scheme", "scope_sha256")
    scopes = [
        {k: s[k] for k in fields}
        for s in data.get("switching_reviewed_source_scopes", [])
        if all(isinstance(s.get(k), str) for k in fields)
        and (s["source_url"], s["source_sha256"]) in known
        and re.fullmatch(r"[a-f0-9]{64}", s["scope_sha256"])
    ]
    data["switching_reviewed_source_scopes"] = scopes
    data["switching_validation"] = report(
        records,
        scopes,
        retained_advisories=retained,
        source_selections=data.get("source_audit", {}).get("source_selections", ()),
    )
    data["switching_review_packet"] = packet(union)


def attach_release_reliability(report, reliability):
    """Keep release-structure checks separate from advisory extraction pass rates.

    Passing these automatic checks does not establish source completeness or
    independent human approval of a publisher action or notice classification.
    """
    from copy import deepcopy

    from .release_reliability import validate_report

    validate_report(reliability)
    for key in ("publication", "generated_at"):
        if key in report and report[key] != reliability[key]:
            raise ValueError("Release validation and extraction generation differ")
    result = deepcopy(report)
    result["release_reliability"] = {
        **deepcopy(reliability["validation"]),
        "publication": deepcopy(reliability["publication"]),
        "generated_at": reliability["generated_at"],
        "catalogue_sha256": reliability["catalogue_sha256"],
        "dataset_observed_at": reliability["dataset_observed_at"],
        "review_status": "independent_human_review_pending",
        "interpretation": (
            "Automatic release evidence checks are separate from extraction pass rates. "
            "They do not approve source classifications, model applicability or completeness."
        ),
    }
    return result
