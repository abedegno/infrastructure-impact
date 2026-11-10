"""Finite packaged source ownership, with fresh cross-claim validation per invocation."""

import copy
import hashlib
import json
from datetime import datetime
from functools import lru_cache
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker


@lru_cache(maxsize=1)
def _metadata():
    package = files("infrastructure_impact")
    data = json.loads(package.joinpath("resources/reviewed-remediation-bindings.json").read_text())
    schema = json.loads(
        package.joinpath("schemas/reviewed-remediation-bindings-v1.json").read_text()
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(data)
    index = {}
    sources = {}
    for source in data["sources"]:
        source_key = (source["vendor"], source["advisory_id"])
        if source_key in sources:
            raise ValueError("Duplicate reviewed source identity")
        sources[source_key] = source
        for binding in source["bindings"]:
            if binding["cve_id"] not in source["expected_cve_ids"]:
                raise ValueError("Reviewed binding CVE outside owned source")
            key = (
                *source_key,
                binding["cve_id"],
                binding["affected_product_id"],
                binding["affected_product"],
                binding["affected_locator"],
            )
            if key in index:
                raise ValueError("Duplicate reviewed affected tuple")
            index[key] = {**source, **binding}
            index[key].pop("bindings")
    return data, sources, index


def definition():
    """Return validated ordinary JSON; callers cannot mutate cached definitions."""
    return copy.deepcopy(_metadata()[0])


def registered_source(claim):
    """Route registered advisories even when their untrusted provenance has drifted."""
    return (claim.get("vendor"), claim.get("advisory_id")) in _metadata()[1]


def rule_for(claim):
    """Return an exact finite affected tuple; never derive pairs from version labels."""
    source = claim.get("source", {})
    key = (
        claim.get("vendor"),
        claim.get("advisory_id"),
        claim.get("cve_id"),
        claim.get("product_id"),
        claim.get("product"),
        source.get("source_locator"),
    )
    rule = _metadata()[2].get(key)
    if rule is not None and (
        claim.get("family") == rule["family"]
        and claim.get("status") == "affected"
        and claim.get("scope") == "cve_specific"
        and claim.get("version_expressions") == rule["affected_versions"]
        and source.get("source_url") == rule["source_url"]
        and (rule["source_sha256"] is None or source.get("source_sha256") == rule["source_sha256"])
    ):
        return copy.deepcopy(rule)
    return None


def fixed_siblings(claim, rule, claims):
    """Count siblings before checking versions, so conflicting duplicates reject."""
    return [
        fixed
        for fixed in claims
        if all(
            fixed.get(k) == claim.get(k)
            for k in (
                "vendor",
                "advisory_id",
                "revision",
                "publisher",
                "cve_id",
                "family",
                "scope",
                "initial_published_at",
                "updated_at",
            )
        )
        and fixed.get("status") == "fixed"
        and fixed.get("product") == rule["fixed_product"]
        and fixed.get("product_id") == rule["fixed_product_id"]
        and fixed.get("source", {}).get("source_locator") == rule["fixed_locator"]
        and all(
            fixed.get("source", {}).get(k) == claim["source"].get(k)
            for k in ("source_url", "source_sha256", "retrieved_at")
        )
    ]


def _day(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except (ValueError, AttributeError):
        return None


def owned_remediation(fixed, remediation, rule, *, released=True, as_of=None):
    """Check the original fixed remediation against its immutable literal owner."""
    details = remediation.get("details")
    date = remediation.get("availability_date")
    target = _day(date)
    reference = _day(as_of or fixed.get("updated_at") or fixed.get("initial_published_at"))
    return (
        fixed.get("version_expressions") == rule["fixed_versions"]
        and "evidence_text_truncated" not in fixed.get("issues", [])
        and remediation.get("category") == "vendor_fix"
        and remediation.get("publisher_id") is None
        and not remediation.get("scope_binding")
        and remediation.get("product_ids")
        == ([rule["fixed_product_id"]] if rule["fixed_product_id"] is not None else [])
        and remediation.get("version_expressions")
        == ([] if rule["kind"] == "csaf" else rule["fixed_versions"])
        and isinstance(details, str)
        and hashlib.sha256(details.encode("utf-8")).hexdigest()
        == rule["remediation_details_sha256"]
        and remediation.get("published_availability") == details
        and all(literal in details for literal in rule["availability_proof_literals"])
        and date == rule["availability_date"]
        and (date is None or (target is not None and reference is not None and target <= reference))
        and remediation.get("source", {}).get("source_locator") == rule["remediation_locator"]
        and all(
            remediation.get("source", {}).get(k) == fixed.get("source", {}).get(k)
            for k in ("source_url", "source_sha256", "retrieved_at")
        )
        and remediation.get("availability")
        in ({"vendor_reports_fixed"} if released else {"unknown", "vendor_reports_fixed"})
    )


def validate_link(claim, remediation, binding, claims):
    """Reject copied fixes unless one fresh retained sibling has the pinned owner."""
    rule = rule_for(claim)
    matching = [] if rule is None else fixed_siblings(claim, rule, claims)
    if (
        rule is None
        or len(matching) != 1
        or "evidence_text_truncated" in claim.get("issues", [])
        or binding.get("basis") != "reviewed_source_sections"
        or binding.get("cve_id") != claim["cve_id"]
        or binding.get("source") != claim["source"]
        or binding.get("fixed_product") != rule["fixed_product"]
        or (binding.get("fixed_product_id") != rule["fixed_product_id"])
        or (rule["fixed_product_id"] is None and "fixed_product_id" in binding)
        or binding.get("fixed_source") != matching[0]["source"]
        or remediation.get("product_ids") != []
        or remediation.get("version_expressions") != rule["fixed_versions"]
    ):
        raise ValueError("Registered reviewed section requires exact retained source/CVE linkage")
    originals = [
        rem for rem in matching[0]["remediations"] if owned_remediation(matching[0], rem, rule)
    ]
    if len(originals) != 1 or any(
        remediation.get(k) != originals[0].get(k)
        for k in (
            "publisher_id",
            "category",
            "details",
            "published_availability",
            "availability",
            "availability_date",
            "source",
        )
    ):
        raise ValueError("Registered reviewed remediation differs from pinned original")
