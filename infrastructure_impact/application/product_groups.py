"""Versioned, conservative product-role classification; never a device inventory.

Rules match whole publisher family names or delimited prefixes. Numeric version
leaves may inherit a retained product family. A longer family rule takes
precedence; equal-length conflicting rules produce an explicit ambiguity.
"""

import json
from functools import lru_cache

from jsonschema import Draft202012Validator, FormatChecker

from ..collection.transport import allowed
from ..settings import PACKAGE


@lru_cache(maxsize=1)
def definition():
    value = json.loads((PACKAGE / "resources/product-groups.json").read_text())
    validate_definition(value)
    return value


def validate_definition(value):
    validate_report(value, "product-group-definition-v1.json")
    groups = {g["id"] for g in value["groups"]}
    if len(groups) != len(value["groups"]) or len({r["id"] for r in value["rules"]}) != len(
        value["rules"]
    ):
        raise ValueError("Product group and rule IDs must be unique")
    for rule in value["rules"]:
        if (
            rule["group"] not in groups
            or not rule["prefix"].strip()
            or not allowed(rule["source_url"], rule["vendor"])
        ):
            raise ValueError("Product rule needs a known group, family and official HTTPS source")


def validate_report(value, schema="product-groups-v1.json"):
    Draft202012Validator(
        json.loads((PACKAGE / "schemas" / schema).read_text()), format_checker=FormatChecker()
    ).validate(value)


def classify(vendor, assessment, taxonomy=None):
    taxonomy = definition() if taxonomy is None else taxonomy
    # The named family is more informative than a CSAF numeric version leaf.
    names = [assessment.get("product_family") or assessment.get("product", "")]
    matches = [
        r
        for r in taxonomy["rules"]
        if r["vendor"] == vendor
        and any(
            name.strip() == r["prefix"]
            or (
                name.strip().startswith(r["prefix"])
                and name.strip()[len(r["prefix"]) : len(r["prefix"]) + 1] in (" ", "-", "(")
            )
            for name in names
        )
    ]
    if not matches:
        return {"state": "unmapped", "group": None, "rule_ids": []}
    length = max(len(r["prefix"]) for r in matches)
    matches = [r for r in matches if len(r["prefix"]) == length]
    groups = {r["group"] for r in matches}
    return {
        "state": "mapped" if len(groups) == 1 else "ambiguous",
        "group": next(iter(groups)) if len(groups) == 1 else None,
        "rule_ids": sorted(r["id"] for r in matches),
    }


def product_groups(data):
    taxonomy = definition()
    rows = []
    for vendor in data["vendors"]:
        claims = [
            (a, classify(vendor, a, taxonomy))
            for r in data["records"]
            if r["vendor"] == vendor and r.get("document_status") != "draft"
            for a in r["assessments"]
        ]
        rows.append(
            dict(
                vendor=vendor,
                statement_count=len(claims),
                mapped_statements=sum(c["state"] == "mapped" for _, c in claims),
                unmapped_statements=sum(c["state"] == "unmapped" for _, c in claims),
                ambiguous_statements=sum(c["state"] == "ambiguous" for _, c in claims),
                unresolved_labels=sorted({a["product"] for a, c in claims if not c["group"]}),
                groups=[
                    dict(
                        group=g["id"],
                        statement_count=sum(c["group"] == g["id"] for _, c in claims),
                        product_labels=sorted(
                            {a["product"] for a, c in claims if c["group"] == g["id"]}
                        ),
                    )
                    for g in taxonomy["groups"]
                ],
            )
        )
    return dict(
        **taxonomy,
        vendors=rows,
        method="Product roles group retained statements, not equivalent devices or complete portfolios. Longest delimited family prefix wins; conflicting ties and unknown labels remain unresolved. A role match never changes CVE applicability, versions, platform/configuration qualifiers or metric eligibility. Counts cover all retained non-draft statements, independently of the comparison reporting period.",
    )
