"""Curated family evidence gaps; no inferred portfolio or release-train completeness."""

import json
import re
from collections import Counter

from ..settings import PACKAGE


def definition():
    return json.loads((PACKAGE / "resources/product-families.json").read_text())


def matches(family, claim):
    labels = [claim.get("product", ""), claim.get("product_family") or ""] + [
        value
        for category, value in claim.get("product_context", [])
        if category in {"product_name", "product_family"}
    ]
    prefixes = family["prefixes"]
    named = any(
        re.match(re.escape(prefix.casefold()) + r"(?=$|[\s(/])", label.strip().casefold())
        is not None
        for label in labels
        for prefix in prefixes
    )
    platforms = claim.get("platforms", [])
    required = family["platform_prefixes"]
    return named and (
        not required
        or bool(platforms)
        and all(any(p.startswith(prefix) for prefix in required) for p in platforms)
    )


def version_text(claim):
    # Product/model labels cannot establish software release lines.
    contexts = [
        value
        for category, value in claim.get("product_context", [])
        if category in {"product_version", "product_version_range"}
    ]
    return json.dumps(claim.get("versions", []), ensure_ascii=False) + " " + " ".join(contexts)


def statements(data, family):
    return [
        (r, a)
        for r in data["records"]
        if r["vendor"] == family["vendor"] and r.get("document_status") != "draft"
        for a in r["assessments"]
        if matches(family, a)
    ]


def completeness(data):
    catalog = definition()
    rows = []
    for family in catalog["families"]:
        if family["vendor"] not in data["vendors"]:
            continue
        found = statements(data, family)
        trains = []
        for train in family["expected_train_references"]:
            references = [
                (r, a)
                for r, a in found
                if re.search(r"(?<![\d.])" + re.escape(train) + r'(?=[.("\s]|$)', version_text(a))
            ]
            trains.append(
                dict(
                    train=train,
                    state="referenced" if references else "unknown",
                    statements=len(references),
                    meaning="Literal publisher version reference only; coverage of this entire train is not established.",
                )
            )
        examples = {}
        for record, claim in found:
            key = record["source_url"], record["sha256"]
            examples[key] = dict(
                source_url=key[0],
                source_sha256=key[1],
                publisher_date=record.get("published_at"),
                observed_at=record.get("source_observed_at") or record.get("observed_at"),
            )
        errors = [
            h
            for h in data.get("health", [])
            if h["vendor"] == family["vendor"] and h["outcome"] == "error"
        ]
        rows.append(
            dict(
                id=family["id"],
                vendor=family["vendor"],
                name=family["name"],
                state="evidence_present" if found else "unknown",
                statements=len(found),
                advisories=len({r["advisory_id"] for r, _ in found}),
                cves=len({a["cve_id"] for _, a in found}),
                statuses=dict(Counter(a["status"] for _, a in found)),
                explicit_statements=sum(a["scope"] == "cve_specific" for _, a in found),
                shared_statements=sum(a["scope"] == "bulletin_shared" for _, a in found),
                product_labels=sorted({a["product"] for _, a in found}),
                train_references=trains,
                version_scope_unresolved=sum(
                    not a.get("versions")
                    and not any(
                        category in {"product_version", "product_version_range"}
                        for category, _ in a.get("product_context", [])
                    )
                    for _, a in found
                ),
                vendor_source_errors=len(errors),
                evidence=list(examples.values())[:20],
                evidence_truncated=len(examples) > 20,
                inventory_completeness="not_established",
                source_url=family["source_url"],
            )
        )
    unmapped = {
        vendor: sum(
            not any(f["vendor"] == vendor and matches(f, a) for f in catalog["families"])
            for r in data["records"]
            if r["vendor"] == vendor and r.get("document_status") != "draft"
            for a in r["assessments"]
        )
        for vendor in data["vendors"]
    }
    return dict(
        schema_version=1,
        catalogue_version=catalog["catalogue_version"],
        scope="whole_publication",
        families=rows,
        unmapped_statements=unmapped,
        method=catalog["scope"]
        + " Unknown means no matching retained non-draft product statement, not unaffectedness. A referenced release line is not a complete train inventory. Mixed platform classes are not split. Vendor-wide errors may affect any family; per-family absence is not proven. Evidence examples are bounded to twenty sources.",
    )
