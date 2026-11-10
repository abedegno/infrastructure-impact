"""Apply only bundled, finite reviewed source-section fix derivations."""

import copy
import hashlib

from .. import remediation_bindings as registry
from .common import availability


def arista_assessments(tree, parsed, slug):
    """Read finite CVE-owned direct marker/list clauses, preserving affected evidence.

    The complete normalized Resolution (including separate hotfix text) is pinned.
    Only direct marker/list pairs before the explicit Hotfix boundary own EOS fixes.
    Neither wrapper bytes nor sorted CVE positions establish ownership.
    """
    from .common import Node, assessment

    sources = [
        s
        for s in registry.definition()["sources"]
        if s["kind"] == "arista_marker_list" and s["advisory_id"] == slug
    ]
    if not sources:
        return [], []
    source = sources[0]
    drift = ([], ["reviewed_fix_source_drift"])
    if (
        parsed.get("vendor") != source["vendor"]
        or parsed.get("advisory_id") != slug
        or parsed.get("source_url") != source["source_url"]
        or parsed.get("source_format") != source["source_format"]
        or sorted(parsed.get("cves", [])) != sorted(source["expected_cve_ids"])
    ):
        return drift
    articles = [n for n in tree.find({"div"}) if "item-page" in n.attrs.get("class", "").split()]
    if len(articles) != 1:
        return drift
    # Raw visible qualifications must not vanish when selecting sibling nodes.
    if any(isinstance(n, str) and n.strip() for n in articles[0].children):
        return drift
    nodes = [n for n in articles[0].children if isinstance(n, Node)]
    starts = [i for i, n in enumerate(nodes) if n.tag in {"h2", "h3"} and n.text() == "Resolution"]
    if len(starts) != 1:
        return drift
    start = starts[0]
    end = next(
        (
            i
            for i in range(start + 1, len(nodes))
            if nodes[i].tag in {"h2", "h3", "h4"}
            and (nodes[i].tag <= nodes[start].tag or nodes[i].text() == "For More Information")
        ),
        len(nodes),
    )
    resolution = " ".join(n.text() for n in nodes[start:end] if n.text())
    if hashlib.sha256(resolution.encode("utf-8")).hexdigest() != source["resolution_sha256"]:
        return drift
    hotfix = [
        i for i in range(start + 1, end) if nodes[i].tag == "h3" and nodes[i].text() == "Hotfix"
    ]
    if source["source_format"] == "Arista reviewed reconciliation software HTML":
        if len(hotfix) != 1:
            return drift
        owned_end = hotfix[0]
    else:
        if hotfix or end == len(nodes) or nodes[end].text() != "For More Information":
            return drift
        owned_end = end
    fixed, owned_lists = [], []
    for rule in source["bindings"]:
        affected = [
            a
            for a in parsed["assessments"]
            if a["cve_id"] == rule["cve_id"]
            and a["product"] == rule["affected_product"]
            and a["status"] == "affected"
            and a["scope"] == "cve_specific"
            and a["evidence_locator"] == rule["affected_locator"]
            and [v.get("expression") for v in a["versions"]] == rule["affected_versions"]
        ]
        markers = [
            i
            for i in range(start + 1, owned_end)
            if nodes[i].tag == "div" and nodes[i].text() == rule["statement"]
        ]
        if len(affected) != 1 or len(markers) != 1:
            return drift
        marker = nodes[markers[0]]
        if (
            marker.attrs
            or any(isinstance(c, Node) for c in marker.children)
            or markers[0] + 1 >= owned_end
        ):
            return drift
        listing = nodes[markers[0] + 1]
        items = [c for c in listing.children if isinstance(c, Node)]
        if (
            listing.tag != "ul"
            or listing.attrs
            or any(isinstance(c, str) and c.strip() for c in listing.children)
            or any(
                c.tag != "li" or c.attrs or any(isinstance(n, Node) for n in c.children)
                for c in items
            )
        ):
            return drift
        versions = [c.text() for c in items]
        clause = " ".join([marker.text(), *versions])
        if (
            versions != rule["fixed_versions"]
            or hashlib.sha256(clause.encode("utf-8")).hexdigest() != rule["clause_sha256"]
        ):
            return drift
        owned_lists.append(listing)
        fixed.append(
            assessment(
                rule["cve_id"],
                rule["fixed_product"],
                "fixed",
                rule["fixed_locator"],
                [dict(expression=v) for v in versions],
                [
                    dict(
                        category="vendor_fix",
                        availability="vendor_reports_fixed",
                        details=marker.text(),
                        source_locator=rule["remediation_locator"],
                    )
                ],
            )
        )
    if [n for n in nodes[start + 1 : owned_end] if n.tag in {"ul", "ol"}] != [
        n for n in nodes[start + 1 : owned_end] if n in owned_lists
    ]:
        return drift
    return fixed, []


def _pointer(data, locator):
    for key in locator.strip("/").split("/"):
        data = data[int(key)] if isinstance(data, list) else data[key]
    return data


def attach_links(claims):
    """Copy an owned original fix onto each exact reviewed affected tuple."""
    for claim in claims:
        rule = registry.rule_for(claim)
        if rule is None or "evidence_text_truncated" in claim.get("issues", []):
            continue
        siblings = registry.fixed_siblings(claim, rule, claims)
        if len(siblings) != 1:
            continue
        originals = [
            rem
            for rem in siblings[0]["remediations"]
            if registry.owned_remediation(siblings[0], rem, rule)
        ]
        if len(originals) != 1:
            continue
        bound = copy.deepcopy(originals[0])
        bound["product_ids"] = []
        bound["version_expressions"] = rule["fixed_versions"][:]
        binding = dict(
            basis="reviewed_source_sections",
            cve_id=claim["cve_id"],
            source=claim["source"].copy(),
            fixed_product=rule["fixed_product"],
            fixed_source=siblings[0]["source"].copy(),
        )
        if rule["fixed_product_id"] is not None:
            binding["fixed_product_id"] = rule["fixed_product_id"]
        bound["scope_binding"] = binding
        registry.validate_link(claim, bound, binding, claims)
        if bound not in claim["remediations"]:
            claim["remediations"].append(bound)


def apply_csaf(data, claims, url, digest, as_of):
    """Upgrade original fixed availability only after source, parent and proof checks.

    Return bounded diagnostic codes. A drift never removes existing affected claims
    or directly scoped remediations. No validation result is cached.
    """
    advisory_id = data.get("document", {}).get("tracking", {}).get("id")
    sources = [
        s
        for s in registry.definition()["sources"]
        if s["kind"] == "csaf"
        and s["advisory_id"] == advisory_id
        and any(c["vendor"] == s["vendor"] and c["advisory_id"] == advisory_id for c in claims)
    ]
    if not sources:
        return []
    source = sources[0]
    try:
        parent = _pointer(data, source["product_parent"]["locator"])
        parent_ok = all(parent.get(k) == source["product_parent"][k] for k in ("category", "name"))
    except (KeyError, IndexError, TypeError, ValueError):
        parent_ok = False
    cves = [v.get("cve") for v in data.get("vulnerabilities", [])]
    if (
        url != source["source_url"]
        or digest != source["source_sha256"]
        or not parent_ok
        or sorted(cves) != sorted(source["expected_cve_ids"])
    ):
        return ["reviewed_fix_source_drift"]
    drift = False
    for claim in claims:
        rule = registry.rule_for(claim)
        if rule is None:
            continue
        siblings = registry.fixed_siblings(claim, rule, claims)
        if len(siblings) != 1:
            drift = True
            continue
        originals = [
            rem
            for rem in siblings[0]["remediations"]
            if registry.owned_remediation(siblings[0], rem, rule, released=False, as_of=as_of)
        ]
        if len(originals) != 1:
            drift = True
            continue
        rem = originals[0]
        # Literal owner proves availability; shared category/date/future guards remain.
        state = availability(
            "\n".join(rule["availability_proof_literals"]),
            rem["category"],
            rem["availability_date"],
            as_of=as_of,
        )
        if state == "vendor_reports_fixed":
            rem["availability"] = state
        else:
            drift = True
    attach_links(claims)
    return ["reviewed_fix_source_drift"] if drift else []
