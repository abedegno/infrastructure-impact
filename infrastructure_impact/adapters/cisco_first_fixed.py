"""Bounded extraction of explicitly owned Cisco IOS XE Fixed Releases tables.

Facts inherit their enclosing advisory's source receipt and revision metadata.
This parser neither orders releases nor assigns table rows to product IDs.
"""

import re

_HEADER = "Cisco IOS XE Software Release First Fixed Release"
_OWNERSHIP = (
    "The right column indicates whether a release is affected by the vulnerabilities "
    "that are described in this advisory and the first release that includes the fix "
    "for these vulnerabilities."
)
_END = (
    "The Cisco Product Security Incident Response Team (PSIRT) validates only "
    "the affected and fixed release information that is documented in this advisory."
)


def _resolved_products(tree):
    """Bound source graph shape, then reuse the core CSAF ambiguity boundary."""
    if not isinstance(tree, dict):
        return None

    def product_shape(product):
        return isinstance(product, dict) and all(
            isinstance(product.get(k), str) and product[k] for k in ("product_id", "name")
        )

    branches = tree.get("branches", [])
    flat = tree.get("full_product_names", [])
    relationships = tree.get("relationships", [])
    if not all(isinstance(rows, list) for rows in (branches, flat, relationships)):
        return None
    visited = len(flat) + len(relationships)
    if visited + len(branches) > 20000 or not all(product_shape(p) for p in flat):
        return None
    for relationship in relationships:
        if not isinstance(relationship, dict) or not product_shape(
            relationship.get("full_product_name")
        ):
            return None
        if any(
            not isinstance(relationship.get(k, ""), str)
            for k in ("category", "product_reference", "relates_to_product_reference")
        ):
            return None
    stack = [(branch, 0) for branch in branches]
    while stack:
        branch, depth = stack.pop()
        visited += 1
        if visited > 20000 or depth > 128 or not isinstance(branch, dict):
            return None
        if any(not isinstance(branch.get(k, ""), str) for k in ("category", "name")):
            return None
        if "product" in branch and not product_shape(branch["product"]):
            return None
        children = branch.get("branches", [])
        if not isinstance(children, list) or visited + len(stack) + len(children) > 20000:
            return None
        stack.extend((child, depth + 1) for child in children)
    # Lazy import avoids a standards -> table parser -> standards import cycle.
    # All product namespaces, duplicate definitions and relationship resolution
    # must agree with the existing assessment resolver.
    from .standards import csaf_products

    try:
        return csaf_products(tree)
    except RecursionError:
        return None  # Excessive relationship depth/cycles cannot establish scope.


def _owners(data):
    """Require every reviewed CVE product-reference path to resolve to IOS XE."""
    tree = data.get("product_tree", {})
    products = _resolved_products(tree)
    if products is None:
        return None
    groups = tree.get("product_groups", [])
    if not isinstance(groups, list) or len(groups) > 1000:
        return None
    by_group = {}
    for group in groups:
        if isinstance(group, dict) and isinstance(group.get("group_id"), str):
            by_group.setdefault(group["group_id"], []).append(group)
    references = 0

    def product_refs(values):
        nonlocal references
        if not isinstance(values, list):
            return False
        references += len(values)
        if references > 20000:
            return False
        for pid in values:
            if not isinstance(pid, str):
                return False
            product = products.get(pid)
            if product is None or product.get("issues"):
                return False
            family = next(
                (
                    name
                    for category, name in reversed(product["ancestry"])
                    if category in {"product_family", "product_name"}
                ),
                None,
            )
            if family != "Cisco IOS XE Software":
                return False
        return True

    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities or len(vulnerabilities) > 1000:
        return None
    owners = []
    scoped_rows = 0
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            return None
        cid = entry.get("cve")
        if not isinstance(cid, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cid):
            return None
        statuses = entry.get("product_status", {})
        if not isinstance(statuses, dict) or not statuses:
            return None
        if not all(product_refs(values) for values in statuses.values()) or not any(
            statuses.values()
        ):
            return None
        for collection, product_field in (
            ("remediations", "product_ids"),
            ("threats", "product_ids"),
            ("flags", "product_ids"),
            ("scores", "products"),
        ):
            rows = entry.get(collection, [])
            if not isinstance(rows, list):
                return None
            scoped_rows += len(rows)
            if scoped_rows > 20000:
                return None
            for row in rows:
                if not isinstance(row, dict) or not product_refs(row.get(product_field, [])):
                    return None
                group_ids = row.get("group_ids", []) if collection != "scores" else []
                if not isinstance(group_ids, list):
                    return None
                references += len(group_ids)
                if references > 20000:
                    return None
                for gid in group_ids:
                    if not isinstance(gid, str):
                        return None
                    matches = by_group.get(gid, [])
                    if len(matches) != 1:
                        return None
                    members = matches[0].get("product_ids")
                    if not members or not product_refs(members):
                        return None
        if cid in owners:
            return None
        owners.append(cid)
    return sorted(owners)


def extract_cisco_first_fixed(data: dict) -> dict:
    """Return source facts and bounded diagnostics; no IO or environment access."""

    def rejected(reason):
        return {"first_fixed": [], "issues": ["Cisco first-fixed: " + reason]}

    if not isinstance(data, dict) or not isinstance(data.get("document"), dict):
        return rejected("unsupported document")
    notes = data["document"].get("notes", [])
    if not isinstance(notes, list) or len(notes) > 100:
        return rejected("unsupported document notes")
    selected = [
        (i, n)
        for i, n in enumerate(notes)
        if isinstance(n, dict) and n.get("title") == "Fixed Software"
    ]
    if len(selected) != 1:
        return rejected("one owned Fixed Software note required")
    index, note = selected[0]
    text = note.get("text")
    if note.get("category") != "general" or not isinstance(text, str) or len(text) > 131072:
        return rejected("unsupported Fixed Software note")
    title = data["document"].get("title", "")
    if not isinstance(title, str) or len(title) > 8192:
        return rejected("unsupported document title")
    if re.search(
        r"\b(?:UTD|Unified\s+Threat\s+Defense|WLC|Wireless\s+(?:LAN\s+)?Controller|ROMMON)\b",
        title + " " + text,
        re.I,
    ):
        return rejected("qualified IOS XE scope requires product-specific interpretation")
    # Normalize whitespace for recognition only. Row splitting still uses
    # the original two-column separators; a descriptive locator names the row.
    normalized = " ".join(text.split())
    if (
        normalized.count("Fixed Releases") != 1
        or normalized.count(_HEADER) != 1
        or normalized.count(_END) != 1
        or _OWNERSHIP not in normalized
    ):
        return rejected("table heading, ownership, header or PSIRT boundary unresolved")
    heading = normalized.index("Fixed Releases")
    header = normalized.index(_HEADER)
    end = normalized.index(_END)
    if not heading < header < end or _OWNERSHIP not in normalized[heading:header]:
        return rejected("table boundaries out of order")
    owners = _owners(data)
    if not owners:
        return rejected("CVE/product ownership is mixed or unresolved")
    header_match = re.search(
        r"Cisco\s+IOS\s+XE\s+Software\s+Release\s+First\s+Fixed\s+Release", text
    )
    end_match = re.search(r"\s+".join(map(re.escape, _END.split())), text)
    body = text[header_match.end() : end_match.start()].strip()
    cells = re.split(r"\s{2,}", body)
    if not cells or len(cells) % 2 or len(cells) > 200:
        return rejected("malformed or oversized table rows")
    facts, issues, seen = [], [], set()
    for expression, value in zip(cells[::2], cells[1::2]):
        expression, value = expression.strip(), value.strip()
        if expression in seen:
            return rejected("duplicate train row")
        seen.add(expression)
        if expression == "17.8 and earlier" and value == "Migrate to a fixed release.":
            train, fixed, disposition = None, [], "migrate"
        elif re.fullmatch(r"[0-9]+\.[0-9]+", expression):
            train = expression
            fixed = [v.strip() for v in value.split(",")]
            if (
                len(fixed) > 20
                or not all(
                    re.fullmatch(r"[^\s,]{1,128}", v) and v[0].isdecimal() and "." in v
                    for v in fixed
                )
                or len(set(fixed)) != len(fixed)
            ):
                return rejected("malformed fixed release alternatives")
            if any(
                ".".join(v.split(".")[:2]) != train
                for v in fixed
                if re.fullmatch(r"[0-9]+\.[0-9]+\.[^\s]+", v)
            ):
                return rejected("fixed release outside row train")
            disposition = "fixed"
            if any(not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[abc]?", v) for v in fixed):
                issues.append(f"Cisco first-fixed: unsupported ordering literal at train {train}")
        else:
            return rejected("unsupported train or disposition")
        facts.append(
            {
                "method": "stated_table",
                "evidence_state": "publisher_stated",
                "scope": "bulletin_shared" if len(owners) > 1 else "cve_specific",
                "cve_ids": owners.copy(),
                "family": "cisco-iosxe",
                "product": None,
                "product_ids": None,
                "train": train,
                "train_expression": expression,
                "fixed_versions": fixed,
                "disposition": disposition,
                "source_locator": f"/document/notes/{index}/text / Fixed Releases / row[train={expression}]",
            }
        )
    return {"first_fixed": facts, "issues": issues}
