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


def _owners(data):
    """Resolve every encoded vulnerability product to the single table family."""
    tree = data.get("product_tree", {})
    if not isinstance(tree, dict) or not isinstance(tree.get("branches", []), list):
        return None
    products = {}
    stack = [(b, None) for b in tree.get("branches", [])]
    visited = 0
    while stack:
        branch, family = stack.pop()
        visited += 1
        if visited > 20000 or not isinstance(branch, dict):
            return None
        if branch.get("category") in {"product_family", "product_name"}:
            family = branch.get("name")
        product = branch.get("product")
        if product:
            if not isinstance(product, dict):
                return None
            pid = product.get("product_id")
            if not isinstance(pid, str) or not pid or pid in products:
                return None
            products[pid] = family
        branches = branch.get("branches", [])
        if not isinstance(branches, list) or len(stack) + len(branches) > 20000:
            return None
        stack.extend((b, family) for b in branches)
    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities or len(vulnerabilities) > 1000:
        return None
    owners = []
    references = 0
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            return None
        cid = entry.get("cve")
        if not isinstance(cid, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cid):
            return None
        statuses = entry.get("product_status", {})
        if not isinstance(statuses, dict) or not statuses:
            return None
        ids = []
        for values in statuses.values():
            if not isinstance(values, list):
                return None
            references += len(values)
            if references > 20000 or any(not isinstance(pid, str) for pid in values):
                return None
            ids.extend(values)
        if not ids or any(products.get(pid) != "Cisco IOS XE Software" for pid in ids):
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
