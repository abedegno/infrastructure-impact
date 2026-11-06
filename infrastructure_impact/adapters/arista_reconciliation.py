"""Exact reviewed SA-0099/0103 HTML scopes; no cross-representation CVE aliases."""

import re

from .arista_scoped import article
from .common import Node, assessment, cves

PREFIX = "https://www.arista.com/en/support/advisories-notices/security-advisory/"
URL99 = PREFIX + "19862-security-advisory-0099"
URL103 = PREFIX + "19917-security-advisory-0103"
CSAF103 = "https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_103.json"
CSAF103_ID = "Arista Networks Security Advisory 103"
FORMAT = "Arista reviewed reconciliation software HTML"
ROUTES = {
    URL99: ("0099", ["CVE-2024-27890", "CVE-2024-27892"]),
    URL103: ("0103", ["CVE-2024-6858"]),
}


def inline(node):
    if node.attrs:
        raise ValueError("Unreviewed Arista software markup")
    if any(isinstance(c, Node) and c.tag not in {"b", "strong", "br"} for c in node.children):
        raise ValueError("Nested Arista software scope")
    for child in node.children:
        if isinstance(child, Node):
            inline(child)
    return node.text()


def versions(node):
    children = [c for c in node.children if isinstance(c, Node)]
    if (
        node.tag != "ul"
        or node.attrs
        or not children
        or any(c.tag != "li" for c in children)
        or any(isinstance(c, str) and c.strip() for c in node.children)
    ):
        raise ValueError("Unbound Arista version list")
    values = [inline(c) for c in children]
    if len(values) != len(set(values)) or any(
        not re.fullmatch(
            r"4\.\d+\.\d+(?:\.\d+)?[MF] and below releases in the 4\.\d+\.x train\.?", v
        )
        for v in values
    ):
        raise ValueError("Unreviewed Arista EOS version expression")
    return [{"expression": v} for v in values]


def parse(raw, url, vendor):
    if vendor != "arista" or url not in ROUTES:
        raise ValueError("Unreviewed Arista reconciliation route")
    number, ids = ROUTES[url]
    a, out = article(raw, url, number)
    headings = [n for n in a.find({"h2"}) if n.text().startswith("Security Advisory ")]
    if (
        len(headings) != 1
        or " ".join(" ".join(c for c in headings[0].children if isinstance(c, str)).split())
        != "Security Advisory " + number
    ):
        raise ValueError("Reviewed Arista advisory identity changed")
    # Only direct tracking paragraphs before Description define header scope.
    # Other CVE mentions (including navigation and description) cannot bind lists.
    header_ids, sections = [], {}
    current = None
    for node in a.children:
        if not isinstance(node, Node):
            if node.strip():
                raise ValueError("Unreviewed Arista article text boundary")
            continue
        if node.tag in {"h2", "h3", "h4"}:
            current = node.text()
            if current in sections:
                raise ValueError("Repeated Arista section")
            sections[current] = []
        elif current:
            if node.text():
                sections[current].append(node)
        elif node.tag == "p" and node.text().startswith("The CVE-ID tracking this issue:"):
            header_ids.extend(cves(node.text()))
    if sorted(header_ids) != ids or not sections.get("Description"):
        raise ValueError("Reviewed Arista tracking header changed")
    context = []
    for name in ("Affected Platforms", "Required Configuration for Exploitation"):
        if not sections.get(name):
            raise ValueError("Reviewed Arista applicability qualification missing")
        context.append(
            dict(
                category="publisher_applicability",
                details="\n".join(n.text() for n in sections[name]),
                source_scope="advisory_context_requires_product_configuration_review",
                source_locator=name,
            )
        )
    software = sections.get("Affected Software", [])
    width = 3 if number == "0099" else 2
    if len(software) != width * len(ids):
        raise ValueError("Unbound Arista software group or section boundary")
    seen = set()
    for offset in range(0, len(software), width):
        group = software[offset : offset + width]
        if number == "0099":
            marker = group.pop(0)
            match = re.fullmatch(
                r"The following EOS versions are affected for (CVE-\d{4}-\d{4,})", inline(marker)
            )
            if marker.tag != "p" or not match or match[1] not in ids:
                raise ValueError("Unreviewed Arista local CVE group")
            cid = match[1]
        else:
            cid = ids[0]
        if cid in seen or group[0].tag != "div" or inline(group[0]) != "EOS Versions":
            raise ValueError("Repeated or unbound Arista product group")
        seen.add(cid)
        claim = assessment(
            cid,
            "Arista EOS",
            "affected",
            "Affected Software / " + cid + " / EOS Versions",
            versions(group[1]),
        )
        claim["exposure"] = context
        out["assessments"].append(claim)
    if seen != set(ids):
        raise ValueError("Missing Arista local CVE group")
    out.update(cves=ids.copy(), source_format=FORMAT, document_status="published")
    out["warnings"] = [
        "Only article-local tracking and affected EOS lists are normalized. Platform and configuration qualifications remain publisher context requiring review; no hardware applicability or remediation is inferred. Other representations cannot rename these CVEs or supply their fixed versions."
    ]
    return out
