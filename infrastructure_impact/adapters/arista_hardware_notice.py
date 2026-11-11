"""Exact SA-0226 CVA-table identities and shared EOS hardware exclusions."""

import re
from urllib.parse import urlsplit

from .arista_current_scope import inline, leaves
from .arista_legacy_scope import children, one
from .arista_scoped import article
from .common import assessment, cves

PREFIX = "https://www.arista.com/en/support/advisories-notices/security-advisory/"
SLUG = "25048-security-advisory-0226"
FORMAT = "Arista reviewed hardware notice HTML"
MARKER = "The following product versions and platforms are not affected by this vulnerability:"
CVA = "CloudVision Appliance (CVA)"
RESOLVED = "CVEs Resolved by upgrading to CVA 7.2.0"
DMF = "Danz Monitoring Fabric (DMF) Appliances"
AGNI = "Arista Guardian for Network Identity (AGNI) Appliance"


def safe(node):
    """Check selected evidence and its ancestors; page chrome is not evidence."""
    nodes = [node, *walk(node)]
    ancestor = node.parent
    while ancestor is not None:
        nodes.append(ancestor)
        ancestor = ancestor.parent
    for n in nodes:
        style = re.sub(r"\s+", "", (n.attrs.get("style") or "").lower())
        if (
            n.tag
            in {
                "script",
                "style",
                "iframe",
                "object",
                "embed",
                "template",
                "svg",
                "math",
                "img",
                "input",
            }
            or any(k.lower().startswith("on") and v for k, v in n.attrs.items())
            or "hidden" in n.attrs
            or n.attrs.get("aria-hidden") == "true"
            or "display:none" in style
            or "visibility:hidden" in style
            or (n.tag == "a" and urlsplit(n.attrs.get("href") or "").scheme not in {"", "https"})
        ):
            raise ValueError("Active or concealed Arista hardware evidence")


def walk(node):
    for child in children(node):
        yield child
        yield from walk(child)


def plain(node):
    safe(node)
    if any(n.tag not in {"b", "strong", "br"} for n in walk(node)):
        raise ValueError("Nested Arista hardware table cell")
    if any(k not in {"class"} for n in [node, *walk(node)] for k in n.attrs):
        raise ValueError("Unreviewed Arista hardware cell attributes")
    return node.text()


def rows(table):
    safe(table)
    containers = [table]
    contents = children(table)
    if len(contents) == 1 and contents[0].tag == "tbody":
        containers.append(contents[0])
        contents = children(contents[0])
    if not contents or any(n.tag != "tr" for n in contents):
        raise ValueError("Arista hardware table structure changed")
    if any(isinstance(c, str) and c.strip() for n in containers for c in n.children):
        raise ValueError("Unbound Arista hardware table content")
    result = []
    for row in contents:
        cells = children(row)
        if any(n.tag not in {"td", "th"} for n in cells) or not cells:
            raise ValueError("Arista hardware table row changed")
        if any(isinstance(c, str) and c.strip() for n in [table, row] for c in n.children):
            raise ValueError("Unbound Arista hardware table content")
        result.append([plain(c) for c in cells])
    return result


def parse(raw, url, vendor):
    if vendor != "arista" or url != PREFIX + SLUG:
        raise ValueError("Unreviewed Arista hardware notice route")
    a, out = article(raw, url, "0226")
    heading = one(
        (n for n in a.find({"h2"}) if n.text().startswith("Security Advisory ")), "hardware title"
    )
    safe(heading)
    if heading.text() not in {"Security Advisory 0226", "Security Advisory 0226 PDF"}:
        raise ValueError("Arista hardware notice title changed")
    nodes = children(a)
    sections = {}
    current = None
    preamble = []
    for n in nodes:
        if n.tag == "h2":
            current = n.text()
            if current in sections:
                raise ValueError("Repeated Arista hardware section")
            sections[current] = []
        elif current is not None:
            sections[current].append(n)
        else:
            preamble.append(n)
    if list(sections) != [
        "Description",
        "Vulnerability Assessment",
        "Required Configuration for Exploitation",
        "Indicators of Compromise",
        "Mitigation",
        "Resolution",
    ]:
        raise ValueError("Arista hardware notice section boundaries changed")
    revisions = one((n for n in preamble if n.tag == "table"), "hardware revision table")
    if rows(revisions) != [
        ["Revision", "Date", "Changes"],
        ["1.0", "November 10, 2026", "Initial release"],
    ]:
        raise ValueError("Arista hardware notice revision changed")
    out.update(
        source_format=FORMAT,
        document_status="published",
        updated_at="2026-11-10",
        timeline=[dict(number="1.0", date="2026-11-10", summary="Initial release")],
    )
    platform = [n for n in sections["Vulnerability Assessment"] if n.text()]
    for n in platform:
        safe(n)
    if not platform or platform[0].tag != "h3" or plain(platform[0]) != "Affected Platforms":
        raise ValueError("Arista hardware affected-platform boundary changed")
    if [(n.tag, n.text()) for n in platform if n.tag in {"h3", "h4"}] != [
        ("h3", "Affected Platforms"),
        ("h4", CVA),
        ("h4", RESOLVED),
        ("h4", DMF),
        ("h4", AGNI),
    ]:
        raise ValueError("Arista CVA table ownership headings changed")
    positions = [
        next(i for i, n in enumerate(platform) if n.tag == "h4" and n.text() == text)
        for text in [CVA, RESOLVED, DMF, AGNI]
    ]
    cva, resolved, dmf, agni = positions
    if any(n.tag != "p" for n in platform[1:cva]) or not platform[1:cva]:
        raise ValueError("Arista server hardware context changed")
    local = platform[cva + 1 : resolved]
    if [n.tag for n in local] != ["p", "ul", "p"] or leaves(local[1]) != [
        "DCA-250-CV",
        "DCA-300-CV",
        "DCA-350E-CV",
    ]:
        raise ValueError("Arista CVA hardware list changed")
    tables = platform[resolved + 1 : dmf]
    if [n.tag for n in tables] != ["table", "table"]:
        raise ValueError("Arista CVA CVE table boundary changed")
    owned = []
    for table, owner in zip(tables, ["DCA-250-CV", "DCA-300-CV, DCA-350E-CV"]):
        values = rows(table)
        if values[0] != ["CVE", owner] or not 2 <= len(values) <= 101:
            raise ValueError("Arista owned CVA CVE table header or row bounds changed")
        ids = []
        for row in values[1:]:
            if len(row) != 2 or cves(row[0]) != [row[0]] or row[1] != "X" or row[0] in ids:
                raise ValueError("Arista owned CVA CVE identity or marker changed")
            ids.append(row[0])
        owned.append(ids)
    if not set(owned[0]) <= set(owned[1]):
        raise ValueError("Arista CVA table identity relationship changed")
    out["cves"] = sorted(set(owned[0] + owned[1]))
    # OEM mapping tables supply context only, never CVE-to-EOS assignments.
    group = platform[dmf + 1 : agni]
    if [n.tag for n in group] != ["p", "table"] or rows(group[1])[0] != [
        "DMF SKU",
        "OEM Product Name",
    ]:
        raise ValueError("Arista OEM mapping ownership changed")
    tail = platform[agni + 1 :]
    if (
        [n.tag for n in tail] != ["p", "table", "div", "ul"]
        or rows(tail[1])[0] != ["AGNI SKU", "OEM Product Name"]
        or inline(tail[2]) != MARKER
    ):
        raise ValueError("Arista EOS exclusion ownership changed")
    outer = tail[3]
    if outer.attrs or any(isinstance(c, str) and c.strip() for c in outer.children):
        raise ValueError("Unreviewed outer Arista exclusion qualifier")
    exclusions = children(outer)
    if (
        len(exclusions) < 3
        or [n.tag for n in exclusions[:2]] != ["li", "ul"]
        or inline(exclusions[0]) != "Arista EOS-based products:"
    ):
        raise ValueError("Arista EOS sibling-list boundary changed")
    platforms = leaves(exclusions[1])
    # A second reviewed sibling list belongs to CVA hardware, not EOS.
    previous = None
    for n in exclusions[2:]:
        if n.tag == "li":
            previous = inline(n)
        elif n.tag == "ul" and previous == "CloudVision Appliance":
            if leaves(n) != ["DCA-400-CV", "DCA-450-CV"]:
                raise ValueError("Arista separate appliance exclusion changed")
            previous = None
        else:
            raise ValueError("Unbound Arista non-EOS exclusion")
    if sum(n.text() == MARKER for n in a.find({"div"})) != 1:
        raise ValueError("Repeated Arista exclusion marker")
    locator = (
        "Affected Platforms / CVA CVE tables / shared not affected / Arista EOS-based products"
    )
    for cid in out["cves"]:
        claim = assessment(cid, "Arista EOS", "unaffected", locator, scope="bulletin_shared")
        claim["platforms"] = platforms[:]
        out["assessments"].append(claim)
    # Context is retained without attaching server prerequisites/fixes to EOS.
    resolution = sections["Resolution"]
    stop = next(
        (
            i
            for i, n in enumerate(resolution)
            if n.tag == "h3" and n.text() == "For More Information"
        ),
        None,
    )
    if stop is None:
        raise ValueError("Arista hardware resolution end boundary changed")
    resolution = [n for n in resolution[:stop] if n.text()]
    firmware = one(
        (n for n in resolution if n.tag == "h4" and n.text() == "Recommended Firmware Versions"),
        "firmware context heading",
    )
    index = resolution.index(firmware)
    if index + 1 >= len(resolution) or resolution[index + 1].tag != "table":
        raise ValueError("Arista firmware context table boundary changed")
    firmware_rows = rows(resolution[index + 1])
    if (
        firmware_rows[0] != ["SKU", "BIOS", "iDRAC"]
        or any(len(row) != 3 for row in firmware_rows[1:])
        or "DCA-350-CV" not in [row[0] for row in firmware_rows[1:]]
        or "DCA-350E-CV" in [row[0] for row in firmware_rows[1:]]
    ):
        raise ValueError("Arista recorded firmware SKU discrepancy changed")
    contexts = {**sections, "Resolution": resolution}
    for name, content in contexts.items():
        for n in content:
            safe(n)
        out["notes"].append(
            dict(
                category="publisher_context",
                text="\n".join(n.text() for n in content if n.text()),
                source_locator=name,
            )
        )
    out["warnings"] = [
        "Only the two owned CVA CVE tables supply identities for bulletin-shared EOS-unaffected context. No CVA/OEM/DMF/AGNI affected or fixed assessments, EOS fixes, release dates or configuration conditions are inferred.",
        "Only literally listed EOS platforms are excluded; omitted platforms remain unknown. Slash labels stay unresolved; 750X is not 750 and no automatic model binding is established.",
        "Publisher SKU discrepancy: applicability/CVA tables name DCA-350E-CV while Recommended Firmware Versions names DCA-350-CV. These labels are not reconciled.",
    ]
    return out
