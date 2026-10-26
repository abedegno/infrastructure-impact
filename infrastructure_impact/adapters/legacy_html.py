"""Reviewed legacy html source normalization."""

import re
from datetime import datetime
from urllib.parse import urlsplit

from .common import HTML, Node, availability, base, cves, iso_date


def html_advisory(raw, url, vendor):
    """Fallback for two known publisher layouts. Fail closed on unknown sections."""
    tree = HTML(raw).root
    headings = list(tree.find({"h1", "h2", "h3", "h4"}))
    wanted = next(
        (
            h
            for h in headings
            if ("Security Advisory " in h.text() if vendor == "arista" else h.tag == "h1")
        ),
        None,
    )
    if wanted is None:
        raise ValueError("Expected advisory title missing")
    # Content is collected in source order after a known advisory heading.
    nodes = list(tree.find({"h1", "h2", "h3", "h4", "p", "li", "tr"}))
    start = nodes.index(wanted)
    content = nodes[start:]
    title = wanted.text()
    out = base(vendor, url, urlsplit(url).path.rstrip("/").split("/")[-1], title)
    out["source_format"] = "Vendor HTML"
    out["document_status"] = "published"
    text = " ".join(n.text() for n in content)
    out["cves"] = cves(text)
    out["warnings"].append(
        "HTML extraction; raw vendor expressions retained. No automatic version comparison."
    )
    if vendor == "cisco":
        # Limit CVE scope to header/summary; references/footer must not expand it.
        summary = text.split("Affected Products")[0]
        out["cves"] = cves(summary)
        explicit_scope = re.search(r"This advisory covers\s+(CVE-\d{4}-\d+)\s+only", summary, re.I)
        if explicit_scope:
            out["cves"] = [explicit_scope[1].upper()]
            out["warnings"].append(
                "Other CVEs mentioned in background are excluded by the publisher's explicit single-CVE scope."
            )
        for label, key in [("First Published", "published_at"), ("Last Updated", "updated_at")]:
            match = re.search(
                label + r"\s*:?\s*(\d{4}\s+[A-Za-z]+\s+\d{1,2}\s+\d{2}:\d{2})", tree.text()
            )
            if match:
                out[key] = datetime.strptime(match[1], "%Y %B %d %H:%M").isoformat() + "Z"
    else:
        match = re.search(r"Date:\s*([A-Za-z]+\s+\d{1,2}(?:st|nd|rd|th)?,\s*\d{4})", text)
        if match:
            out["updated_at"] = iso_date(match[1])
        # Revision rows identify original publication independently of page date.
        for n in content:
            if n.tag == "tr":
                cells = [c.text() for c in n.find({"td", "th"})]
                if len(cells) >= 3 and re.match(r"\d+\.\d+", cells[0]):
                    out["timeline"].append(
                        {"number": cells[0], "date": iso_date(cells[1]), "summary": cells[2]}
                    )
        initial = next((t for t in out["timeline"] if t["number"] == "1.0"), None)
        out["published_at"] = initial["date"] if initial else None
    state, section = None, ""
    for n in content:
        t = n.text()
        if n.tag in {"h1", "h2", "h3", "h4"}:
            if vendor == "arista" and section == "Vulnerability Assessment" and n.tag == "h4":
                if "NOT affected" in t:
                    state = "unaffected"
                elif "following products are affected by" in t:
                    state, ids = "affected", cves(t)
                else:
                    state = None
                continue
            section = t
            if vendor == "cisco":
                state = {
                    "Products Under Investigation": "investigating",
                    "Vulnerable Products": "affected",
                    "Products Confirmed Not Vulnerable": "unaffected",
                }.get(t)
            continue
        if n.tag == "p" and section in (
            "Summary",
            "Description",
            "Vulnerability Assessment",
            "Vulnerable Products",
            "Required Configuration for Exploitation",
            "Workarounds",
            "Fixed Software",
            "Patches and Mitigation Instructions",
        ):
            out["notes"].append({"category": "bulletin_context", "title": section, "text": t})
        if vendor == "cisco" and state and n.tag in {"li", "tr"}:
            if n.tag == "tr":
                cells = [x.text() for x in n.find({"td"})]
                if (
                    not cells
                    or (state == "affected" and len(cells) < 2)
                    or "Cisco Product" in cells[0]
                    or "Cisco Bug ID" in t
                ):
                    continue
                product = cells[0]
                if len(product) < 3:
                    continue
                details = cells[-1]
                rem = (
                    [
                        {
                            "category": "vendor_fix",
                            "details": details,
                            "availability": availability(details, "vendor_fix"),
                        }
                    ]
                    if state == "affected"
                    else []
                )
            else:
                if list(n.find({"li"})):
                    continue
                product = t
                rem = []
            if len(product) > 160 or product.lower().startswith(
                ("cisco is ", "cisco has ", "the following", "for ")
            ):
                continue
            for cid in out["cves"]:
                out["assessments"].append(
                    {
                        "cve_id": cid,
                        "product_id": product,
                        "product": product,
                        "status": state,
                        "scope": "bulletin_shared",
                        "versions": [],
                        "remediations": rem,
                        "exposure": [],
                        "product_context": [],
                        "evidence_locator": section,
                    }
                )
        if vendor == "arista" and section == "Vulnerability Assessment":
            if n.tag == "p":
                if "NOT affected" in t:
                    state = "unaffected"
                elif "following products are affected by" in t:
                    ids = cves(t)
                    state = "affected"
                elif "following cloud services were affected" in t:
                    state = "fixed"
                elif "following products" in t:
                    state = None
            if n.tag == "li" and state:
                ancestor = n.parent
                nested_item = False
                while ancestor:
                    nested_item |= ancestor.tag == "li"
                    ancestor = ancestor.parent
                if nested_item:
                    continue
                # Leaf versions stay attached to their parent product, not separate products.
                nested = list(n.find({"ul", "ol"}))
                own = " ".join(
                    c if isinstance(c, str) else c.text()
                    for c in n.children
                    if not isinstance(c, Node) or c.tag not in {"ul", "ol"}
                )
                product = " ".join(own.split())
                if not product or re.match(r"^\d", product):
                    continue
                scope_ids = ids if state == "affected" and "ids" in locals() else out["cves"]
                versions = [{"expression": child.text()} for child in nested[:1]]
                for cid in scope_ids:
                    out["assessments"].append(
                        {
                            "cve_id": cid,
                            "product_id": product,
                            "product": product,
                            "status": state,
                            "scope": "cve_specific" if state == "affected" else "bulletin_shared",
                            "versions": versions,
                            "remediations": [],
                            "exposure": [],
                            "product_context": [],
                            "evidence_locator": section,
                        }
                    )
    # Deduplicate nested lists or repeated rows without conflating different products.
    unique = {(a["cve_id"], a["product_id"], a["status"]): a for a in out["assessments"]}
    out["assessments"] = list(unique.values())
    if not out["assessments"]:
        raise ValueError("No product assessments extracted; source layout may have changed")
    return out
