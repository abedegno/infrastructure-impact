"""Reviewed single-CVE Cisco campaign HTML, retaining literal product boundaries."""

import re
from datetime import datetime

from .common import HTML, Node, base, cves

ADVISORY_ID = "cisco-sa-openssh-rce-2024"
CVE = "CVE-2024-6387"
URL = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/" + ADVISORY_ID
TITLE = (
    "Remote Unauthenticated Code Execution Vulnerability in OpenSSH Server (regreSSHion): July 2024"
)
CATEGORIES = {
    "Network and Content Security Devices",
    "Network Management and Provisioning",
    "Routing and Switching - Enterprise and Service Provider",
    "Unified Computing",
    "Voice and Unified Communications Devices",
    "Video, Streaming, TelePresence, and Transcoding Devices",
    "Wireless",
}


def reviewed_route(url):
    return url == URL


def one(nodes, label):
    values = list(nodes)
    if len(values) != 1:
        raise ValueError(f"Expected one Cisco {label}")
    return values[0]


def cells(row):
    return [
        child for child in row.children if isinstance(child, Node) and child.tag in {"th", "td"}
    ]


def lines(node):
    def raw(value):
        if isinstance(value, str):
            return value
        if value.tag == "br":
            return "\n"
        return "".join(raw(child) for child in value.children)

    return [" ".join(line.split()) for line in raw(node).splitlines() if line.strip()]


def remediation(value):
    # Preserve what was estimated at the publisher's dated update, even after the
    # estimated month has passed. Calendar passage is not release verification.
    if re.search(r"\bno fix planned\b|\bwill not (?:fix|be fixed)\b", value, re.I):
        availability = "no_fix_planned"
    elif re.search(
        r"\bno fix (?:needed|required)\b|\b(?:consult|contact|details|investigat)\w*\b", value, re.I
    ):
        availability = "unknown"
    elif re.search(r"\bno fix(?:ed)?(?: releases?)?\b|\bunavailable\b", value, re.I):
        availability = "unavailable"
    elif re.search(
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+20\d{2}\b|\b(?:TBD|upcoming|planned|scheduled)\b",
        value,
        re.I,
    ):
        availability = "planned"
    elif not any(character.isdigit() for character in value):
        availability = "unknown"
    else:
        availability = "vendor_reports_fixed"
    return {"category": "vendor_fix", "details": value, "availability": availability}


def parse_campaign(raw, url, vendor="cisco"):
    if not reviewed_route(url):
        return None
    if vendor != "cisco":
        raise ValueError("Cisco campaign vendor mismatch")
    tree = HTML(raw).root
    headline = one(
        (n for n in tree.find({"h1"}) if n.attrs.get("class") == "headline"), "campaign headline"
    )
    if headline.text() != TITLE:
        raise ValueError("Unreviewed Cisco campaign title")
    text = tree.text()
    if not re.search(r"Advisory ID:\s*" + ADVISORY_ID + r"\b", text):
        raise ValueError("Cisco advisory identity mismatch")
    before_affected = text.split("Affected Products", 1)
    if len(before_affected) != 2 or cves(before_affected[0]) != [CVE]:
        raise ValueError("Cisco campaign CVE header scope changed")
    out = base(vendor, url, ADVISORY_ID, TITLE)
    out.update(
        cves=[CVE],
        source_format="Cisco reviewed single-CVE campaign HTML",
        document_status="published",
    )
    for label, key in [("First Published", "published_at"), ("Last Updated", "updated_at")]:
        match = re.search(label + r":\s*(\d{4}\s+[A-Za-z]+\s+\d{1,2}\s+\d{2}:\d{2})\s+GMT", text)
        if not match:
            raise ValueError("Cisco dated campaign header missing")
        out[key] = datetime.strptime(match[1], "%Y %B %d %H:%M").isoformat() + "Z"
    if not re.search(r"Version\s+\d+\.\d+:\s*Final\b", before_affected[0]):
        raise ValueError("Cisco campaign is not the reviewed final layout")
    affected = one(
        (n for n in tree.find({"div"}) if n.attrs.get("id") == "vulnerableproducts"),
        "vulnerable-products section",
    )
    if "The following table lists Cisco products that are affected" not in affected.text():
        raise ValueError("Cisco affected-product introduction changed")
    table = one(affected.find({"table"}), "affected-product table")
    rows = list(table.find({"tr"}))
    if not rows or [c.text() for c in cells(rows[0])] != [
        "Product",
        "Cisco Bug ID",
        "Fixed Release Availability",
    ]:
        raise ValueError("Cisco product table columns changed")
    category = None
    seen = set()
    for row in rows[1:]:
        values = cells(row)
        if (
            len(values) == 1
            and values[0].attrs.get("colspan") == "3"
            and values[0].attrs.get("class") == "categoryheader"
        ):
            category = values[0].text()
            if category not in CATEGORIES:
                raise ValueError("Unreviewed Cisco product category")
            continue
        if (
            len(values) != 3
            or category is None
            or any(list(c.find({"table", "ul", "ol"})) for c in values)
        ):
            raise ValueError("Unreviewed Cisco product row structure")
        product, bugs, fixes = (value.text() for value in values)
        if (
            not product
            or product in seen
            or not re.fullmatch(r"CSC[a-zA-Z0-9]+(?:\s+CSC[a-zA-Z0-9]+)*", bugs)
            or not fixes
        ):
            raise ValueError("Cisco product row identity or bug reference changed")
        seen.add(product)
        out["assessments"].append(
            {
                "cve_id": CVE,
                "product_id": "vulnerable:" + product,
                "product": product,
                "status": "affected",
                "scope": "cve_specific",
                "versions": [],
                "product_context": [
                    ["product_name", product],
                    ["publisher_category", category],
                    ["publisher_bug_id", bugs],
                ],
                "remediations": [remediation(value) for value in lines(values[2])],
                "exposure": [
                    {
                        "source_scope": "publisher_product_row_requires_platform_and_configuration_review",
                        "details": "Source bug IDs and article footnotes retain platform/configuration qualifications. A fixed-release entry is not an affected-version range or verified release availability.",
                    }
                ],
                "evidence_locator": f"div#vulnerableproducts table / Product={product} / Cisco Bug ID={bugs}; review article footnotes",
            }
        )
    if not out["assessments"]:
        raise ValueError("Cisco affected-product table empty")
    unaffected = one(
        (n for n in tree.find({"div"}) if n.attrs.get("id") == "productsconfirmednotvulnerable"),
        "explicit unaffected section",
    )
    if (
        "Cisco has confirmed that this vulnerability does not affect the following Cisco products"
        not in unaffected.text()
    ):
        raise ValueError("Cisco explicit unaffected statement changed")
    items = list(unaffected.find({"li"}))
    if not items:
        raise ValueError("Cisco unaffected product list missing")
    categories = {}
    previous = None
    for child in unaffected.children:
        if not isinstance(child, Node):
            continue
        if child.tag == "ul":
            if (
                previous is None
                or previous.tag != "p"
                or previous.text()
                not in CATEGORIES
                | {
                    "Endpoint Clients and Client Software",
                    "Network Application, Service, and Acceleration",
                    "Cisco Cloud Hosted Services",
                }
            ):
                raise ValueError("Cisco unaffected category structure changed")
            categories[id(child)] = previous.text()
        previous = child
    unaffected_seen = {}
    for item in items:
        if list(item.find({"ul", "ol", "table"})) or item.parent.tag != "ul":
            raise ValueError("Nested Cisco unaffected scope requires review")
        product = item.text()
        category = categories.get(id(item.parent))
        if not product or product in seen and product not in unaffected_seen or not category:
            raise ValueError("Cisco duplicate or conflicting product label requires review")
        if product in unaffected_seen:
            claim = unaffected_seen[product]
            if ["publisher_category", category] not in claim["product_context"]:
                claim["product_context"].append(["publisher_category", category])
            continue
        seen.add(product)
        out["assessments"].append(
            {
                "cve_id": CVE,
                "product_id": "not-vulnerable:" + product,
                "product": product,
                "status": "unaffected",
                "scope": "cve_specific",
                "versions": [],
                "product_context": [["product_name", product], ["publisher_category", category]],
                "remediations": [],
                "exposure": [
                    {
                        "source_scope": "explicit_listed_product_statement",
                        "details": "Only this literal listed product is normalized. No unlisted product, model, software release or deployment equivalence is inferred.",
                    }
                ],
                "evidence_locator": "div#productsconfirmednotvulnerable / explicit product list / "
                + product,
            }
        )
        unaffected_seen[product] = out["assessments"][-1]
    out["warnings"].append(
        "Reviewed single-CVE HTML product table and explicit unaffected list. Do not infer unaffectedness for unlisted products. Affected ranges and deployment exposure remain unverified; dated planned fixes remain planned publisher claims."
    )
    return out
