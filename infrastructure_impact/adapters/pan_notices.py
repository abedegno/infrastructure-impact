"""Exact reviewed non-CVE configuration notices; never invent CVE identities."""

import re

from .common import HTML, Node, base, cves

IDENTITY = "PAN-SA-2025-0005"
URL = "https://security.paloaltonetworks.com/" + IDENTITY
TITLE = (
    IDENTITY
    + " GlobalProtect Clientless VPN: Clientless VPN Misconfiguration Allows Cross-Site Attacks"
)
FORMAT = "Palo Alto reviewed non-CVE configuration notice HTML"


def one(items, label):
    values = list(items)
    if len(values) != 1:
        raise ValueError("Expected one reviewed PAN notice " + label)
    return values[0]


def configuration_notice(raw, url, vendor):
    if url != URL or vendor != "paloalto":
        raise ValueError("Unreviewed PAN non-CVE notice route")
    root = HTML(raw).root
    article = one((n for n in root.find({"div"}) if n.attrs.get("id") == "content"), "article")
    if one(article.find({"h2"}), "heading").text() != TITLE or cves(article.text()):
        raise ValueError("PAN non-CVE notice identity or CVE scope changed")
    headings = [n.text() for n in article.find({"h3"})]
    if headings != [
        "Description",
        "Product Status",
        "Required Configuration for Exposure",
        "Exploitation Status",
        "Workarounds and Mitigations",
        "Acknowledgments",
        "Timeline",
    ]:
        raise ValueError("PAN non-CVE notice section boundaries changed")
    table = one(article.find({"table"}), "notice product-status table")
    rows = [[n.text() for n in row.find({"th", "td"})] for row in table.find({"tr"})]
    if rows != [
        ["Versions", "Affected", "Unaffected"],
        ["Cloud NGFW", "None", "All"],
        ["PAN-OS", "All", "None"],
        ["Prisma Access", "All", "None"],
    ]:
        raise ValueError("PAN notice-level product scope changed")
    sections = {}
    current = None
    for node in article.children:
        if not isinstance(node, Node):
            continue
        if node.tag == "h3":
            current = node.text()
            sections[current] = []
        elif current:
            sections[current].append(node)
    required = " ".join(n.text() for n in sections["Required Configuration for Exposure"])
    if any(
        phrase not in required
        for phrase in (
            "All of the following must be true",
            "valid GlobalProtect Subscription license",
            "Clientless VPN is enabled",
            "Security Policies allow Clientless VPN access to more than one internal or external Application",
        )
    ):
        raise ValueError("PAN Clientless VPN configuration prerequisites changed")
    summary = one(
        (n for n in article.find({"div"}) if n.attrs.get("class") == "sa_summary"), "summary"
    )
    dates = {
        label: re.findall(label + r"\s+(\d{4}-\d{2}-\d{2})", summary.text())
        for label in ("Published", "Updated")
    }
    if any(len(values) != 1 for values in dates.values()) or not summary.text().startswith(
        "Informational"
    ):
        raise ValueError("PAN informational notice date metadata changed")
    out = base(vendor, url, IDENTITY, TITLE, dates["Published"][0], dates["Updated"][0])
    out.update(source_format=FORMAT, document_status="published")
    out["warnings"] = [
        "Reviewed non-CVE configuration notice. No CVE identifier or CVE/product assessments are created. The publisher's Product Status table is notice-scoped: PAN-OS and Prisma Access list All in Affected; Cloud NGFW lists All in Unaffected. These entries must not be applied to any CVE or treated as a complete product inventory.",
        "Applicability requires the stated GlobalProtect subscription, enabled Clientless VPN and security policies allowing access to multiple applications. The publisher describes configuration restrictions and alternatives, not a verified firmware security-fix release. No hidden fix, historical availability or deployment exposure is inferred.",
    ]
    return out
