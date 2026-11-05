"""One reviewed informational schedule article; linked advisories are separate scope."""

import re
from datetime import datetime

from .cisco_campaign import cells, one
from .common import HTML, Node, base, cves

ID = "cisco-sa-notice-I8z3n6lK"
PREFIX = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
URL = PREFIX + ID
TITLE = "Cisco Advance Notification for Publication of November 4, 2026, Security Advisories"


def parse_notice(raw, url, vendor):
    if url != URL:
        return None
    if vendor != "cisco":
        raise ValueError("Cisco notice vendor mismatch")
    tree = HTML(raw).root

    def field(root, identity):
        return one((n for n in root.find({"div"}) if n.attrs.get("id") == identity), identity)

    headline = one(
        (n for n in tree.find({"h1"}) if n.attrs.get("class") == "headline"), "notice headline"
    )
    article = field(tree, "advisorycontentcontainer")
    header = field(article, "advisorycontentheader")
    body = field(article, "advisorycontentbody")
    if (
        headline.text() != TITLE
        or field(header, "severitycirclecontent").text() != "Informational"
        or field(header, "ud-advisory-identifier").text() != "Advisory ID: " + ID
        or cves(header.text())
    ):
        raise ValueError("Cisco informational identity or own CVE scope changed")
    if any(
        (n.tag, n.text())
        not in {
            ("h2", "Summary"),
            ("h2", "Details"),
            ("h2", "Cisco Security Vulnerability Policy"),
            ("h2", "Subscribe to Cisco Security Notifications"),
            ("h2", "Related to This Advisory"),
            ("h2", "URL"),
            ("h2", "Revision History"),
            ("h2", "Legal Disclaimer"),
            ("h2", "Feedback"),
            ("h3", "SOFTWARE DOWNLOADS AND TECHNICAL SUPPORT"),
            ("h3", "LEGAL DISCLAIMER DETAILS"),
        }
        for n in body.find({"h2", "h3", "h4"})
    ):
        raise ValueError("Cisco notice gained an unreviewed own-body section")
    summary, details = field(body, "summaryfield"), field(body, "detailfield")
    if (
        "published the following advisories:" not in summary.text()
        or "seven-day advance notice of upcoming security vulnerability disclosures"
        not in details.text()
        or "schedule is not a final commitment of releases" not in details.text()
    ):
        raise ValueError("Cisco positive informational markers changed")
    table = one(summary.find({"table"}), "linked advisory table")
    rows = list(table.find({"tr"}))
    if (
        not rows
        or [c.text() for c in cells(rows[0])]
        != ["Cisco Security Advisory", "CVE ID", "Security Impact Rating", "CVSS Base Score"]
        or len(rows) < 2
    ):
        raise ValueError("Cisco linked advisory columns changed")
    linked = []
    for row in rows[1:]:
        values = cells(row)
        if len(values) != 4 or not re.fullmatch(r"CVE-\d{4}-\d{4,}", values[1].text()):
            raise ValueError("Cisco linked advisory row scope changed")
        link = one(values[0].find({"a"}), "separate advisory link")
        target = link.attrs.get("href", "")
        if (
            not re.fullmatch(re.escape(PREFIX) + r"cisco-sa-[A-Za-z0-9-]+", target)
            or target == URL
            or cves(values[0].text() + values[2].text() + values[3].text())
        ):
            raise ValueError("Cisco linked advisory identity changed")
        linked.append(
            {
                "category": "publisher_reference",
                "text": values[1].text() + " refers to a separate advisory: " + values[0].text(),
                "source_locator": "Summary / linked advisories / " + target,
            }
        )

    # CVE references are permitted only in the reviewed summary table. Empty own
    # CVE fields and the positive schedule markers are independently required.
    def outside_table(node):
        if node is table:
            return ""
        return " ".join(outside_table(c) if isinstance(c, Node) else c for c in node.children)

    # Exclude the exact table node, not its CVE set: a repeated identifier in
    # another own-body section is still a material new own-scope statement.
    # Related/footer material outside this article body remains out of scope.
    if cves(outside_table(body)):
        raise ValueError("Cisco notice has unreviewed own CVE prose")
    out = base(vendor, url, ID, "Cisco Informational: " + TITLE)
    for label, identity, key in [
        ("First Published: ", "ud-published", "published_at"),
        ("Last Updated: ", "ud-last-updated", "updated_at"),
    ]:
        value = field(header, identity).text()
        if not value.startswith(label):
            raise ValueError("Cisco notice publication field changed")
        out[key] = datetime.strptime(value[len(label) :], "%Y %B %d %H:%M GMT").strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    if out["updated_at"] < out["published_at"] or not re.search(
        r"\bVersion \d+\.\d+: Final\b", header.text()
    ):
        raise ValueError("Cisco notice revision chronology changed")
    out.update(
        source_format="Cisco reviewed informational schedule HTML",
        document_status="published",
        notes=linked
        + [{"category": "publisher_context", "text": details.text(), "source_locator": "Details"}],
    )
    out["warnings"] = [
        "Informational publication schedule. Linked CVEs belong to separate advisories; no product assessments, bundles, fix availability or future publication dates are inferred."
    ]
    return out
