"""CloudVision Portal train dates from its reviewed public lifecycle panel."""

import re
from datetime import datetime
from urllib.parse import urlsplit

from .common import HTML


def release_date(text):
    for fmt in ("%d-%b-%Y", "%d-%B-%Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            pass
    raise ValueError("Unreviewed CloudVision initial-release date format")


def arista_release_history(raw, url, vendor):
    parsed = urlsplit(url)
    if (
        parsed.hostname != "www.arista.com"
        or parsed.path != "/en/support/product-documentation/cloudvision-life-cycle-policy"
    ):
        raise ValueError("Unreviewed Arista release-history source")
    tree = HTML(raw).root
    if [h.text() for h in tree.find({"h3"})] != ["CloudVision Software Lifecycle"]:
        raise ValueError("Capture exactly the visible CloudVision Software Lifecycle panel")
    tables = [
        t
        for t in tree.find({"table"})
        if [h.text() for h in t.find({"th"})]
        == ["CVP Release", "Current Status", "Initial Release Date", "End of Support"]
    ]
    updated = re.findall(r"Last Updated:\s*([A-Za-z]+ \d{1,2}, \d{4})", tree.text())
    if len(tables) != 1 or len(updated) != 1:
        raise ValueError("Reviewed CloudVision table or publication context missing")
    updated = datetime.strptime(updated[0], "%B %d, %Y").date()
    rows = []
    for row in tables[0].find({"tr"}):
        cells = [c.text() for c in row.find({"td"})]
        if not cells:
            continue
        if len(cells) == 1 and re.fullmatch(
            r"20\d{2}\.\d+ and earlier release trains are End of Support", cells[0]
        ):
            continue  # Undated historical trains are not assigned invented release dates.
        if (
            len(cells) != 4
            or not re.fullmatch(r"20\d{2}\.\d+", cells[0])
            or cells[1] not in ("Active Development", "Support Only", "End of Support")
        ):
            raise ValueError("CloudVision lifecycle row scope changed")
        released = release_date(cells[2])
        if released > updated:
            raise ValueError("Future planned release cannot be represented as a posted train")
        rows.append(
            dict(
                version=cells[0],
                reported_released_at=released.isoformat(),
                publisher_reports_posted=True,
            )
        )
    if not rows:
        raise ValueError("No dated CloudVision release trains")
    return dict(
        product="CloudVision Portal",
        platforms=["On-premises software; hardware unspecified"],
        branch="major_release_trains",
        version_granularity="release_train",
        releases=rows,
    )


def advisory_bundle(raw, url):
    """0148 summary dates and literal EOS member links, never firmware dates."""
    from ..references.software_releases import (
        ARISTA_URL,
        document,
        explicit_date,
        heading,
        reviewed_html,
        reviewed_table,
        safe_node,
    )

    if url != ARISTA_URL:
        raise ValueError("Unreviewed Arista bundle route")
    tree = reviewed_html(raw)
    heading(tree, "h2", "Security Advisory 0148 PDF")
    revisions = reviewed_table(tree, ["Revision", "Date", "Changes"])
    initial = []
    seen_revisions = set()
    for cells in revisions:
        revision, day, change = [c.text() for c in cells]
        if revision in seen_revisions or not re.fullmatch(r"\d+\.\d+", revision):
            raise ValueError("Duplicate or malformed bundle revision")
        seen_revisions.add(revision)
        parsed = explicit_date(day, "%B %d, %Y")
        if change == "Initial release":
            initial.append(parsed)
    if len(initial) != 1:
        raise ValueError("Bundle initial publication date missing or conflicting")
    announcements = []
    statements = []
    for p in tree.find({"p"}):
        match = re.fullmatch(
            r"On ([A-Z][a-z]+ \d{2}, \d{4}) Arista published multiple Security Advisories\. (.+)",
            p.text(),
        )
        if match:
            safe_node(p)
            announcements.append(explicit_date(match[1], "%B %d, %Y"))
            statements.append(p.text())
    if len(announcements) != 1 or announcements[0] < initial[0]:
        raise ValueError("Bundle member publication context missing or conflicting")
    members, links, issues = [], [], []
    seen = set()
    for cells in reviewed_table(
        tree, ["Security Advisory #", "Product (Component)", "CVE ID", "Severity", "CVSS 3.1 Score"]
    ):
        identity, product = cells[0].text(), cells[1].text()
        anchors = list(cells[0].find({"a"}))
        if (
            len(anchors) != 1
            or anchors[0].text() != identity
            or not re.fullmatch(r"\d{3}", identity)
            or identity in seen
        ):
            raise ValueError("Missing, duplicate or conflicting linked member identity")
        seen.add(identity)
        href = anchors[0].attrs.get("href", "")
        match = re.fullmatch(
            r"/en/support/advisories-notices/security-advisory/\d+-security-advisory-(\d{4})", href
        )
        if not match or int(match[1]) != int(identity):
            raise ValueError("Unreviewed or conflicting bundle member href")
        if 149 <= int(identity) <= 178 and re.fullmatch(r"EOS \(.+\)", product):
            members.append(identity)
            links.append(f"{identity}: {href}")
        elif 179 <= int(identity) <= 182 and product.startswith("VeloCloud "):
            issues.append(f"Excluded non-EOS member {identity}: {product}; href={href}")
        else:
            raise ValueError("Unreviewed bundle member product ownership")
    if seen != {str(identity) for identity in range(149, 183)}:
        raise ValueError("Missing or changed reviewed bundle membership (149–182)")
    bundle = dict(
        publisher_id="0148",
        title="Security Advisory 0148",
        initial_published_at=initial[0],
        member_publication_date=announcements[0],
        member_advisory_ids=members,
        source_locator="Security Advisory # / Product (Component) table; " + "; ".join(links),
        statement=statements[0],
    )
    return document(
        "arista", "arista-eos", "EOS", [], url, "arista_history.py", bundles=[bundle], issues=issues
    )
