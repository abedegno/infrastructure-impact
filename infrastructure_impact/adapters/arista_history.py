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
