"""Reviewed consolidated release-history tables; no inferred version dates."""

import re
from datetime import datetime
from urllib.parse import unquote, urlsplit

from .common import HTML


def aruba_release_history(raw, url, vendor):
    parsed = urlsplit(url)
    if parsed.hostname != "arubanetworking.hpe.com" or not re.fullmatch(
        r"/techdocs/AOS-CX/Consolidated_RNs/4100i Release Notes/aos-cx-10-13-xx/version-history-\d+\.html",
        unquote(parsed.path),
    ):
        raise ValueError("Unreviewed Aruba release-history product, branch or path")
    tree = HTML(raw).root
    headings = [n.text() for n in tree.find({"h1"})]
    if headings != ["Version history"]:
        raise ValueError("Reviewed Version history article heading missing")
    tables = [
        t
        for t in tree.find({"table"})
        if [n.text() for n in t.find({"th"})] == ["Version number", "Release date", "Remarks"]
    ]
    if len(tables) != 1:
        raise ValueError("Expected exactly one reviewed version-history table")
    rows = []
    for row in tables[0].find({"tr"}):
        cells = [n.text() for n in row.find({"td"})]
        if not cells:
            continue
        if len(cells) != 3 or not re.fullmatch(r"10\.13\.\d{4}", cells[0]):
            raise ValueError("Release-history row structure or branch changed")
        try:
            released = datetime.strptime(cells[1], "%d/%m/%Y").date().isoformat()
        except ValueError as error:
            raise ValueError("Expected explicit day/month/year release date") from error
        if cells[2] != "Released, fully supported, and posted on the Web.":
            raise ValueError("Reviewed release-availability wording changed")
        rows.append(
            dict(version=cells[0], reported_released_at=released, publisher_reports_posted=True)
        )
    if not rows:
        raise ValueError("Release-history table has no usable rows")
    return dict(product="AOS-CX", platforms=["4100i Switch Series"], branch="10.13", releases=rows)
