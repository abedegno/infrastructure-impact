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


def consolidated_history(raw, url, branch):
    """6300/6300L/6400 history; keep posting unknown for initial-release wording."""
    from ..references.software_releases import (
        ARUBA_10_14_URL,
        ARUBA_10_16_URL,
        ARUBA_PLATFORMS,
        document,
        explicit_date,
        heading,
        reviewed_html,
        reviewed_table,
    )

    if (branch, url) not in [("10.14", ARUBA_10_14_URL), ("10.16", ARUBA_10_16_URL)]:
        raise ValueError("Unreviewed Aruba release history branch or route")
    tree = reviewed_html(raw)
    heading(tree, "title", "Version history")
    heading(tree, "h1", "Version history")
    rows = []
    seen = set()
    for cells in reviewed_table(tree, ["Version number", "Release date", "Remarks"]):
        version, released, statement = [c.text() for c in cells]
        if not re.fullmatch(re.escape(branch) + r"\.\d{4}", version) or version in seen:
            raise ValueError("Invalid, duplicate or conflicting Aruba release identity")
        seen.add(version)
        posted = {
            "Released, fully supported, and posted on the Web.": True,
            "Initial release.": None,
        }
        if statement not in posted:
            raise ValueError("Reviewed Aruba release remarks changed")
        rows.append(
            dict(
                version=version,
                branch=branch,
                reported_release_date=explicit_date(released, "%d %B %Y"),
                publisher_reports_posted=posted[statement],
                date_basis="publisher_release_history",
                source_locator=f"Version history / Version number={version}",
                statement=statement,
            )
        )
    return document(
        "aruba", "aruba-aoscx", "AOS-CX", ARUBA_PLATFORMS, url, "aruba_history.py", releases=rows
    )


def consolidated_support(raw, url):
    """Literal SKU minima, including later additions to the consolidated page."""
    from ..references.software_releases import (
        ARUBA_PLATFORMS,
        ARUBA_SUPPORT_URL,
        document,
        heading,
        reviewed_html,
        reviewed_table,
    )

    if url != ARUBA_SUPPORT_URL:
        raise ValueError("Unreviewed Aruba support route")
    tree = reviewed_html(raw)
    heading(tree, "title", "Products Supported")
    heading(tree, "h1", "Products Supported")
    rows = []
    seen = set()
    for cells in reviewed_table(
        tree, ["Product Number", "Product Name", "Minimum Software Version"]
    ):
        sku, model, minimum = [c.text() for c in cells]
        if (
            not re.fullmatch(r"[A-Z0-9]{5,12}", sku)
            or sku in seen
            or not re.fullmatch(r"10\.\d{2}\.\d{4}", minimum)
            or not re.search(r"\b(?:6300[FLM]?|6400|6405|6410)\b", model)
            or re.search(r"\b(?:4100i|6200|8320)\b", model)
        ):
            raise ValueError("Invalid, duplicate or out-of-product Aruba support row")
        seen.add(sku)
        rows.append(
            dict(
                sku=sku,
                model_literal=model,
                minimum_version=minimum,
                source_locator=f"Products Supported / Product Number={sku}",
            )
        )
    return document(
        "aruba",
        "aruba-aoscx",
        "AOS-CX",
        ARUBA_PLATFORMS,
        url,
        "aruba_history.py",
        platform_support=rows,
    )
