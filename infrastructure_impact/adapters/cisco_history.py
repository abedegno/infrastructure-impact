"""Exact software model Release Date; documentation updates are separate facts."""

from ..references.software_releases import (
    CISCO_URL,
    document,
    explicit_date,
    heading,
    reviewed_html,
    safe_node,
)


def model_release(raw, url):
    if url != CISCO_URL:
        raise ValueError("Unreviewed Cisco software release route")
    tree = reviewed_html(raw)
    heading(tree, "title", "Cisco IOS XE Dublin 17.12.1 - Cisco")
    heading(tree, "h1", "Cisco IOS XE Dublin 17.12.1")
    labels = [n for n in tree.find({"dt"}) if n.text() == "Release Date"]
    if len(labels) != 1:
        raise ValueError("Expected exactly one software model Release Date")
    label = labels[0]
    siblings = label.parent.children
    position = siblings.index(label)
    following = [n for n in siblings[position + 1 :] if not isinstance(n, str)]
    if label.parent.tag != "dl" or not following or following[0].tag != "dd":
        raise ValueError("Software model Release Date value missing")
    safe_node(label.parent)
    text = following[0].text()
    row = dict(
        version="17.12.1",
        branch="17.12",
        reported_release_date=explicit_date(text, "%d-%b-%Y"),
        publisher_reports_posted=None,
        date_basis="publisher_release_date",
        source_locator="Cisco IOS XE Dublin 17.12.1 / Release Date",
        statement=f"Release Date: {text}",
    )
    return document(
        "cisco",
        "cisco-iosxe",
        "Cisco IOS XE Dublin 17.12.1",
        [],
        url,
        "cisco_history.py",
        releases=[row],
    )
