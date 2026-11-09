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
    # This synthetic-reviewed layout is deliberately narrow until raw acceptance.
    # Page title/h1 alone cannot make a hardware or documentation date software metadata.
    model = "Cisco IOS XE Dublin 17.12.1"
    sections = [
        section
        for section in tree.find({"section"})
        if any(
            not isinstance(child, str) and child.tag == "h2" and child.text() == model
            for child in section.children
        )
    ]
    if len(sections) != 1:
        raise ValueError("Expected exactly one explicitly named software model metadata section")
    section = sections[0]
    safe_node(section)
    elements = [child for child in section.children if not isinstance(child, str)]
    if [child.tag for child in elements] != ["h2", "dl"]:
        raise ValueError("Unsupported software model metadata section layout")
    fields = [child for child in elements[1].children if not isinstance(child, str)]
    if [child.tag for child in fields] != ["dt", "dd"] or fields[0].text() != "Release Date":
        raise ValueError("Expected one directly owned software model Release Date field")
    text = fields[1].text()
    row = dict(
        version="17.12.1",
        branch="17.12",
        reported_release_date=explicit_date(text, "%d-%b-%Y"),
        publisher_reports_posted=None,
        date_basis="publisher_release_date",
        source_locator="section[h2=Cisco IOS XE Dublin 17.12.1] / dl / Release Date",
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
