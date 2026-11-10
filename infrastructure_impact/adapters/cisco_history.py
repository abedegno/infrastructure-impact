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
    metadata = [
        node
        for node in tree.find({"div"})
        if {"support-birth-cert", "software-data-wrapper"}
        & set(node.attrs.get("class", "").split())
    ]
    if metadata:
        text = software_table_date(tree)
        locator = (
            "div.support-birth-cert[data-owner=ID] / div.software-data-wrapper / "
            "table.birth-cert-table.col2 / tbody / tr[th=Release Date] / td"
        )
    else:
        text = synthetic_section_date(tree)
        locator = "section[h2=Cisco IOS XE Dublin 17.12.1] / dl / Release Date"
    row = dict(
        version="17.12.1",
        branch="17.12",
        reported_release_date=explicit_date(text, "%d-%b-%Y"),
        publisher_reports_posted=None,
        date_basis="publisher_release_date",
        source_locator=locator,
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


def children(node):
    return [child for child in node.children if not isinstance(child, str)]


def software_table_date(tree):
    """Read only directly owned software identity and date rows in the reviewed tree."""
    certificates = [
        n for n in tree.find({"div"}) if "support-birth-cert" in n.attrs.get("class", "").split()
    ]
    wrappers = [
        n for n in tree.find({"div"}) if "software-data-wrapper" in n.attrs.get("class", "").split()
    ]
    if len(certificates) != 1 or len(wrappers) != 1:
        raise ValueError("Expected one Cisco software metadata wrapper")
    certificate, wrapper = certificates[0], wrappers[0]
    if certificate.attrs.get("data-owner") != "ID" or wrapper.parent is not certificate:
        raise ValueError("Unowned Cisco software metadata wrapper")
    if "data-wrapper" not in wrapper.attrs.get("class", "").split():
        raise ValueError("Unsupported Cisco software metadata wrapper")
    tables = list(wrapper.find({"table"}))
    if len(tables) != 2 or any(table.parent is not wrapper for table in tables):
        raise ValueError("Expected two directly owned Cisco metadata tables")
    fields = {}
    for table, column in zip(tables, ("col1", "col2"), strict=True):
        if set(table.attrs.get("class", "").split()) != {"birth-cert-table", column}:
            raise ValueError("Unsupported Cisco metadata table")
        bodies = children(table)
        if len(bodies) != 1 or bodies[0].tag != "tbody":
            raise ValueError("Expected directly owned Cisco table body")
        rows = children(bodies[0])
        if any(row.tag != "tr" for row in rows):
            raise ValueError("Expected directly owned Cisco metadata rows")
        direct_headers = []
        for row in rows:
            cells = children(row)
            headers = [cell for cell in cells if cell.tag == "th"]
            direct_headers.extend(headers)
            if not headers:
                continue  # Lifecycle notices and telemetry filler do not supply facts.
            if [cell.tag for cell in cells] != ["th", "td"]:
                raise ValueError("Unsupported Cisco metadata field")
            label = headers[0].text()
            if label in fields:
                raise ValueError("Duplicate Cisco metadata label")
            fields[label] = (column, row, cells[1])
        if list(table.find({"th"})) != direct_headers:
            raise ValueError("Nested Cisco metadata label")
    for label, value in (("Series", "Cisco IOS XE 17"), ("Product Type", "Cisco IOS XE")):
        if label not in fields:
            raise ValueError("Missing Cisco software identity")
        column, row, cell = fields[label]
        if column != "col1" or safe_node(row) != f"{label} {value}" or cell.text() != value:
            raise ValueError("Unreviewed Cisco software identity")
    if "Release Date" not in fields:
        raise ValueError("Missing Cisco software Release Date")
    column, row, cell = fields["Release Date"]
    safe_node(row)
    if column != "col2" or children(cell):
        raise ValueError("Unowned or nested Cisco software Release Date")
    for node in children(row):
        if node.attrs.get("rowspan", "1") != "1" or node.attrs.get("colspan", "1") != "1":
            raise ValueError("Spanned Cisco software Release Date")
    return cell.text()


def synthetic_section_date(tree):
    """Retain the previously reviewed synthetic section contract."""
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
    return fields[1].text()
