"""Narrow release-signal readers for the Phase 1 source layouts."""

import re
from datetime import UTC, datetime
from http.client import HTTPException
from time import monotonic
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from xml.etree import ElementTree

from ..adapters.common import HTML, Node
from .errors import AccessVerificationRequired, CiscoAccessError, check_access_response

ARISTA_URL = "https://www.arista.com/en/support/release-notes"
CISCO_URL = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/"
    "release/17-12/release_notes/ol-17-12-9300/caveats.html"
)
ARUBA_URL = "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/RN/rn_6300-6400_10-13-1040.pdf"
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024

_ARISTA_TITLE = "Arista Networks :: Software Release"
_ARISTA_LINK = "https://www.arista.com/support/release-notes"
_ARISTA_RELEASE = re.compile(r"EOS-(4\.\d+\.\d+(?:\.\d+)?[FM]) is now available for download\.")
_ARISTA_DATE = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}", re.ASCII)
_CISCO_TITLE = "Release Notes for Cisco Catalyst 9300 Series Switches, Cisco IOS XE Dublin 17.12.x"
_CISCO_HEADING = re.compile(r"Resolved Caveats in Cisco IOS XE Dublin (17\.12\.\d+[a-z]?)")
_ARUBA_TITLE = re.compile(r"AOS-CX 10\.13\.\d{4} Release Notes \| for 6300 and 6400 Switches")
_ARUBA_REMARK = "Released, fully supported, and posted on the Web."
_HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}


def _document(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("Document must contain bounded source bytes")
    check_access_response(raw)
    prefix = raw[:15000].lower()
    if re.search(
        rb"<(?:title|h1)[^>]*>\s*(?:client challenge|access denied|forbidden|"
        rb"request blocked|just a moment|sign in|log in)\b",
        prefix,
    ):
        raise AccessVerificationRequired("Source returned an access, challenge or login page")


def _event(kind, vendor, train, release, statement, locator, *, day=None, platforms=(), bugs=()):
    return {
        "kind": kind,
        "vendor": vendor,
        "train": train,
        "release": release,
        "related_release": None,
        "date": day,
        "platforms": list(platforms),
        "statement": statement,
        "bug_ids": list(bugs),
        "source_locator": locator,
    }


def _xml_leaf(node, tag):
    matches = node.findall(tag)
    if len(matches) == 1 and not len(matches[0]):
        return matches[0].text
    return None


def parse_arista_releases(raw):
    """Read EOS 4.33 announcement titles and UTC announcement calendar dates."""
    _document(raw)
    if b"\0" in raw or re.search(rb"<!DOCTYPE|<!ENTITY", raw, re.IGNORECASE):
        raise ValueError("Unsupported Arista RSS declarations or encoding")
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        raise ValueError("Unsupported Arista RSS XML") from None
    channel = root.find("channel")
    if (
        root.tag != "rss"
        or root.get("version") != "2.0"
        or len(root.findall("channel")) != 1
        or _xml_leaf(channel, "title") != _ARISTA_TITLE
        or _xml_leaf(channel, "link") != _ARISTA_LINK
    ):
        raise ValueError("Unsupported Arista software RSS channel")

    events = []
    recognized_announcements = 0
    for index, item in enumerate(channel.findall("item"), start=1):
        title = item.findtext("title", "")
        match = _ARISTA_RELEASE.fullmatch(title)
        if not match:
            if title.startswith("EOS-4.33."):
                raise ValueError("Unsupported EOS 4.33 announcement title")
            continue
        recognized_announcements += 1
        release = match[1]
        if not release.startswith("4.33."):
            continue
        if _xml_leaf(item, "title") != title:
            raise ValueError("Unsupported Arista announcement title")
        pub_date = _xml_leaf(item, "pubDate")
        if not pub_date or not _ARISTA_DATE.fullmatch(pub_date):
            raise ValueError("Unsupported Arista announcement pubDate")
        try:
            timestamp = datetime.strptime(pub_date, "%Y-%m-%d %H:%M:%S %z").astimezone(UTC)
        except ValueError:
            raise ValueError("Invalid Arista announcement pubDate") from None
        events.append(
            _event(
                "release",
                "arista",
                "4.33",
                release,
                title,
                f"RSS channel/item[{index}] / title and pubDate",
                day=timestamp.date().isoformat(),
            )
        )
    if not recognized_announcements:
        raise ValueError("Arista software RSS has no recognized EOS announcements")
    return events


def _html_sections(raw):
    _document(raw)
    html = HTML(raw.decode("utf-8-sig"))
    pending = [(html.root, 0)]
    sections = []
    while pending:
        node, depth = pending.pop()
        if depth > 100:
            raise ValueError("Unsupported HTML nesting")
        if node.tag == "meta" and (node.attrs.get("http-equiv") or "").lower() == "refresh":
            raise AccessVerificationRequired("Source returned an HTML redirect")
        if _hidden(node):
            # Hidden heading boundaries still end the preceding section's ownership.
            if node.tag in _HEADINGS or any(child.tag in _HEADINGS for child in _descendants(node)):
                sections.append(Node("h2"))
            continue
        if node.tag in _HEADINGS | {"table"}:
            sections.append(node)
            if node.tag in _HEADINGS and any(_hidden(child) for child in _descendants(node)):
                raise ValueError("Unsupported heading visibility")
        pending.extend(
            (child, depth + 1) for child in reversed(node.children) if isinstance(child, Node)
        )
    return sections


def _hidden(node):
    return (
        node.tag in {"script", "style", "noscript", "template"}
        or "hidden" in node.attrs
        or (node.attrs.get("aria-hidden") or "").lower() == "true"
        or re.search(
            r"(?:display\s*:\s*none|visibility\s*:\s*hidden)\b", node.attrs.get("style") or "", re.I
        )
    )


def _descendants(node):
    pending = [child for child in node.children if isinstance(child, Node)]
    while pending:
        child = pending.pop()
        yield child
        pending.extend(item for item in child.children if isinstance(item, Node))


def _table_rows(table):
    if any(
        node.tag == "table"
        or _hidden(node)
        or node.attrs.get("rowspan", "1") != "1"
        or node.attrs.get("colspan", "1") != "1"
        for node in _descendants(table)
    ):
        raise ValueError("Unsupported table visibility, nesting or merged cells")
    return [
        [
            cell.text()
            for cell in row.children
            if isinstance(cell, Node) and cell.tag in {"th", "td"}
        ]
        for row in table.find({"tr"})
    ]


def parse_cisco_caveats(raw):
    """Read resolved caveat disclosures from the Catalyst 9300 IOS XE 17.12 chapter."""
    sections = _html_sections(raw)
    headings = {node.text() for node in sections if node.tag in _HEADINGS}
    if _CISCO_TITLE not in headings or "Caveats" not in headings:
        raise ValueError("Unsupported Cisco IOS XE 17.12 Catalyst 9300 caveat chapter")
    events = []
    match = None
    for node in sections:
        if node.tag in _HEADINGS:
            match = _CISCO_HEADING.fullmatch(node.text())
            continue
        if not match:
            continue
        rows = _table_rows(node)
        if not rows or rows[0] not in [
            ["Identifier", "Headline"],
            ["Identifier", "Applicable Models", "Headline"],
        ]:
            raise ValueError("Unsupported Cisco resolved caveat table headers")
        for row in rows[1:]:
            if (
                len(row) != len(rows[0])
                or not re.fullmatch(r"CSC[a-z]{2}\d{5}", row[0], re.ASCII)
                or not row[-1]
            ):
                raise ValueError("Unsupported Cisco resolved caveat row")
            platforms = []
            if len(row) == 3 and row[1].lower() != "all models":
                platforms = row[1].split(", ")
            if any(not re.fullmatch(r"C9300(?:L|LM|X)?(?:-[A-Z0-9]+)*", p) for p in platforms):
                raise ValueError("Unsupported Cisco caveat model scope")
            events.append(
                _event(
                    "bug_list",
                    "cisco",
                    "17.12",
                    match[1],
                    row[-1],
                    f"{match[0]} / Identifier {row[0]}",
                    platforms=platforms,
                    bugs=[row[0]],
                )
            )
    if not events:
        raise ValueError("Cisco chapter has no supported resolved caveat rows")
    return events


def parse_aruba_history(raw):
    """Read an HTML capture of the reviewed AOS-CX 6300/6400 version-history table."""
    sections = _html_sections(raw)
    if not any(node.tag in _HEADINGS and _ARUBA_TITLE.fullmatch(node.text()) for node in sections):
        raise ValueError("Unsupported Aruba AOS-CX 10.13 6300/6400 release notes")
    tables = []
    history = False
    for node in sections:
        if node.tag in _HEADINGS:
            history = node.text() == "Version history"
        elif history:
            tables.append(node)
    if len(tables) != 1:
        raise ValueError("Expected a single Aruba version history table")
    rows = _table_rows(tables[0])
    if len(rows) < 2 or rows[0] != ["Version number", "Release date", "Remarks"]:
        raise ValueError("Unsupported Aruba version history headers")
    events = []
    for row in rows[1:]:
        if (
            len(row) != 3
            or not re.fullmatch(r"10\.13\.\d{4}", row[0], re.ASCII)
            or not re.fullmatch(r"\d{2}/\d{2}/\d{4}", row[1], re.ASCII)
            or row[2] != _ARUBA_REMARK
        ):
            raise ValueError("Unsupported Aruba version history row")
        events.append(
            _event(
                "release",
                "aruba",
                "10.13",
                row[0],
                row[2],
                f"Version history / Version number {row[0]} / Release date and Remarks",
                day=datetime.strptime(row[1], "%d/%m/%Y").date().isoformat(),
                platforms=("6300 Switch Series", "6400 Switch Series"),
            )
        )
    return events


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise CiscoAccessError("redirect_rejected")


def _read_response(response, deadline):
    expected = getattr(response, "length", None)
    if expected is not None and expected > MAX_DOCUMENT_BYTES:
        raise CiscoAccessError("response_too_large")
    data = bytearray()
    while len(data) <= MAX_DOCUMENT_BYTES:
        if monotonic() >= deadline:
            raise CiscoAccessError("network_error")
        chunk = response.read1(min(64 * 1024, MAX_DOCUMENT_BYTES + 1 - len(data)))
        if not chunk:
            if expected is not None and expected != len(data):
                raise CiscoAccessError("network_error")
            return bytes(data)
        data.extend(chunk)
    raise CiscoAccessError("response_too_large")


def fetch_arista():
    """Fetch the fixed public feed with no cookies, auth, redirects or environment proxy."""
    request = Request(ARISTA_URL, headers={"User-Agent": "Infrastructure-Impact release-signals"})
    deadline = monotonic() + 30
    try:
        with build_opener(ProxyHandler({}), _RejectRedirects()).open(
            request, timeout=15
        ) as response:
            if response.geturl() != ARISTA_URL:
                raise CiscoAccessError("redirect_rejected")
            if response.status != 200:
                raise CiscoAccessError("unsupported_response")
            return _read_response(response, deadline)
    except HTTPError as error:
        error.close()
        if 300 <= error.code < 400:
            raise CiscoAccessError("redirect_rejected") from None
        if error.code in {401, 403}:
            raise CiscoAccessError("access_denied") from None
        if error.code == 429:
            raise CiscoAccessError("rate_limited") from None
        raise CiscoAccessError("http_error") from None
    except HTTPException:
        raise CiscoAccessError("network_error") from None
