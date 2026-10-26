"""Reviewed public listing layouts. No source JavaScript is executed.

These parsers return discovery evidence only. Transport validates official domains
for every output; pagination preserves the publisher's declared product filters.
"""

import re
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit

from ..adapters.common import HTML
from .contracts import ArchivePage


def arista(raw, url, vendor):
    root = HTML(raw).root
    if not any(h.text() == "Security Advisories" for h in root.find({"h2"})):
        raise ValueError("Expected Arista Security Advisories listing")
    headings = [h for h in root.find({"h2"}) if h.text().startswith("Security Advisory ")]
    urls = []
    missing = 0
    for h in headings:
        links = [a.attrs.get("href", "") for a in h.find({"a"})]
        matches = [
            u
            for u in links
            if re.fullmatch(
                r"/en/support/advisories-notices/security-advisory/\d+-security-advisory-\d+", u
            )
        ]
        if len(set(matches)) == 1:
            urls.append(urljoin(url, matches[0]))
        else:
            missing += 1
    paging = [n for n in root.find({"div"}) if "pagination" in n.attrs.get("class", "").split()]
    if len(paging) != 1 or not headings:
        raise ValueError("Arista listing or pagination layout changed")
    markers = [
        n for n in paging[0].find({"span"}) if "pageNext" in n.attrs.get("class", "").split()
    ]
    if len(markers) != 1:
        raise ValueError("Arista next-page control missing or ambiguous")
    control = markers[0].parent
    terminal = "disabled" in control.parent.attrs.get("class", "").split()
    if terminal and control.attrs.get("href") != "javascript:void(0);":
        raise ValueError("Arista terminal pagination control changed")
    next_links = [] if terminal else [control.attrs.get("href", "")]
    for u in next_links:
        if not re.fullmatch(r"/en/support/advisories-notices/securityadvisory\?start=\d+", u):
            raise ValueError("Unexpected Arista continuation URL")
    return ArchivePage(
        tuple(dict.fromkeys(urls)),
        len(headings),
        missing,
        tuple(dict.fromkeys(urljoin(url, u) for u in next_links)),
        "Public Security Advisories listing; security-advisory headings only",
    )


def paloalto(raw, url, vendor):
    root = HTML(raw).root
    forms = [f for f in root.find({"form"}) if f.attrs.get("id") == "chartForm"]
    if (
        len(forms) != 1
        or forms[0].attrs.get("method", "").upper() != "GET"
        or forms[0].attrs.get("action") != "/"
    ):
        raise ValueError("Expected Palo Alto public advisory GET form")
    form = forms[0]
    if set(parse_qs(urlsplit(url).query)) - {"page"}:
        raise ValueError("Filtered Palo Alto archive scope is not reviewed")
    pages = [
        n.attrs.get("value", "") for n in form.find({"input"}) if n.attrs.get("name") == "page"
    ]
    if len(pages) != 1 or not re.fullmatch(r"[1-9]\d*", pages[0]):
        raise ValueError("Expected explicit Palo Alto current page")
    page = int(pages[0])
    if str(page) != parse_qs(urlsplit(url).query).get("page", ["1"])[0]:
        raise ValueError("Palo Alto returned a different page than requested")
    tables = [t for t in form.find({"table"}) if "salist" in t.attrs.get("class", "").split()]
    if len(tables) != 1:
        raise ValueError("Expected Palo Alto advisory table")
    rows = [r for r in tables[0].find({"tr"}) if list(r.find({"td"}))]
    urls = []
    missing = 0
    for row in rows:
        links = [a.attrs.get("href", "") for a in row.find({"a"})]
        matches = [u for u in links if re.fullmatch(r"/(?:CVE-\d{4}-\d{4,}|PAN-SA-\d{4}-\d+)", u)]
        if len(set(matches)) == 1:
            urls.append(urljoin(url, matches[0]))
        else:
            missing += 1
    buttons = [
        b
        for b in form.find({"button"})
        if any("right" in n.attrs.get("class", "").split() for n in b.find({"div"}))
    ]
    signatures = {(b.attrs.get("onclick"), "disabled" in b.attrs) for b in buttons}
    if len(buttons) not in (1, 2) or len(signatures) != 1 or not rows:
        raise ValueError("Palo Alto pagination or row layout changed")
    button = buttons[0]
    next_pages = ()
    if "disabled" not in button.attrs:
        # This exact published form control advertises page+1; interpret no other JS.
        if (
            button.attrs.get("onclick")
            != "var p = document.getElementById('page');p.value=Number(p.value)+1.0;formSubmit()"
        ):
            raise ValueError("Palo Alto next-page form control changed")
        next_pages = (urljoin(url, "/?" + urlencode({"page": page + 1})),)
    return ArchivePage(
        tuple(dict.fromkeys(urls)),
        len(rows),
        missing,
        next_pages,
        "Public unauthenticated advisory listing; no query filters; default page size",
    )


def fortinet(raw, url, vendor):
    root = HTML(raw).root
    forms = [
        f
        for f in root.find({"form"})
        if f.attrs.get("action") == "/psirt" and "filters" in f.attrs.get("class", "").split()
    ]
    sections = [
        s for s in root.find({"section"}) if "table-body" in s.attrs.get("class", "").split()
    ]
    if len(forms) != 1 or len(sections) != 1:
        raise ValueError("Expected Fortinet filtered PSIRT listing")
    rows = [
        n for n in sections[0].find({"div"}) if re.fullmatch(r"fwb_id_\d+", n.attrs.get("id", ""))
    ]
    urls = []
    missing = 0
    for row in rows:
        ids = {m[0] for n in row.find({"b"}) if (m := re.match(r"FG-IR-\d{2}-\d+\b", n.text()))}
        if len(ids) == 1:
            # Reviewed canonical IR-ID route, independently checked against an official document.
            urls.append(urljoin(url, "/psirt/" + next(iter(ids))))
        else:
            missing += 1
    selected = sorted(
        {
            value
            for n in forms[0].find({"option"})
            if "selected" in n.attrs
            for value in n.attrs.get("value", "").split(",")
            if value
        }
    )
    if not selected:
        raise ValueError("Expected explicit Fortinet product selection")
    declared = sorted(set(parse_qs(urlsplit(url).query).get("product", [""])[0].split(",")) - {""})
    if declared and selected != declared:
        raise ValueError("Fortinet returned a different product filter")
    query = parse_qs(urlsplit(url).query)
    if any(
        query.get(k)
        for k in ("date", "severity", "component", "discovered", "attack_type", "version")
    ):
        raise ValueError("Additional Fortinet archive filters are not reviewed")
    navs = [n for n in root.find({"ul"}) if "pagination" in n.attrs.get("class", "").split()]
    if len(navs) not in (1, 2):
        raise ValueError("Fortinet pagination layout changed")
    next_pages = []
    controls = []
    for nav in navs:
        current = [
            n.text() for n in nav.find({"li"}) if "active" in n.attrs.get("class", "").split()
        ]
        if current != query.get("page", ["1"]):
            raise ValueError("Fortinet returned a different page")
        buttons = [n for n in nav.find({"li"}) if n.text() == "»"]
        if len(buttons) != 1:
            raise ValueError("Fortinet next-page control missing")
        links = [a.attrs.get("href", "") for a in buttons[0].find({"a"}) if a.attrs.get("href")]
        if len(links) > 1:
            raise ValueError("Ambiguous Fortinet continuation")
        controls.append(tuple(links))
        for u in links:
            parsed = urlsplit(u)
            target_query = parse_qs(parsed.query)
            if parsed.path != "/psirt" or target_query.get("page") != [str(int(current[0]) + 1)]:
                raise ValueError("Unexpected Fortinet continuation URL")
            if sorted(set(target_query.get("product", [""])[0].split(",")) - {""}) != selected:
                raise ValueError("Fortinet continuation changes product scope")
            if any(
                target_query.get(k)
                for k in ("date", "severity", "component", "discovered", "attack_type", "version")
            ):
                raise ValueError("Fortinet continuation changes filter scope")
            next_pages.append(urljoin(url, quote(u, safe="/?&=,;%")))
    if len(set(controls)) != 1 or not rows:
        raise ValueError("Fortinet controls disagree or listing has no rows")
    return ArchivePage(
        tuple(dict.fromkeys(urls)),
        len(rows),
        missing,
        tuple(dict.fromkeys(next_pages)),
        "Published PSIRT product filter: " + ", ".join(selected),
    )
