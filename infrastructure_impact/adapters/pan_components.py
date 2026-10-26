"""Publisher OSS references, never an appliance inventory or vulnerability match."""

import re
from collections import defaultdict
from urllib.parse import urlsplit

from .common import HTML

ROUTES = {
    "/oss-listings/pan-os-oss-listings/pan-os-11-1-open-source-software-oss-listing": "PAN-OS 11.1",
    "/oss-listings/pan-os-oss-listings/pan-os-11-2-open-source-software-oss-listing": "PAN-OS 11.2",
    "/oss-listings/panorama-oss-listings/panorama-11-2-open-source-software-oss-listing": "Panorama 11.2",
}
SCOPE = "Feature-release OSS reference without a pinned patch or deployment inventory. No running-appliance version, backport status, vulnerability, or fix is established."
NAMES = {n: n for n in ("openssl", "openssh", "curl", "php", "nginx", "libxml2")}
NAMES["libcurl"] = "curl"
VERSION = r"\d+(?:\.\d+){1,3}[a-z]?(?:p\d+)?(?:[-+][A-Za-z0-9.]+)?"


def component_inventory(raw, url, vendor):
    u = urlsplit(url)
    if u.hostname != "docs.paloaltonetworks.com" or u.path not in ROUTES:
        return None
    if (
        vendor != "paloalto"
        or u.scheme != "https"
        or u.netloc != "docs.paloaltonetworks.com"
        or u.query
        or u.fragment
    ):
        raise ValueError("Unreviewed component listing route")
    root = HTML(raw).root
    expected = ROUTES[u.path] + " OSS Listing"
    titles = [n for n in root.find({"h1"}) if n.text() == expected]
    text = root.text()
    if len(titles) != 1:
        raise ValueError("Reviewed component listing identity changed")
    scope = SCOPE
    if ROUTES[u.path].startswith("PAN-OS"):
        if not all(
            phrase in text
            for phrase in (
                "latest maintenance release",
                "we do not attempt to capture these differences in detail or per product",
            )
        ):
            raise ValueError("Reviewed component listing scope qualification changed")
        scope += " The publisher aims to list the latest maintenance release and warns that multiple versions and product differences may be omitted."
    elif "Open-Source Software (OSS) licensing for the Panorama" not in text:
        raise ValueError("Reviewed Panorama component listing context changed")
    # The reviewed site has a single component table. Navigation cannot supply rows.
    tables = list(root.find({"table"}))
    if len(tables) != 1:
        raise ValueError("Component listing table boundary changed")
    rows = list(tables[0].find({"tr"}))
    if not rows or [n.text() for n in rows[0].find({"th", "td"})] != [
        "NAME",
        "VERSION",
        "LICENSE TYPE",
    ]:
        raise ValueError("Component listing columns changed")
    components = defaultdict(set)
    blocks = []
    for index, row in enumerate(rows[1:], 1):
        cells = [n.text() for n in row.find({"th", "td"})]
        if cells and not any(cells):
            continue  # Reviewed empty formatting row, never a component reference.
        if len(cells) != 3:
            raise ValueError("Component listing row shape changed")
        name = NAMES.get(cells[0].casefold())
        if name is None:
            continue
        versions = re.split(r"\s*[,;/]\s*|\s+", cells[1])
        if not versions or any(not re.fullmatch(VERSION, v) for v in versions):
            raise ValueError("Component listing version syntax requires review")
        components[name].update(versions)
        blocks.append(
            dict(
                locator=expected + " / component row " + str(index),
                text=cells[0] + " " + cells[1],
                cves=[],
            )
        )
    if not components:
        raise ValueError("No reviewed component references in listing")
    return dict(
        state="scoped",
        blocks=blocks,
        components={k: sorted(v) for k, v in components.items()},
        component_scope=scope,
    )
