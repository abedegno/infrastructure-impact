"""Palo Alto JSON sources and HTML-only per-CVE tables."""

import re

from ..adapters.common import HTML
from ..adapters.paloalto import pan_impact_bulletin, pan_oss_bulletin
from .contracts import VendorPlugin
from .shared import is_json, structured


def parse(raw, url, vendor):
    if is_json(raw):
        return structured(raw, url, vendor)
    if "Impact of OSS CVEs in PAN-OS" in HTML(raw).root.text():
        return pan_impact_bulletin(raw, url, vendor)
    return pan_oss_bulletin(raw, url, vendor)


def resolve(raw, url, fetch):
    if is_json(raw) or "/PAN-SA-" in url:
        return url, raw
    match = re.search(r"/(CVE-\d{4}-\d+)", url)
    if match:
        target = "https://security.paloaltonetworks.com/json/" + match[1]
        return target, fetch(target)
    return url, raw


def plugin():
    return VendorPlugin(
        "paloalto",
        "Palo Alto Networks",
        ("paloaltonetworks.com",),
        parse,
        resolve=resolve,
        capabilities=("cve-json", "html"),
    )
