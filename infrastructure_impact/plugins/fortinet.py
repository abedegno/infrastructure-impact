"""Fortinet CSAF and scoped product release notes."""

from ..adapters.fortinet import fortinet_release
from .contracts import VendorPlugin
from .shared import structured


def parse(raw, url, vendor):
    if "docs.fortinet.com/" in url:
        return fortinet_release(raw, url, vendor)
    return structured(raw, url, vendor)


def plugin():
    return VendorPlugin(
        "fortinet",
        "Fortinet",
        ("fortinet.com", "fortiguard.com"),
        parse,
        capabilities=("csaf", "release-notes-html"),
    )
