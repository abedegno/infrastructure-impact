"""Fortinet CSAF and scoped product release notes."""

from ..adapters.fortinet import fortinet_release
from .archive_listings import fortinet as archive_listing
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
        parse_archive=archive_listing,
        capabilities=("csaf", "release-notes-html"),
    )
