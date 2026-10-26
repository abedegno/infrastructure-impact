"""Example extension. acme.example is reserved; no real vendor claims are made."""

import json

from infrastructure_impact.plugins import ArchivePage, VendorPlugin
from infrastructure_impact.plugins.shared import structured


def archive(raw, url, vendor):
    # Synthetic example publisher index; the hook discovers links, never claims.
    urls = tuple(json.loads(raw)["advisory_urls"])
    return ArchivePage(urls, len(urls), scope="Example publisher JSON listing")


def plugin():
    return VendorPlugin(
        id="acme",
        name="Acme Example Networking",
        domains=("acme.example",),
        parse_document=structured,
        parse_archive=archive,
        version="0.1.1",
        capabilities=("csaf", "cve-json"),
    )
