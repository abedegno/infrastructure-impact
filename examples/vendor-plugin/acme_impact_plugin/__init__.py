"""Example extension. acme.example is reserved; no real vendor claims are made."""

import json

from infrastructure_impact.plugins import ArchivePage, VendorPlugin
from infrastructure_impact.plugins.shared import structured


def archive(raw, url, vendor):
    # Synthetic example publisher index; the hook discovers links, never claims.
    urls = tuple(json.loads(raw)["advisory_urls"])
    return ArchivePage(urls, len(urls), scope="Example publisher JSON listing")


def component_inventory(raw, url, vendor):
    if url != "https://security.acme.example/components.json":
        return None
    if vendor != "acme":
        raise ValueError("Example component source vendor mismatch")
    # Synthetic source protocol only. The registry validates the returned JSON
    # against the common contract; this is never a CVE affectedness parser.
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("component_reference") is None:
        raise ValueError("Example component source layout changed")
    return document["component_reference"]


def plugin():
    return VendorPlugin(
        id="acme",
        name="Acme Example Networking",
        domains=("acme.example",),
        parse_document=structured,
        parse_archive=archive,
        parse_component_inventory=component_inventory,
        version="0.1.2",
        capabilities=("csaf", "cve-json", "component-inventory"),
    )
