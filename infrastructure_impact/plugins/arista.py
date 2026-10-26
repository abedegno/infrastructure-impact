"""Arista reviewed historical and current HTML layouts."""

from ..adapters.arista import arista_aggregate_notice, arista_software
from ..adapters.arista_history import arista_release_history
from ..adapters.common import HTML
from ..adapters.legacy_html import html_advisory
from .archive_listings import arista as archive_listing
from .contracts import VendorPlugin
from .shared import is_json, structured


def parse(raw, url, vendor):
    if is_json(raw):
        return structured(raw, url, vendor)
    if url.rstrip("/").endswith("/24776-security-advisory-0184"):
        return arista_aggregate_notice(raw, url, vendor)
    if "Affected Software" in HTML(raw).root.text():
        return arista_software(raw, url, vendor)
    return html_advisory(raw, url, vendor)


def plugin():
    return VendorPlugin(
        "arista",
        "Arista",
        ("arista.com",),
        parse,
        parse_archive=archive_listing,
        capabilities=("csaf", "html", "browser-release-history"),
        parse_release_history=arista_release_history,
    )
