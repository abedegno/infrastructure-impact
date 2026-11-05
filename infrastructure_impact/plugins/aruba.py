"""HPE Aruba CSAF sources."""

from ..adapters.aruba_history import aruba_release_history
from ..adapters.aruba_text import parse as text_parse
from ..adapters.switching import extract
from .archive_listings import aruba as archive
from .contracts import VendorPlugin
from .shared import is_json, structured


def parse(raw, url, vendor):
    return structured(raw, url, vendor) if is_json(raw) else text_parse(raw, url, vendor)


def plugin():
    return VendorPlugin(
        "aruba",
        "HPE Aruba Networking",
        ("hpe.com", "arubanetworks.com"),
        parse,
        reference_filter=lambda url: "aruba" in url.lower(),
        capabilities=("csaf", "browser-release-history", "archive-listing", "historical-text"),
        parse_archive=archive,
        parse_release_history=aruba_release_history,
        research_evidence=extract,
        normalizer_dependencies=(structured, text_parse),
    )
