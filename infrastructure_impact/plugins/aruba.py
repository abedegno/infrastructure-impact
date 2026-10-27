"""HPE Aruba CSAF sources."""

from ..adapters.aruba_history import aruba_release_history
from .contracts import VendorPlugin
from .shared import structured


def plugin():
    return VendorPlugin(
        "aruba",
        "HPE Aruba Networking",
        ("hpe.com", "arubanetworks.com"),
        structured,
        reference_filter=lambda url: "aruba" in url.lower(),
        capabilities=("csaf", "browser-release-history"),
        parse_release_history=aruba_release_history,
        normalizer_dependencies=(),
    )
