"""HPE Aruba CSAF sources."""

from .contracts import VendorPlugin
from .shared import structured


def plugin():
    return VendorPlugin(
        "aruba",
        "HPE Aruba Networking",
        ("hpe.com", "arubanetworks.com"),
        structured,
        reference_filter=lambda url: "aruba" in url.lower(),
        capabilities=("csaf",),
    )
