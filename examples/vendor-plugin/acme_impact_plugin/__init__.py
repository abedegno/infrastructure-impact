"""Example extension. acme.example is reserved; no real vendor claims are made."""
from infrastructure_impact.plugins import VendorPlugin
from infrastructure_impact.plugins.shared import structured


def plugin():
    return VendorPlugin(
        id="acme",
        name="Acme Example Networking",
        domains=("acme.example",),
        parse_document=structured,
        version="0.1.0",
        capabilities=("csaf", "cve-json"),
    )
