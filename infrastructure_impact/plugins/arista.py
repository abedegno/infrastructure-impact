"""Arista reviewed historical and current HTML layouts."""

from ..adapters.arista import arista_software
from ..adapters.common import HTML
from ..adapters.legacy_html import html_advisory
from .contracts import VendorPlugin
from .shared import is_json, structured


def parse(raw, url, vendor):
    if is_json(raw):
        return structured(raw, url, vendor)
    if "Affected Software" in HTML(raw).root.text():
        return arista_software(raw, url, vendor)
    return html_advisory(raw, url, vendor)


def plugin():
    return VendorPlugin("arista", "Arista", ("arista.com",), parse, capabilities=("csaf", "html"))
