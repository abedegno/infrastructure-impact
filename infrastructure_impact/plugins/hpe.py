"""Curated HPE bulletin sources outside Aruba."""

from urllib.parse import parse_qs, urlsplit

from ..adapters.component_statements import hpe_component_statement
from ..adapters.hpe import hpe_bulletin
from ..adapters.vendor_cna import registry_route, vendor_cna
from .contracts import VendorPlugin
from .shared import is_json, structured


def canonicalize(url):
    parsed = urlsplit(url)
    if "/docDisplay" in parsed.path:
        ids = parse_qs(parsed.query).get("docId", [])
        if ids:
            return "https://support.hpe.com/hpesc/public/api/document/" + ids[0]
    return url


def parse(raw, url, vendor):
    if urlsplit(url).hostname == "cveawg.mitre.org":
        return vendor_cna(raw, url, vendor)
    return structured(raw, url, vendor) if is_json(raw) else hpe_bulletin(raw, url, vendor)


def plugin():
    return VendorPlugin(
        "hpe",
        "HPE (other products)",
        ("hpe.com", "cveawg.mitre.org"),
        parse,
        canonicalize=canonicalize,
        reference_filter=lambda url: "aruba" not in url.lower(),
        url_filter=lambda url: (
            (urlsplit(url).hostname or "") == "hpe.com"
            or (urlsplit(url).hostname or "").endswith(".hpe.com")
            or registry_route(url)
        ),
        capabilities=("verified-vendor-cna", "csaf", "html", "component-reference"),
        parse_component_inventory=hpe_component_statement,
        normalizer_dependencies=(hpe_bulletin, vendor_cna, structured),
    )
