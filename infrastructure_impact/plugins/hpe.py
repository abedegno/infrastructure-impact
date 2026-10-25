"""Curated HPE bulletin sources outside Aruba."""

from urllib.parse import parse_qs, urlsplit

from ..adapters.hpe import hpe_bulletin
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
    return structured(raw, url, vendor) if is_json(raw) else hpe_bulletin(raw, url, vendor)


def plugin():
    return VendorPlugin(
        "hpe",
        "HPE (other products)",
        ("hpe.com",),
        parse,
        canonicalize=canonicalize,
        reference_filter=lambda url: "aruba" not in url.lower(),
        capabilities=("csaf", "html"),
    )
