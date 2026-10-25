"""Cisco source routing and informational-advisory policy."""

from urllib.parse import urlsplit

from ..adapters.legacy_html import html_advisory
from .contracts import VendorPlugin
from .shared import is_json, structured


def parse(raw, url, vendor):
    return structured(raw, url, vendor) if is_json(raw) else html_advisory(raw, url, vendor)


def canonicalize(url):
    if "/security/center/content/" in url:
        return "https://sec.cloudapps.cisco.com" + urlsplit(url).path
    if "/.well-known/csaf/" in url and url.endswith(".json"):
        name = urlsplit(url).path.rsplit("/", 1)[-1]
        return f"https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/{name[:-5]}/csaf/{name}"
    return url


def plugin():
    return VendorPlugin(
        "cisco",
        "Cisco",
        ("cisco.com",),
        parse,
        canonicalize=canonicalize,
        non_cve_notice=lambda d: not d["cves"] and d["title"].startswith("Cisco Informational"),
        capabilities=("csaf", "cve-json", "html"),
    )
