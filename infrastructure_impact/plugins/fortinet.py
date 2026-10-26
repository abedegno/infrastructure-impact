"""Fortinet CSAF and scoped product release notes."""

import json
import re

from ..adapters.fortinet import document_history, fortinet_release, investigation_advisory
from .archive_listings import fortinet as archive_listing
from .contracts import VendorPlugin
from .shared import is_json, structured


def parse(raw, url, vendor):
    if "docs.fortinet.com/" in url:
        return fortinet_release(raw, url, vendor)
    if not is_json(raw):
        return investigation_advisory(raw, url, vendor)
    return structured(raw, url, vendor)


def resolve(raw, url, fetch):
    if is_json(raw):
        document = json.loads(raw)
        identity = document.get("document", {}).get("tracking", {}).get("id", "")
        if not document.get("vulnerabilities") and re.fullmatch(r"FG-IR-\d{2}-\d+", identity):
            target = "https://www.fortiguard.com/psirt/" + identity
            html = fetch(target)
            # Only a fully reviewed, identity-matching layout can replace the empty envelope.
            investigation_advisory(html, target, "fortinet")
            return target, html
    return url, raw


def plugin():
    return VendorPlugin(
        "fortinet",
        "Fortinet",
        ("fortinet.com", "fortiguard.com"),
        parse,
        resolve=resolve,
        parse_document_history=document_history,
        parse_archive=archive_listing,
        capabilities=("csaf", "release-notes-html", "investigation-html"),
    )
