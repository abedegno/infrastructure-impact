"""Juniper RSS discovery and explicitly reviewed public PDF scopes."""

from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET

from ..adapters.common import base, cves
from ..adapters.juniper import juniper_pdf
from .contracts import FeedBatch, VendorPlugin
from .shared import structured


def metadata(raw, url, vendor, item):
    document = base(
        vendor, url, item.findtext("guid") or item.findtext("link"), item.findtext("title")
    )
    document.update(
        cves=cves(document["title"]),
        source_format="RSS discovery metadata",
        document_status="published",
        advisory_url=item.findtext("link"),
    )
    if item.findtext("pubDate"):
        document["published_at"] = parsedate_to_datetime(item.findtext("pubDate")).isoformat()
    document["warnings"] = [
        "RSS title proves discovery only. Article application shells do not establish product impact or fixes."
    ]
    return document


def parse_feed(raw, url, limit, cohort):
    items = ET.fromstring(raw).findall(".//item")
    records = tuple(
        metadata(raw, url, "juniper", item)
        for i, item in enumerate(items)
        if (i < limit or set(cves(item.findtext("title") or "")) & cohort)
        and cves(item.findtext("title") or "")
    )
    return FeedBatch(
        records,
        frozenset(c for item in items for c in cves(item.findtext("title") or "")),
        f"Current RSS window ({len(items)} entries); discovery metadata only",
        "partial",
    )


def parse(raw, url, vendor):
    return (
        juniper_pdf(raw, url, vendor)
        if isinstance(raw, bytes) and raw.startswith(b"%PDF")
        else structured(raw, url, vendor)
    )


def plugin():
    return VendorPlugin(
        "juniper",
        "Juniper",
        ("juniper.net",),
        parse,
        parse_feed=parse_feed,
        capabilities=("rss-discovery", "scoped-pdf"),
    )
