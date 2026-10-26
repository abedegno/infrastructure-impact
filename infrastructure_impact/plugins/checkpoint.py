"""Public product index and detailed SK article precedence."""

from urllib.parse import urlsplit

from ..adapters.checkpoint import checkpoint_article, checkpoint_records, checkpoint_release_listing
from ..adapters.checkpoint_blog import checkpoint_blog
from ..adapters.vendor_cna import registry_route, vendor_cna
from .contracts import FeedBatch, VendorPlugin


def parse_feed(raw, url, limit, cohort):
    records = checkpoint_records(raw, url)
    selected = tuple(r for i, r in enumerate(records) if i < limit or set(r["cves"]) & cohort)
    return FeedBatch(
        selected,
        frozenset(c for r in records for c in r["cves"]),
        "All active entries returned by public product advisory API; historical/archive coverage unknown; up to eight selected CVE registry follow-ups require separate Check Point CNA verification",
        document_urls=tuple(
            "https://cveawg.mitre.org/api/cve/" + cid
            for cid in sorted({cid for row in selected for cid in row["cves"]})[:8]
        ),
    )


def parse(raw, url, vendor):
    if urlsplit(url).hostname == "cveawg.mitre.org":
        return vendor_cna(raw, url, vendor)
    return (
        checkpoint_blog(raw, url, vendor)
        if urlsplit(url).hostname == "blog.checkpoint.com"
        else checkpoint_article(raw, url, vendor)
    )


def plugin():
    return VendorPlugin(
        "checkpoint",
        "Check Point",
        ("checkpoint.com", "cveawg.mitre.org"),
        parse,
        parse_feed=parse_feed,
        parse_release=checkpoint_release_listing,
        prefer_existing=lambda old, new: (
            old.get("source_format") == "Public SK article embedded JSON"
        ),
        url_filter=lambda url: (
            (urlsplit(url).hostname or "") == "checkpoint.com"
            or (urlsplit(url).hostname or "").endswith(".checkpoint.com")
            or registry_route(url)
        ),
        capabilities=("verified-vendor-cna", "public-product-index", "embedded-json-html"),
    )
