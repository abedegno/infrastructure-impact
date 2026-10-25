"""Public product index and detailed SK article precedence."""

from ..adapters.checkpoint import checkpoint_article, checkpoint_records
from .contracts import FeedBatch, VendorPlugin


def parse_feed(raw, url, limit, cohort):
    records = checkpoint_records(raw, url)
    selected = tuple(r for i, r in enumerate(records) if i < limit or set(r["cves"]) & cohort)
    return FeedBatch(
        selected,
        frozenset(c for r in records for c in r["cves"]),
        "All active entries returned by public product advisory API; historical/archive coverage unknown",
    )


def plugin():
    return VendorPlugin(
        "checkpoint",
        "Check Point",
        ("checkpoint.com",),
        checkpoint_article,
        parse_feed=parse_feed,
        prefer_existing=lambda old, new: (
            old.get("source_format") == "Public SK article embedded JSON"
        ),
        capabilities=("public-product-index", "embedded-json-html"),
    )
