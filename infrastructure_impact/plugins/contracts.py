"""Vendor extension boundary. Plugins normalize sources, never write storage."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

Advisory = dict[str, Any]


class DocumentParser(Protocol):
    def __call__(self, raw: bytes | str, url: str, vendor: str) -> Advisory: ...


@dataclass(frozen=True)
class FeedBatch:
    """Selected normalized records and scope of the entire index inspected."""

    records: tuple[Advisory, ...]
    referenced_cves: frozenset[str]
    scope: str
    outcome: str = "ok"
    document_urls: tuple[str, ...] = ()

    def __post_init__(self):
        if (
            not isinstance(self.document_urls, tuple)
            or len(self.document_urls) > 20
            or any(not isinstance(u, str) or not u for u in self.document_urls)
        ):
            raise ValueError("Feed document targets must be a tuple of at most 20 URLs")


@dataclass(frozen=True)
class VendorPlugin:
    id: str
    name: str
    domains: tuple[str, ...]
    parse_document: DocumentParser
    version: str = "1"
    parse_feed: Callable[[bytes, str, int, frozenset[str]], FeedBatch] | None = None
    canonicalize: Callable[[str], str] = lambda url: url
    resolve: Callable[[bytes, str, Callable[[str], bytes]], tuple[str, bytes]] | None = None
    prefer_existing: Callable[[Advisory, Advisory], bool] = lambda old, new: False
    non_cve_notice: Callable[[Advisory], bool] = lambda document: False
    reference_filter: Callable[[str], bool] = lambda url: True
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    parse_release: DocumentParser | None = None
    parse_release_history: DocumentParser | None = None
    parse_archive: Callable[[bytes, str, str], "ArchivePage"] | None = None
    parse_document_history: Callable[[bytes, str, str], dict | None] | None = None
    url_filter: Callable[[str], bool] = lambda url: True
    retain_unlinked_notice: Callable[[Advisory], bool] = lambda document: False
    parse_component_inventory: Callable[[bytes, str, str], dict | None] | None = None


@dataclass(frozen=True)
class ArchivePage:
    """Pure discovery result; listing entries never establish product exposure."""

    urls: tuple[str, ...]
    entry_count: int
    entries_without_links: int = 0
    next_pages: tuple[str, ...] = ()
    scope: str = ""

    def __post_init__(self):
        if not isinstance(self.scope, str):
            raise ValueError("Archive scope must be a string")
        for value in (self.entry_count, self.entries_without_links):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("Archive counts must be nonnegative integers")
        if len(set(self.urls)) + self.entries_without_links > self.entry_count:
            raise ValueError("Archive entries do not account for discovery results")
        for links in (self.urls, self.next_pages):
            if not isinstance(links, tuple) or any(not isinstance(u, str) or not u for u in links):
                raise ValueError("Archive URLs must be tuples of nonempty strings")


class SourceNotApplicable(ValueError):
    """Retained source is explicitly outside the requested vendor evidence scope."""
