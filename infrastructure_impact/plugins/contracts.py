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
