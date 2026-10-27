"""Vendor extension boundary. Plugins normalize sources, never write storage."""

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, NotRequired, Protocol, TypedDict

Advisory = dict[str, Any]


class ComponentBlock(TypedDict):
    locator: str
    text: str
    cves: list[str]


class ComponentInventory(TypedDict):
    """Literal version references, separate from CVE applicability assertions."""

    state: Literal["scoped"]
    blocks: list[ComponentBlock]
    components: dict[str, list[str]]
    component_scope: str
    schema_version: NotRequired[int]  # Registry supplies v1 for existing hooks.
    extensions: NotRequired[dict[str, Any]]


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
class SourceView:
    """One parsed publisher representation; counts describe claims, not products."""

    url: str
    raw: bytes
    format: str
    assessments: int
    adapter_version: str

    def __post_init__(self):
        if (
            not isinstance(self.url, str)
            or not self.url
            or not isinstance(self.raw, bytes)
            or not self.raw
            or not isinstance(self.format, str)
            or not self.format.strip()
            or type(self.assessments) is not int
            or self.assessments < 0
            or not isinstance(self.adapter_version, str)
            or not 1 <= len(self.adapter_version) <= 128
        ):
            raise ValueError("Invalid source representation")


@dataclass(frozen=True)
class SourceViewIssue:
    """An unavailable alternative, without response bodies or request secrets."""

    url: str
    error_code: str

    def __post_init__(self):
        if (
            not isinstance(self.url, str)
            or not self.url
            or not isinstance(self.error_code, str)
            or not re.fullmatch(r"[a-z][a-z_]{0,63}", self.error_code)
        ):
            raise ValueError("Invalid source representation issue")


@dataclass(frozen=True)
class SourceSelection:
    """An explicit reviewed source choice, replacing automatic CSAF-link following.

    Legacy resolvers may still return (url, raw). Every view must be retrieved
    through the supplied allowlisted fetch callback and validated by the plugin.
    """

    selected: SourceView
    alternatives: tuple[SourceView, ...]
    reason: str
    unavailable: tuple[SourceViewIssue, ...] = ()

    def __post_init__(self):
        if (
            not isinstance(self.selected, SourceView)
            or not isinstance(self.alternatives, tuple)
            or len(self.alternatives) > 4
            or not isinstance(self.unavailable, tuple)
            or not 1 <= len(self.alternatives) + len(self.unavailable) <= 4
            or any(not isinstance(v, SourceViewIssue) for v in self.unavailable)
            or any(not isinstance(v, SourceView) for v in self.alternatives)
            or not isinstance(self.reason, str)
            or not self.reason.strip()
            or len(self.reason) > 500
        ):
            raise ValueError("Invalid reviewed source selection")
        urls = (
            [self.selected.url]
            + [v.url for v in self.alternatives]
            + [v.url for v in self.unavailable]
        )
        if len(set(urls)) != len(urls):
            raise ValueError("Source representations require distinct URLs")


@dataclass(frozen=True)
class VendorPlugin:
    id: str
    name: str
    domains: tuple[str, ...]
    parse_document: DocumentParser
    version: str = "1"
    parse_feed: Callable[[bytes, str, int, frozenset[str]], FeedBatch] | None = None
    canonicalize: Callable[[str], str] = lambda url: url
    resolve: (
        Callable[[bytes, str, Callable[[str], bytes]], tuple[str, bytes] | SourceSelection] | None
    ) = None
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
    parse_component_inventory: Callable[[bytes, str, str], ComponentInventory | None] | None = None
    # None preserves the legacy package fingerprint. A tuple opts into scoped
    # hook/shared-source hashing and declares additional Python helper modules.
    normalizer_dependencies: tuple[Callable, ...] | None = None


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
