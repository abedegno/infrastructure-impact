"""Validate source configuration before making any network request."""

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from ..plugins.registry import default_registry
from ..settings import PACKAGE, Paths


def validate_config(config):
    if not isinstance(config, dict) or not isinstance(config.get("vendors"), list):
        raise ValueError("Sources configuration must contain a vendor feed list")
    unknown = set(config) - {"vendors", "pinned", "release_documents"}
    if unknown:
        raise ValueError(f"Unknown sources configuration keys: {sorted(unknown)}")
    registry = default_registry()
    for section in ("vendors", "pinned", "release_documents"):
        entries = config.get(section, [])
        if not isinstance(entries, list):
            raise ValueError(f"{section} must be a list")
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("vendor"), str)
                or not isinstance(entry.get("url"), str)
            ):
                raise ValueError("Source entries require string vendor and url fields")
            keys = {"vendor", "url"} | (
                {"kind", "limit", "order"}
                if section == "vendors"
                else {"product", "published_at"}
                if section == "release_documents"
                else set()
            )
            if set(entry) - keys:
                raise ValueError(f"Unknown source-entry keys: {sorted(set(entry) - keys)}")
            plugin = registry.get(entry["vendor"])
            url = urlsplit(entry["url"])
            if url.scheme != "https" or url.username or url.password or url.port not in (None, 443):
                raise ValueError("Configured sources must use HTTPS without credentials")
            if not any(
                url.hostname == d or (url.hostname or "").endswith("." + d) for d in plugin.domains
            ):
                raise ValueError(f"Source URL outside {plugin.id} official domains")
            if section == "vendors":
                if entry.get("kind") not in ("rss", "index", "advisory_index", "checkpoint"):
                    raise ValueError("Unsupported feed discovery kind")
                limit = entry.get("limit", 4)
                if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= 1000:
                    raise ValueError("Source limit must be an integer from 0 to 1000")
                if entry["kind"] in ("advisory_index", "checkpoint") and not plugin.parse_feed:
                    raise ValueError("Advisory index requires a plugin feed parser")
            if section == "release_documents" and not entry.get("product", "").strip():
                raise ValueError("Release documents require a product label")
    return config


def load_config(path=None):
    explicit = path is not None or bool(os.environ.get("IMPACT_SOURCES"))
    path = Path(path) if path else Paths.from_env().sources
    if not path.exists():
        if explicit:
            raise FileNotFoundError(f"Configured sources file not found: {path}")
        path = PACKAGE / "resources/sources.json"
    return validate_config(json.loads(path.read_text()))
