"""Built-in and explicitly installed entry-point vendor plugins."""

import inspect
import re
from functools import lru_cache
from hashlib import sha256
from importlib import metadata
from pathlib import Path

from .contracts import VendorPlugin


class PluginRegistry:
    def __init__(self):
        self._plugins: dict[str, VendorPlugin] = {}

    def register(self, plugin: VendorPlugin) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", plugin.id) or plugin.id == "upstream":
            raise ValueError("Invalid or reserved vendor plugin id")
        if plugin.id in self._plugins:
            raise ValueError(f"Vendor plugin already registered: {plugin.id}")
        if not plugin.name.strip() or not plugin.domains or not callable(plugin.parse_document):
            raise ValueError("Plugin requires a name, official domains and a document parser")
        for domain in plugin.domains:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", domain) or "." not in domain:
                raise ValueError(f"Invalid official domain: {domain}")
        if plugin.normalizer_dependencies is not None:
            from .fingerprints import sources

            sources(plugin)  # Fail early if an opted-in dependency cannot be tracked.
        self._plugins[plugin.id] = plugin

    def get(self, vendor: str) -> VendorPlugin:
        try:
            return self._plugins[vendor]
        except KeyError as exc:
            raise ValueError(f"No installed vendor plugin: {vendor}") from exc

    def all(self) -> tuple[VendorPlugin, ...]:
        return tuple(self._plugins.values())

    def names(self) -> dict[str, str]:
        return {plugin.id: plugin.name for plugin in self.all()}

    def normalize(self, raw, url, vendor):
        plugin = self.get(vendor)
        return self.finalize(plugin.parse_document(raw, url, vendor), url, vendor)

    def fingerprint(self, vendor):
        """The same code identity used in normalized advisory revisions."""
        plugin = self.get(vendor)
        if plugin.normalizer_dependencies is not None:
            from .fingerprints import fingerprint

            return fingerprint(plugin)
        from ..adapters.common import ADAPTER_VERSION

        source = inspect.getsourcefile(plugin.parse_document)
        code = Path(source).read_bytes() if source else plugin.version.encode()
        return sha256(ADAPTER_VERSION.encode() + plugin.version.encode() + code).hexdigest()[:16]

    def fingerprint_scheme(self, vendor):
        if self.get(vendor).normalizer_dependencies is None:
            return "legacy-package-v1"
        from .fingerprints import SCHEME

        return SCHEME

    def finalize(self, document, url, vendor):
        import json

        from ..domain import validate_advisory

        document = json.loads(json.dumps(document))
        document["adapter_version"] = self.fingerprint(vendor)
        for field in ("published_at", "updated_at"):
            value = document.get(field)
            if value and "T" in value:
                from datetime import datetime

                if datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
                    document["warnings"].append(
                        f"Publisher {field} has no timezone; UTC is not inferred."
                    )
        validate_advisory(document, vendor=vendor, source_url=url)
        return document


@lru_cache(maxsize=1)
def default_registry() -> PluginRegistry:
    from .builtin import builtin_plugins

    registry = PluginRegistry()
    for plugin in builtin_plugins():
        registry.register(plugin)
    # Installed plugins are trusted application code, not imports named by remote feeds.
    for entry in sorted(
        metadata.entry_points(group="infrastructure_impact.vendors"), key=lambda e: e.name
    ):
        registry.register(entry.load()())
    return registry
