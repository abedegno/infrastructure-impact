"""Stable, scoped code identities for explicitly opted-in normalization plugins."""

import inspect
import json
from dataclasses import fields
from hashlib import sha256
from pathlib import Path

from ..settings import PACKAGE

SCHEME = "scoped-code-v1"
SHARED_SOURCES = tuple(
    ("core:" + name, PACKAGE / name)
    for name in (
        "adapters/common.py",
        "adapters/standards.py",
        "domain.py",
        "plugins/contracts.py",
        "plugins/registry.py",
        "plugins/fingerprints.py",
        "schemas/advisory-v2.json",
        "schemas/component-inventory-v1.json",
        "source_policy.py",
        # Two scoped PDF adapters use this public cohort in CVE extraction.
        "application/cohort.py",
        "resources/benchmark-cohort.json",
    )
)


def sources(plugin):
    """Return local source files; caller metadata and remote feeds cannot name paths."""
    dependencies = plugin.normalizer_dependencies
    if not isinstance(dependencies, tuple) or any(not callable(d) for d in dependencies):
        raise ValueError("Scoped normalizer dependencies must be a tuple of Python callables")
    result = {}

    def include(label, path):
        path = Path(path).resolve()
        if not path.is_file():
            raise ValueError("Normalizer source unavailable: " + label)
        # A module can be reached by several hooks/helpers. Include it once with
        # a deterministic label; machine-specific absolute paths are never hashed.
        result[path] = min(label, result.get(path, label))

    for label, path in SHARED_SOURCES:
        include(label, path)
    callbacks = [
        getattr(plugin, f.name) for f in fields(plugin) if callable(getattr(plugin, f.name))
    ]
    for callback in callbacks + list(dependencies):
        module = getattr(callback, "__module__", None)
        try:
            path = inspect.getsourcefile(callback)
        except TypeError as error:
            raise ValueError(
                "Scoped normalizer dependency needs inspectable Python source"
            ) from error
        if not module or not path:
            raise ValueError("Scoped normalizer dependency needs inspectable Python source")
        include("module:" + module + ":" + Path(path).name, path)
    return result


def fingerprint(plugin):
    identities = []
    for path, label in sources(plugin).items():
        try:
            digest = sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            raise ValueError("Normalizer source unreadable: " + label) from error
        identities.append([label, digest])
    payload = {
        "scheme": SCHEME,
        "plugin": plugin.id,
        "version": plugin.version,
        "sources": sorted(identities),
    }
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[
        :16
    ]
