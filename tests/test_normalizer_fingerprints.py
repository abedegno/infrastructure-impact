"""Code identity must track real dependencies without unrelated-vendor churn."""

import ast
import inspect
import json
from dataclasses import replace
from hashlib import sha256
from importlib.util import resolve_name
from pathlib import Path

import pytest

from infrastructure_impact.adapters import common
from infrastructure_impact.adapters.arista_routing_scope import routing_scope
from infrastructure_impact.plugins import fingerprints
from infrastructure_impact.plugins.contracts import VendorPlugin
from infrastructure_impact.plugins.registry import PluginRegistry, default_registry
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.settings import PACKAGE
from infrastructure_impact.storage.repository import connect, ingest


def versions():
    registry = default_registry()
    return {p.id: registry.fingerprint(p.id) for p in registry.all()}


@pytest.mark.parametrize(
    "filename,affected",
    [
        ("adapters/juniper_apstra.py", {"juniper"}),
        ("adapters/fortinet_ranges.py", {"fortinet"}),
        ("adapters/f5_pdf.py", {"f5"}),
        ("adapters/arista_routing_scope.py", {"arista"}),
        ("adapters/arista_management_scope.py", {"arista"}),
        ("adapters/component_statements.py", {"hpe", "juniper"}),
        ("adapters/vendor_cna.py", {"cisco", "hpe", "juniper", "checkpoint"}),
        (
            "schemas/advisory-v2.json",
            {
                "cisco",
                "aruba",
                "arista",
                "paloalto",
                "juniper",
                "checkpoint",
                "fortinet",
                "hpe",
                "f5",
            },
        ),
        (
            "resources/benchmark-cohort.json",
            {
                "cisco",
                "aruba",
                "arista",
                "paloalto",
                "juniper",
                "checkpoint",
                "fortinet",
                "hpe",
                "f5",
            },
        ),
        (
            "schemas/component-inventory-v1.json",
            {
                "cisco",
                "aruba",
                "arista",
                "paloalto",
                "juniper",
                "checkpoint",
                "fortinet",
                "hpe",
                "f5",
            },
        ),
    ],
)
def test_vendor_and_shared_source_changes_affect_only_their_dependents(
    monkeypatch, filename, affected
):
    before = versions()
    original = Path.read_bytes
    target = (PACKAGE / filename).resolve()

    def edited(path):
        raw = original(path)
        return raw + b"\nSYNTHETIC CODE IDENTITY CHANGE\n" if path.resolve() == target else raw

    monkeypatch.setattr(Path, "read_bytes", edited)
    after = versions()
    assert {v for v in before if before[v] != after[v]} == affected


def test_package_wide_legacy_hash_does_not_leak_into_scoped_plugins(monkeypatch):
    before = versions()
    monkeypatch.setattr(common, "ADAPTER_VERSION", "synthetic-unrelated-module-change")
    assert versions() == before
    assert all(default_registry().fingerprint_scheme(v) == "scoped-code-v1" for v in before)


def test_external_plugin_keeps_the_exact_legacy_algorithm_until_opt_in(monkeypatch):
    plugin = VendorPlugin(
        "example", "Synthetic", ("example.invalid",), structured, version="fixture-1"
    )
    registry = PluginRegistry()
    registry.register(plugin)
    expected = sha256(
        common.ADAPTER_VERSION.encode()
        + plugin.version.encode()
        + Path(inspect.getsourcefile(structured)).read_bytes()
    ).hexdigest()[:16]
    assert registry.fingerprint("example") == expected
    assert registry.fingerprint_scheme("example") == "legacy-package-v1"
    monkeypatch.setattr(common, "ADAPTER_VERSION", "synthetic-new-package-version")
    assert registry.fingerprint("example") != expected


def test_dependency_order_duplicates_and_version_are_explicit():
    plugin = default_registry().get("arista")
    original = fingerprints.fingerprint(plugin)
    reordered = replace(
        plugin,
        normalizer_dependencies=tuple(reversed(plugin.normalizer_dependencies))
        + (routing_scope, routing_scope),
    )
    assert fingerprints.fingerprint(reordered) == original
    assert (
        fingerprints.fingerprint(replace(plugin, version="changed-runtime-dependency")) != original
    )


def test_relocating_source_files_does_not_change_code_identity(tmp_path, monkeypatch):
    plugin = default_registry().get("arista")
    expected = fingerprints.fingerprint(plugin)
    original = inspect.getsourcefile
    path = Path(original(routing_scope))
    relocated = tmp_path / path.name
    relocated.write_bytes(path.read_bytes())
    monkeypatch.setattr(
        inspect,
        "getsourcefile",
        lambda callback: str(relocated) if callback is routing_scope else original(callback),
    )
    assert fingerprints.fingerprint(plugin) == expected
    assert str(tmp_path) not in json.dumps(list(fingerprints.sources(plugin).values()))


@pytest.mark.parametrize("dependencies", [[structured], ("remote.module.name",), (len,)])
def test_invalid_or_uninspectable_dependencies_fail_during_registration(dependencies):
    plugin = VendorPlugin(
        "example",
        "Synthetic",
        ("example.invalid",),
        structured,
        normalizer_dependencies=dependencies,
    )
    with pytest.raises(ValueError, match="normalizer dependenc"):
        PluginRegistry().register(plugin)


def test_builtin_declarations_cover_all_imported_adapter_and_shared_helper_modules():
    """A new helper import cannot silently escape a built-in's declaration."""
    for plugin in default_registry().all():
        assert plugin.normalizer_dependencies is not None
        included = set(fingerprints.sources(plugin))
        for source in included:
            if source.suffix != ".py" or source.parent.name not in {"adapters", "plugins"}:
                continue
            package = "infrastructure_impact." + ".".join(source.relative_to(PACKAGE).parts[:-1])
            for node in ast.walk(ast.parse(source.read_text())):
                if not isinstance(node, ast.ImportFrom) or not node.module:
                    continue
                module = (
                    resolve_name("." * node.level + node.module, package)
                    if node.level
                    else node.module
                )
                if (
                    module.startswith("infrastructure_impact.adapters.")
                    or module == "infrastructure_impact.plugins.shared"
                ):
                    dependency = (
                        PACKAGE
                        / (module.removeprefix("infrastructure_impact.").replace(".", "/") + ".py")
                    ).resolve()
                    assert dependency in included, (plugin.id, source.name, module)


def test_normalized_advisory_and_archive_replay_use_the_same_scoped_fingerprint():
    registry = default_registry()
    raw = json.dumps(
        {
            "document": {"title": "Synthetic", "tracking": {"id": "SYNTHETIC-1"}},
            "vulnerabilities": [{"cve": "CVE-2099-12345"}],
        }
    ).encode()
    record = registry.normalize(raw, "https://www.arubanetworks.com/synthetic.json", "aruba")
    assert record["adapter_version"] == registry.fingerprint("aruba")


def test_scheme_transition_preserves_evidence_and_does_not_invent_publisher_changes():
    registry = default_registry()
    legacy = PluginRegistry()
    legacy.register(replace(registry.get("aruba"), normalizer_dependencies=None))
    raw = json.dumps(
        {
            "document": {"title": "Synthetic", "tracking": {"id": "SYNTHETIC-1"}},
            "vulnerabilities": [{"cve": "CVE-2099-12345"}],
        }
    ).encode()
    url = "https://www.arubanetworks.com/synthetic.json"
    old = legacy.normalize(raw, url, "aruba")
    new = registry.normalize(raw, url, "aruba")
    assert old["adapter_version"] != new["adapter_version"]
    with connect(":memory:") as db:
        assert ingest(db, raw, url, lambda *_: old, "aruba")
        assert ingest(db, raw, url, lambda *_: new, "aruba")
        assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM changes").fetchone()[0] == 0
