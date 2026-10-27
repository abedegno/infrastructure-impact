"""Every installed component hook uses one checked, private writer contract."""

import copy
import json
from dataclasses import replace

import pytest

from infrastructure_impact.application import fix_leads
from infrastructure_impact.application.disclosure import import_release_note
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.collection import service
from infrastructure_impact.domain import NormalizationError
from infrastructure_impact.plugins import PluginRegistry, VendorPlugin
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.storage.repository import connect, health

URL = "https://support.hpe.com/component-contract-synthetic"


def reference():
    return {
        "state": "scoped",
        "blocks": [
            {
                "locator": "Synthetic component row",
                "text": "OpenSSH 9.4 PRIVATE_BLOCK_SENTINEL",
                "cves": [],
            }
        ],
        "components": {"openssh": ["9.4"]},
        "component_scope": "Synthetic iLO release example; installation and patch applicability unknown.",
        "extensions": {"private_note": "PRIVATE_EXTENSION_SENTINEL"},
    }


def registry_for(result):
    registry = PluginRegistry()
    registry.register(
        VendorPlugin(
            "acme",
            "Example",
            ("acme.example",),
            structured,
            parse_component_inventory=lambda raw, url, vendor: result,
        )
    )
    return registry


def test_existing_hook_gets_versioned_isolated_output_without_mutation():
    source = reference()
    result = registry_for(source).normalize_component_inventory(b"synthetic", URL, "acme")
    assert result["schema_version"] == 1 and "schema_version" not in source
    result["components"]["openssh"].append("9.5")
    assert source["components"] == {"openssh": ["9.4"]}


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("state", "affected"),
        ("components", {}),
        ("components", {"openssh": "9.4"}),
        ("components", {"openssh": []}),
        ("components", {"openssh": [" "]}),
        ("components", {"openssh": ["9.4", "9.4"]}),
        ("components", {"../private": ["9.4"]}),
        ("blocks", []),
        ("blocks", [{"locator": "x", "text": "y", "cves": ["CVE-foo"]}]),
        ("blocks", [{"locator": " ", "text": "y", "cves": []}]),
        ("blocks", [{"locator": "x", "text": 1, "cves": []}]),
        ("blocks", [{"locator": "x", "text": "y", "cves": [], "status": "affected"}]),
        ("component_scope", " "),
        ("extensions", []),
        ("unexpected", "PRIVATE_VALUE_SENTINEL"),
    ],
)
def test_malformed_component_results_are_rejected_without_logging_values(field, value):
    result = reference()
    result[field] = value
    with pytest.raises(NormalizationError, match="Component reference") as error:
        registry_for(result).normalize_component_inventory(b"synthetic", URL, "acme")
    assert "PRIVATE_VALUE_SENTINEL" not in str(error.value)
    assert "PRIVATE_EXTENSION_SENTINEL" not in str(error.value)


@pytest.mark.parametrize("result", [[], False, "private source text"])
def test_hook_must_return_an_object_or_none(result):
    with pytest.raises(NormalizationError, match="JSON object"):
        registry_for(result).normalize_component_inventory(b"synthetic", URL, "acme")


@pytest.mark.parametrize("value", [{1, 2}, float("nan")])
def test_non_json_extensions_do_not_escape_validation(value):
    result = reference()
    result["extensions"]["unsupported"] = value
    with pytest.raises(NormalizationError, match="JSON values"):
        registry_for(result).normalize_component_inventory(b"synthetic", URL, "acme")


def test_none_retains_the_unrelated_route_contract():
    assert registry_for(None).normalize_component_inventory(b"synthetic", URL, "acme") is None
    assert default_registry().normalize_component_inventory(b"synthetic", URL, "aruba") is None


def install_hook(monkeypatch, result):
    registry = PluginRegistry()
    for plugin in default_registry().all():
        registry.register(
            replace(plugin, parse_component_inventory=lambda *args: copy.deepcopy(result))
            if plugin.id == "hpe"
            else plugin
        )
    monkeypatch.setattr("infrastructure_impact.plugins.registry.default_registry", lambda: registry)
    monkeypatch.setattr(service, "default_registry", lambda: registry)
    monkeypatch.setattr(fix_leads, "default_registry", lambda: registry)
    return registry


def test_collection_rejects_bad_hook_before_replacing_a_retained_baseline(tmp_path, monkeypatch):
    invalid = reference()
    invalid["components"]["openssh"] = "9.5"
    install_hook(monkeypatch, invalid)
    path = tmp_path / "evidence.sqlite3"
    with connect(path) as db:
        import_release_note(db, b"<h1>Old source</h1>", URL, "hpe", "Synthetic product")
    monkeypatch.setattr(service, "fetch", lambda *args: b"<h1>New source</h1>")
    outcome = service.run(
        {
            "vendors": [],
            "release_documents": [
                {
                    "vendor": "hpe",
                    "url": URL,
                    "product": "Synthetic product",
                    "kind": "component_inventory",
                }
            ],
        },
        db_path=path,
    )
    assert outcome == (0, 1)
    with connect(path) as db:
        assert db.execute("SELECT count(*) FROM documents").fetchone()[0] == 1
        assert db.execute("SELECT text FROM documents").fetchone()[0] == "Old source"
        assert health(db)[0]["error_code"] == "unsupported_or_invalid_document"


def test_invalid_research_output_is_a_gap_without_generic_fallback(monkeypatch):
    invalid = reference()
    invalid["blocks"] = "invalid"
    install_hook(monkeypatch, invalid)
    monkeypatch.setattr(
        fix_leads, "scoped_release", lambda raw: pytest.fail("Must not widen invalid hook scope")
    )
    result = fix_leads.scoped_document(b"synthetic", URL, "hpe")
    assert result["state"] == "component_inventory_layout_requires_review"
    assert not result["components"] and not result["blocks"]


def test_none_can_fall_back_to_existing_release_section_analysis(monkeypatch):
    install_hook(monkeypatch, None)
    fallback = {"state": "synthetic_fallback"}
    monkeypatch.setattr(fix_leads, "scoped_release", lambda raw: fallback)
    assert fix_leads.scoped_document(b"synthetic", URL, "hpe") == fallback


def test_component_contract_does_not_publish_raw_blocks_or_private_extensions(
    tmp_path, monkeypatch
):
    install_hook(monkeypatch, reference())
    with connect(":memory:") as db:
        import_release_note(db, b"<h1>PRIVATE_RAW_SENTINEL</h1>", URL, "hpe", "Synthetic product")
        generation = publish(state(db), root=tmp_path, public_release_urls=[URL])
    public = json.loads((tmp_path / "current/snapshot.json").read_text())
    assert public["fix_leads"]["sources"][0]["components"] == {"openssh": ["9.4"]}
    for path in (tmp_path / "generations" / generation).rglob("*"):
        if path.is_file():
            assert b"PRIVATE_" not in path.read_bytes(), path.name
    assert (tmp_path / "current/schemas/component-inventory-v1.json").is_file()
    from infrastructure_impact.http import Application

    statuses = []
    body = b"".join(
        Application(tmp_path)(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/schemas/component-inventory-v1.json",
                "QUERY_STRING": "",
            },
            lambda status, headers: statuses.append(status),
        )
    )
    assert statuses == ["200 OK"]
    assert json.loads(body)["$id"] == "urn:infrastructure-impact:component-inventory:1"


def test_cli_component_validation_uses_the_same_contract(tmp_path, capsys):
    from infrastructure_impact.cli import main

    document = {**reference(), "schema_version": 1}
    path = tmp_path / "component.json"
    path.write_text(json.dumps(document))
    main(["validate", str(path), "--schema", "component-inventory"])
    assert capsys.readouterr().out.strip() == "Normalized component reference is valid"
    document["components"]["openssh"] = "9.4"
    path.write_text(json.dumps(document))
    with pytest.raises(NormalizationError):
        main(["validate", str(path), "--schema", "component-inventory"])
