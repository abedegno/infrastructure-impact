"""Product research targets cannot certify inventories or exposure rates."""

import json
from copy import deepcopy
from unittest.mock import patch

import pytest

from infrastructure_impact.application.product_cohorts import (
    definition,
    fingerprint,
    product_cohorts,
)
from infrastructure_impact.application.publication import public_projection, publish
from infrastructure_impact.application.query import state
from infrastructure_impact.application.research_reports import validator
from infrastructure_impact.http import Application
from infrastructure_impact.storage.repository import connect


def data():
    return dict(
        vendors={"paloalto": "Palo Alto Networks", "cisco": "Cisco"},
        health=[],
        fix_leads={"sources": []},
    )


def test_scope_definitions_are_frozen_ordered_and_require_unique_official_members():
    original = definition()
    assert len(original["cohorts"]) == 3
    assert sum(len(c["units"]) for c in original["cohorts"]) == 15
    for mutate in [
        lambda d: d["cohorts"][0]["units"].append(deepcopy(d["cohorts"][0]["units"][0])),
        lambda d: d["cohorts"][0]["units"][0].update(family_id="unknown"),
        lambda d: d["cohorts"][0]["units"][0].update(
            component_sources=["https://attacker.example/inventory"]
        ),
        lambda d: d["cohorts"][0]["period"].update(end="2020-01-01"),
        lambda d: d["cohorts"].append(deepcopy(d["cohorts"][0])),
    ]:
        candidate = deepcopy(original)
        mutate(candidate)
        candidate["definition_sha256"] = fingerprint(candidate)
        with pytest.raises(ValueError):
            definition(candidate)
    candidate = deepcopy(original)
    candidate["cohorts"][0]["units"][0]["firmware_build"] = "new target"
    with pytest.raises(ValueError, match="fingerprint"):
        definition(candidate)


def test_fully_populated_targets_do_not_become_verified_build_denominators():
    spec = definition()
    target = spec["cohorts"][0]["units"][0]
    target.update(
        release_train="synthetic",
        firmware_build="1.0",
        hardware_model="Synthetic model",
        deployment="on-prem",
        support_window={"start": "2023-01-01", "end": "2026-01-01"},
    )
    target["service"]["enabled"] = False
    spec["definition_sha256"] = fingerprint(spec)
    report = product_cohorts(data(), spec)
    validator("product_cohorts").validate(report)
    row = report["cohorts"][0]["units"][0]
    assert row["build_inventory_denominator"] is None and row["comparison_rate"] is None
    assert (
        row["state"] == "blocked"
        and "product_build_inventory_unverified" in row["missing_dimensions"]
    )
    assert not any(x.endswith("_target_unspecified") for x in row["missing_dimensions"])
    assert report["ranking_supported"] is False


def test_exact_source_and_vendor_binding_cannot_transfer_panorama_to_panos():
    d = data()
    spec = definition()
    panorama = next(
        u for c in spec["cohorts"] for u in c["units"] if u["family_id"] == "paloalto-panorama"
    )
    url = panorama["component_sources"][0]
    source = dict(
        vendor="paloalto",
        source_url=url,
        analysis_state="scoped",
        components={"openssh": ["8.0p1"]},
        component_scope="Feature-release reference only",
        current_evidence=dict(source_sha256="a" * 64, observed_at="2026-10-27T00:00:00Z"),
        component_locators=["Exact row 5"],
        latest_retrieval_matches_analyzed_snapshot=False,
    )
    d["fix_leads"]["sources"] = [source]
    report = product_cohorts(d)
    rows = [u for c in report["cohorts"] for u in c["units"]]
    matching = [u for u in rows if u["component_evidence"]]
    assert len(matching) == 1 and matching[0]["target"]["id"] == panorama["id"]
    assert (
        matching[0]["component_evidence"][0]["latest_retrieval_matches_analyzed_snapshot"] is False
    )
    d["fix_leads"]["sources"][0]["vendor"] = "cisco"
    assert not any(
        u["component_evidence"] for c in product_cohorts(d)["cohorts"] for u in c["units"]
    )
    source["vendor"] = "paloalto"
    source["analysis_state"] = "component_inventory_layout_requires_review"
    assert not any(
        u["component_evidence"] for c in product_cohorts(d)["cohorts"] for u in c["units"]
    )


def test_publication_rebuilds_reports_and_serves_generation_bound_api_and_static(tmp_path):
    with connect(":memory:") as db:
        original = state(db)
    original["product_cohorts"] = {"PRIVATE_SENTINEL": "operator notes"}
    original["disclosure_review"] = {"PRIVATE_SENTINEL": "review state"}
    projected = public_projection(original)
    assert "PRIVATE_SENTINEL" not in json.dumps(projected)
    root = tmp_path / "publications"
    publish(original, root)
    for name in ["product-cohorts", "disclosure-review"]:
        replies = []
        body = b"".join(
            Application(root)(
                {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/" + name, "QUERY_STRING": ""},
                lambda s, h: replies.append(s),
            )
        )
        assert replies == ["200 OK"]
        report = json.loads(body)
        validator(name.replace("-", "_")).validate(report)
        assert report == json.loads((root / "current" / f"{name}.json").read_text())
        assert report["publication"]["id"]
    assert (root / "current/schemas/product-cohort-definition-v1.json").exists()
    # Every contract exported by the writer must be reachable from the Python
    # reader as well as a static host; an omitted allowlist entry is a regression.
    for schema_path in (root / "current/schemas").glob("*.json"):
        replies = []
        body = b"".join(
            Application(root)(
                {
                    "REQUEST_METHOD": "GET",
                    "PATH_INFO": "/schemas/" + schema_path.name,
                    "QUERY_STRING": "",
                },
                lambda status, headers: replies.append(status),
            )
        )
        assert replies == ["200 OK"], schema_path.name
        assert body == schema_path.read_bytes(), schema_path.name


def test_cohort_validation_cli_does_not_open_or_write_vault(tmp_path, capsys):
    from infrastructure_impact.research_cli import main

    path = tmp_path / "cohorts.json"
    path.write_text(json.dumps(definition()))
    with patch(
        "infrastructure_impact.research_cli.connect",
        side_effect=AssertionError("Vault access forbidden"),
    ):
        main(["cohort-validate", str(path)])
    assert json.loads(capsys.readouterr().out)["valid"] is True
