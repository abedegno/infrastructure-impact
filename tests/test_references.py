"""Reference ingestion cannot manufacture vendor claims or a partial study universe."""

import json
from copy import deepcopy
from unittest.mock import patch

import pytest

from infrastructure_impact.collection.config import validate_config
from infrastructure_impact.collection.service import run
from infrastructure_impact.collection.transport import allowed
from infrastructure_impact.references.nvd import parse_openssh
from infrastructure_impact.references.registry import NVD_OPENSSH_URL
from infrastructure_impact.references.storage import ingest, latest
from infrastructure_impact.storage.repository import collection_result, connect


def response():
    return {
        "format": "NVD_CVE",
        "version": "2.0",
        "totalResults": 1,
        "resultsPerPage": 1,
        "startIndex": 0,
        "timestamp": "2026-10-26T00:00:00Z",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-12345",
                    "published": "2026-01-01T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Synthetic server example"}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:a:openbsd:openssh:1.0:*:*:*:*:*:*:*",
                                            "vulnerable": True,
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }


def test_partial_empty_duplicate_and_unrelated_responses_are_rejected():
    for field, value in [
        ("totalResults", 2),
        ("startIndex", 1),
        ("resultsPerPage", True),
        ("vulnerabilities", []),
    ]:
        data = response()
        data[field] = value
        with pytest.raises(ValueError):
            parse_openssh(json.dumps(data))
    data = response()
    data["vulnerabilities"] *= 2
    data["resultsPerPage"] = data["totalResults"] = 2
    with pytest.raises(ValueError, match="duplicate"):
        parse_openssh(json.dumps(data))
    data = response()
    data["vulnerabilities"][0]["cve"]["configurations"] = []
    with pytest.raises(ValueError, match="mapping"):
        parse_openssh(json.dumps(data))


def test_timestamp_churn_is_distinct_from_semantic_drift_and_mapping_is_not_exposure():
    first = response()
    second = deepcopy(first)
    second["timestamp"] = "2026-10-27T00:00:00Z"
    second["vulnerabilities"][0]["cve"]["lastModified"] = "2026-10-27T00:00:00Z"
    assert parse_openssh(json.dumps(first)) == parse_openssh(json.dumps(second))
    second["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0][
        "vulnerable"
    ] = False
    result = parse_openssh(json.dumps(second))["records"][0]
    assert (
        result["record_semantic_sha256"]
        != parse_openssh(json.dumps(first))["records"][0]["record_semantic_sha256"]
    )
    assert result["has_positive_product_mapping"] is False
    assert "affected" not in result


def test_only_exact_reviewed_reference_routes_are_configurable_and_retrievable():
    config = {
        "vendors": [],
        "reference_sources": [{"source_id": "nvd-openssh-products", "url": NVD_OPENSSH_URL}],
    }
    assert validate_config(config) is config
    assert allowed(NVD_OPENSSH_URL, "upstream")
    for url in [
        NVD_OPENSSH_URL + "&extra=1",
        NVD_OPENSSH_URL.replace("https:", "http:"),
        "https://services.nvd.nist.gov/other",
    ]:
        assert not allowed(url, "upstream")
        broken = deepcopy(config)
        broken["reference_sources"][0]["url"] = url
        with pytest.raises(ValueError):
            validate_config(broken)
    config["reference_sources"] *= 2
    with pytest.raises(ValueError, match="Duplicate"):
        validate_config(config)


def test_reference_revisions_and_failure_health_do_not_become_vendor_documents(tmp_path):
    path = tmp_path / "vault.sqlite"
    raw = json.dumps(response()).encode()
    with connect(path) as db:
        assert latest(db) == []
        assert ingest(db, raw, "nvd-openssh-products")
        assert not ingest(db, raw, "nvd-openssh-products")
        collection_result(db, "upstream", NVD_OPENSSH_URL, "ok", "collected")
        item = latest(db)[0]
        assert item["collection"]["outcome"] == "ok"
        collection_result(
            db, "upstream", NVD_OPENSSH_URL, "error", "private failure detail", "parse_error"
        )
        assert latest(db)[0]["collection"]["outcome"] == "error"
        assert latest(db)[0]["source_sha256"] == item["source_sha256"]
        assert not db.execute("SELECT 1 FROM revisions").fetchone()
        assert not db.execute("SELECT 1 FROM documents").fetchone()
    config = {
        "vendors": [],
        "reference_sources": [{"source_id": "nvd-openssh-products", "url": NVD_OPENSSH_URL}],
    }
    with patch("infrastructure_impact.collection.service.fetch", return_value=raw):
        assert run(config, db_path=path) == (0, 0)
    with connect(path) as db:
        assert latest(db)[0]["collection"]["outcome"] == "ok"


def test_checkout_example_matches_installed_default_sources():
    from pathlib import Path

    from infrastructure_impact.settings import PACKAGE

    root = Path(__file__).resolve().parents[1]
    assert validate_config(json.loads((root / "sources.json").read_text())) == validate_config(
        json.loads((PACKAGE / "resources/sources.json").read_text())
    )


def test_read_only_legacy_vault_is_unknown_and_reference_audit_detects_reinterpretation(
    tmp_path, monkeypatch
):
    import sqlite3

    from infrastructure_impact.storage.audit import audit

    legacy = sqlite3.connect(":memory:")
    assert latest(legacy) == []
    assert not legacy.execute(
        "SELECT 1 FROM sqlite_master WHERE name='reference_documents'"
    ).fetchone()
    legacy.close()
    path = tmp_path / "reference.sqlite"
    monkeypatch.setenv("IMPACT_DATABASE", str(path))
    with connect(path) as db:
        ingest(db, json.dumps(response()).encode(), "nvd-openssh-products")
    assert audit()["reference_documents"] == 1
    with connect(path) as db:
        altered = parse_openssh(json.dumps(response()))
        altered["records"][0]["has_positive_product_mapping"] = False
        db.execute("UPDATE reference_documents SET normalized=?", (json.dumps(altered),))
    with pytest.raises(ValueError, match="normalization"):
        audit()
