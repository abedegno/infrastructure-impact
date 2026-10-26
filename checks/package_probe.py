"""Executed outside the checkout against installed wheels, including an extension."""

import json
import tempfile
from pathlib import Path

import infrastructure_impact
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.collection.config import validate_config
from infrastructure_impact.http import Application
from infrastructure_impact.plugins import default_registry
from infrastructure_impact.storage.repository import connect, ingest


def main():
    registry = default_registry()
    assert "acme" in registry.names()
    assert registry.get("aruba").parse_release_history is not None
    package = Path(infrastructure_impact.__file__).parent
    for name in ("browser-capture-v1.json", "release-history-v1.json"):
        assert (package / "schemas" / name).is_file()
    assert (package / "migrations/004_browser_captures.sql").is_file()
    assert not Path(infrastructure_impact.__file__).resolve().is_relative_to(Path.cwd())
    url = "https://security.acme.example/advisory.json"
    validate_config(
        {
            "vendors": [
                {
                    "vendor": "acme",
                    "kind": "index",
                    "url": "https://security.acme.example/index.txt",
                }
            ]
        }
    )
    raw = json.dumps(
        {
            "document": {
                "title": "Synthetic example fixture",
                "tracking": {"id": "ACME-1", "status": "final"},
            },
            "product_tree": {
                "full_product_names": [{"product_id": "router", "name": "Example Router"}]
            },
            "vulnerabilities": [
                {"cve": "CVE-2025-12345", "product_status": {"known_affected": ["router"]}}
            ],
        }
    ).encode()
    document = registry.normalize(raw, url, "acme")
    db = connect(":memory:")
    ingest(db, raw, url, lambda *_: document, "acme")
    data = state(db, ["CVE-2025-12345"])
    assert len(data["vendors"]) == 9
    assert any(
        row["vendor"] == "acme" and row["affected_cves"] == 1
        for row in data["comparison"]["vendors"]
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        publish(data, root=root)
        app = Application(root)
        response = []
        body = b"".join(
            app(
                {
                    "REQUEST_METHOD": "GET",
                    "PATH_INFO": "/api/v1/assessments",
                    "QUERY_STRING": "vendor=acme",
                },
                lambda status, headers: response.append(status),
            )
        )
        assert response == ["200 OK"]
        assert json.loads(body)["items"][0]["vendor"] == "acme"
        assert (root / "current/schemas/advisory-v2.json").exists()
    db.close()
    print(
        json.dumps(
            {
                "installed_package": True,
                "entry_point_plugin": True,
                "vendors": 9,
                "schema_validated": True,
                "database_and_publication": True,
                "public_api": True,
            }
        )
    )


if __name__ == "__main__":
    main()
