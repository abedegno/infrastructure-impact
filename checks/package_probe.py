"""Executed outside the checkout against installed wheels, including an extension."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import infrastructure_impact
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.collection.archive import progress
from infrastructure_impact.collection.archive import run as backfill
from infrastructure_impact.collection.config import validate_config
from infrastructure_impact.http import Application
from infrastructure_impact.plugins import default_registry
from infrastructure_impact.storage.repository import connect, ingest


def main():
    registry = default_registry()
    assert "acme" in registry.names()
    assert registry.get("aruba").parse_release_history is not None
    assert registry.get("arista").parse_release_history is not None
    package = Path(infrastructure_impact.__file__).parent
    for name in ("browser-capture-v1.json", "release-history-v1.json"):
        assert (package / "schemas" / name).is_file()
    assert (package / "migrations/004_browser_captures.sql").is_file()
    assert (package / "migrations/006_archive_scope.sql").is_file()
    assert (package / "migrations/007_source_observations.sql").is_file()
    assert (package / "resources/archive-source-review.json").is_file()
    assert (package / "schemas/comparison-eligibility-v1.json").is_file()
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
        assert (root / "current/scorecards.json").exists()
        assert (root / "current/comparison-eligibility.json").exists()
        for filename in (
            "product-groups.json",
            "extraction-validation.json",
            "review-packet.json",
            "publisher-history.json",
        ):
            assert (root / "current" / filename).exists()
        for filename in (
            "product-groups-v1.json",
            "publisher-history-v1.json",
            "extraction-review-v1.json",
            "review-submission-v1.json",
            "static-index-v1.json",
            "vendor-gaps-v1.json",
            "family-completeness-v1.json",
            "comparison-readiness-v1.json",
            "fix-leads-v1.json",
        ):
            assert (root / "current/schemas" / filename).exists()
        groups = json.loads((root / "current/product-groups.json").read_text())
        assert (
            next(v for v in groups["vendors"] if v["vendor"] == "acme")["unmapped_statements"] == 1
        )
        status, _, report_body = app.route(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/v1/comparison-eligibility",
                "QUERY_STRING": "vendor=acme",
            }
        )
        assert status == 200
        assert len(json.loads(report_body)["vendors"]) == 1
        assert json.loads(report_body)["vendors"][0]["vendor"] == "acme"
        assert (root / "current/timeline.json").exists()
        assert (root / "current/source-audit.json").exists()
        assert len(json.loads((root / "current/casefiles.json").read_text())["cases"]) == 4
    # Selection for external vendors uses the same pure policy as bundled vendors.
    from infrastructure_impact.application.eligibility import eligibility

    assert any(row["vendor"] == "acme" for row in eligibility(data)["vendors"])
    db.close()
    archive_url = "https://security.acme.example/archive"
    config = {
        "vendors": [],
        "archives": [{"vendor": "acme", "url": archive_url, "kind": "listing"}],
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "vault.sqlite3"
        with (
            patch(
                "infrastructure_impact.collection.archive.fetch",
                return_value=json.dumps({"advisory_urls": [url]}).encode(),
            ),
            patch(
                "infrastructure_impact.collection.archive.resolve_document", return_value=(url, raw)
            ),
        ):
            assert backfill(config, path) == (1, 0)
        with connect(path) as vault:
            assert progress(vault, [], config)[0]["known_queue_exhausted"]
    print(
        json.dumps(
            {
                "installed_package": True,
                "entry_point_plugin": True,
                "external_archive_hook": True,
                "vendors": 9,
                "schema_validated": True,
                "database_and_publication": True,
                "public_api": True,
            }
        )
    )


if __name__ == "__main__":
    main()
