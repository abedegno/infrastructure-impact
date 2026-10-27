"""Contract, extension, storage and publication-boundary acceptance tests."""

import copy
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from wsgiref.util import setup_testing_defaults

from infrastructure_impact.adapters.common import base
from infrastructure_impact.application.comparison import compare, parse_date
from infrastructure_impact.application.disclosure import signals
from infrastructure_impact.application.jobs import execute
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.collection.config import load_config, validate_config
from infrastructure_impact.domain import NormalizationError, validate_advisory
from infrastructure_impact.http import Application
from infrastructure_impact.plugins import PluginRegistry, VendorPlugin
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.storage.migrations import migrate
from infrastructure_impact.storage.repository import connect, history, ingest
from infrastructure_impact.worker import next_daily

CID = "CVE-2025-12345"
OTHER = "CVE-2025-54321"
URL = "https://security.acme.example/advisory.json"


def source():
    return {
        "document": {
            "title": "Example router library vulnerability",
            "tracking": {
                "id": "ACME-1",
                "status": "final",
                "initial_release_date": "2025-01-01T00:00:00Z",
            },
        },
        "product_tree": {
            "full_product_names": [{"product_id": "router", "name": "Example Router 1.0"}]
        },
        "vulnerabilities": [
            {
                "cve": CID,
                "product_status": {"known_affected": ["router"]},
                "notes": [{"category": "general", "text": "PRIVATE_RAW_SOURCE_SENTINEL"}],
            }
        ],
    }


def normalized():
    registry = PluginRegistry()
    registry.register(VendorPlugin("acme", "Acme Example", ("acme.example",), structured))
    return registry.normalize(json.dumps(source()), URL, "acme")


def dataset():
    db = connect(":memory:")
    document = normalized()
    ingest(db, json.dumps(source()), URL, lambda *_: document, "acme")
    data = state(db, [CID])
    # A publication carries its vendor catalogue. The reader needs no parser plugin.
    data["vendors"]["acme"] = "Acme Example"
    data["research"]["fix_candidates"] = [{"basis": "PRIVATE_REVIEW_SENTINEL"}]
    data["signals"].append(
        {"kind": "fix_predates_collected_advisory", "basis": "PRIVATE_REVIEW_SENTINEL"}
    )
    db.close()
    return data


def request(app, path, query="", method="GET"):
    environ = {}
    setup_testing_defaults(environ)
    environ.update(PATH_INFO=path, QUERY_STRING=query, REQUEST_METHOD=method)
    status = []
    body = b"".join(
        app(environ, lambda code, headers: status.append((int(code[:3]), dict(headers))))
    )
    return status[0][0], status[0][1], body


class SchemaContract(unittest.TestCase):
    def test_new_vendor_normalizes_without_changing_core_dispatch(self):
        document = normalized()
        self.assertEqual(document["vendor"], "acme")
        self.assertEqual(document["assessments"][0]["status"], "affected")
        self.assertIs(validate_advisory(document), document)

    def test_invalid_status_and_unknown_top_fields_are_rejected(self):
        for change in (
            lambda d: d["assessments"][0].update(status="probably vulnerable"),
            lambda d: d.update(secret_field="must not escape"),
        ):
            document = normalized()
            change(document)
            with self.assertRaises(NormalizationError):
                validate_advisory(document)

    def test_cve_scope_and_duplicate_product_identity_are_rejected(self):
        document = normalized()
        document["assessments"][0]["cve_id"] = OTHER
        with self.assertRaises(NormalizationError):
            validate_advisory(document)
        document = normalized()
        document["assessments"].append(copy.deepcopy(document["assessments"][0]))
        with self.assertRaises(NormalizationError):
            validate_advisory(document)

    def test_vendor_and_source_identity_cannot_be_spoofed(self):
        registry = PluginRegistry()
        registry.register(
            VendorPlugin(
                "acme", "Acme", ("acme.example",), lambda *_: base("another", URL, "1", "Title")
            )
        )
        with self.assertRaises(NormalizationError):
            registry.normalize(b"{}", URL, "acme")
        with self.assertRaises(NormalizationError):
            validate_advisory(normalized(), source_url="https://other.example/")

    def test_duplicate_plugin_ids_and_invalid_official_domains_fail_closed(self):
        registry = PluginRegistry()
        plugin = VendorPlugin("acme", "Acme", ("acme.example",), structured)
        registry.register(plugin)
        with self.assertRaises(ValueError):
            registry.register(plugin)
        with self.assertRaises(ValueError):
            PluginRegistry().register(
                VendorPlugin("bad", "Bad", ("https://example.test",), structured)
            )

    def test_publisher_local_timestamp_is_preserved_without_utc_inference(self):
        raw = source()
        raw["document"]["tracking"]["initial_release_date"] = "2025-01-01T10:00:00"
        registry = PluginRegistry()
        registry.register(VendorPlugin("acme", "Acme", ("acme.example",), structured))
        result = registry.normalize(json.dumps(raw), URL, "acme")
        self.assertTrue(any("no timezone" in w for w in result["warnings"]))
        self.assertIsNone(parse_date(result["published_at"]))

    def test_platform_specific_product_rows_remain_distinct(self):
        raw = {
            "cveMetadata": {"cveId": CID},
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "product": "Agent",
                            "platforms": ["Linux"],
                            "versions": [{"version": "1", "status": "affected"}],
                        },
                        {
                            "product": "Agent",
                            "platforms": ["Windows"],
                            "versions": [{"version": "1", "status": "unaffected"}],
                        },
                    ]
                }
            },
        }
        registry = PluginRegistry()
        registry.register(VendorPlugin("acme", "Acme", ("acme.example",), structured))
        records = registry.normalize(json.dumps(raw), URL, "acme")["assessments"]
        self.assertEqual(len({a["product_id"] for a in records}), 2)
        self.assertEqual({a["platforms"][0] for a in records}, {"Linux", "Windows"})

    def test_invalid_contract_does_not_enter_the_repository(self):
        db = connect(":memory:")
        document = normalized()
        document["assessments"][0]["cve_id"] = OTHER
        with self.assertRaises(ValueError):
            ingest(db, b"raw", URL, lambda *_: document, "acme")
        self.assertEqual(db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0], 0)
        db.close()

    def test_source_view_switch_is_not_a_new_cve_disclosure(self):
        db = connect(":memory:")
        first = normalized()
        ingest(db, b"first", URL, lambda *_: first, "acme")
        second = copy.deepcopy(first)
        second["source_url"] = "https://security.acme.example/advisory.html"
        second["cves"].append(OTHER)
        ingest(db, b"second", second["source_url"], lambda *_: second, "acme")
        self.assertEqual(history(db)[0]["kind"], "source_view_change")
        self.assertFalse(any(s["kind"] == "cve_reference_added" for s in signals(db)))
        db.close()

    def test_reader_comparison_uses_the_publication_vendor_catalogue(self):
        result = compare([normalized()], [CID], vendors={"acme": "Acme Example"})
        self.assertEqual(result["vendors"][0]["name"], "Acme Example")
        self.assertEqual(result["vendors"][0]["affected_cves"], 1)


class PublicationBoundary(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.generation = publish(dataset(), root=self.root)
        self.app = Application(self.root)

    def tearDown(self):
        self.directory.cleanup()

    def test_publication_excludes_raw_evidence_and_private_reviews(self):
        text = (self.generation / "snapshot.json").read_text()
        self.assertNotIn("PRIVATE_RAW_SOURCE_SENTINEL", text)
        self.assertNotIn("PRIVATE_REVIEW_SENTINEL", text)
        code, _, body = request(self.app, "/api/evidence/1")
        self.assertEqual(code, 200)
        self.assertNotIn("raw_text", json.loads(body))

    def test_paginated_api_exposes_third_party_vendors_without_reader_plugins(self):
        code, _, body = request(self.app, "/api/v1/assessments", "vendor=acme&limit=1")
        self.assertEqual(code, 200)
        page = json.loads(body)
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["vendor"], "acme")

    def test_api_exports_obey_the_selected_cohort(self):
        code, _, body = request(self.app, "/api/export.json", "cves=" + OTHER)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["records"], [])
        code, _, body = request(self.app, "/api/export.csv", "cves=" + OTHER)
        self.assertNotIn(CID.encode(), body)

    def test_bad_queries_and_write_methods_are_rejected(self):
        for query in (
            "cves=not-a-cve",
            "limit=0",
            "limit=501",
            "offset=-1",
            "limit=bad",
            "vendor=unknown",
        ):
            self.assertEqual(request(self.app, "/api/v1/assessments", query)[0], 400)
        for method in ("POST", "PUT", "DELETE"):
            self.assertEqual(request(self.app, "/api/v1/advisories", method=method)[0], 405)

    def test_private_paths_and_traversal_are_not_served(self):
        for path in (
            "/data/intel.sqlite3",
            "/.env",
            "/../data/intel.sqlite3",
            "/evidence/../snapshot.json",
        ):
            self.assertEqual(request(self.app, path)[0], 404)
        secret = self.root / "private.json"
        secret.write_text("PRIVATE_FILESYSTEM_SENTINEL")
        (self.generation / "evidence/999.json").symlink_to(secret)
        self.assertEqual(request(self.app, "/evidence/999.json")[0], 404)

    def test_failed_build_retains_the_previous_complete_generation(self):
        before = (self.root / "current").resolve()
        with patch(
            "infrastructure_impact.application.publication.write_bundle",
            side_effect=OSError("disk full"),
        ):
            with self.assertRaises(OSError):
                publish(dataset(), root=self.root)
        self.assertEqual((self.root / "current").resolve(), before)
        self.assertEqual(request(self.app, "/api/state")[0], 200)

    def test_reader_observes_new_generation_without_redeployment(self):
        first = json.loads(request(self.app, "/api/state")[2])["publication"]["id"]
        second = publish(dataset(), root=self.root).name
        self.assertNotEqual(first, second)
        self.assertEqual(
            json.loads(request(self.app, "/api/state")[2])["publication"]["id"], second
        )

    def test_stale_publication_is_reported_but_data_remains_readable(self):
        old = dataset()
        old["generated_at"] = "2000-01-01T00:00:00Z"
        publish(old, root=self.root)
        self.assertEqual(request(self.app, "/health/ready")[0], 503)
        self.assertEqual(request(self.app, "/api/state")[0], 200)

    def test_schema_and_openapi_documents_are_served(self):
        for path in ("/schemas/advisory-v2.json", "/openapi.json", "/manifest.json"):
            code, _, body = request(self.app, path)
            self.assertEqual(code, 200)
            self.assertIsInstance(json.loads(body), dict)


class StorageAndScheduling(unittest.TestCase):
    def test_migration_failure_rolls_back_ddl_and_version_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            migrations = Path(directory)
            (migrations / "001_base.sql").write_text(
                "CREATE TABLE items(id INTEGER); INSERT INTO items VALUES(1);"
            )
            db = sqlite3.connect(":memory:")
            migrate(db, migrations)
            (migrations / "002_bad.sql").write_text(
                "ALTER TABLE items ADD COLUMN bad TEXT; INVALID SQL;"
            )
            with self.assertRaises(sqlite3.Error):
                migrate(db, migrations)
            self.assertEqual([r[1] for r in db.execute("PRAGMA table_info(items)")], ["id"])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0], 1)
            db.close()

    def test_applied_migration_cannot_be_rewritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "001_base.sql"
            path.write_text("CREATE TABLE items(id INTEGER);")
            db = sqlite3.connect(":memory:")
            migrate(db, directory)
            path.write_text("CREATE TABLE different(id INTEGER);")
            with self.assertRaises(ValueError):
                migrate(db, directory)
            db.close()

    def test_read_only_connections_reject_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.sqlite3"
            connect(path).close()
            db = connect(path, read_only=True)
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("DELETE FROM evidence")
            db.close()

    def test_daily_schedule_preserves_london_wall_time_across_dst(self):
        spring = datetime(2026, 3, 28, 8, 15, tzinfo=timezone.utc)
        autumn = datetime(2026, 10, 24, 7, 15, tzinfo=timezone.utc)
        self.assertEqual((next_daily(spring) - spring).total_seconds(), 23 * 3600)
        self.assertEqual((next_daily(autumn) - autumn).total_seconds(), 25 * 3600)

    def test_all_failed_checks_do_not_create_a_fresh_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.sqlite3"
            built = []

            def failed_source():
                db = connect(path)
                from infrastructure_impact.storage.repository import collection_result

                collection_result(db, "acme", URL, "error", "unavailable")
                db.close()
                return 0, 1

            result = execute(
                failed_source, lambda: (0, 0), lambda: None, lambda: built.append(True), path
            )
            self.assertEqual(result["outcome"], "error")
            self.assertFalse(built)

    def test_unknown_vendor_and_misspelled_configuration_fail_before_fetch(self):
        with self.assertRaises(ValueError):
            validate_config({"vendors": [{"vendor": "unknown", "url": URL, "kind": "rss"}]})
        with self.assertRaises(ValueError):
            validate_config(
                {
                    "vendors": [
                        {
                            "vendor": "cisco",
                            "url": "https://cisco.com/rss",
                            "kind": "rss",
                            "limti": 4,
                        }
                    ]
                }
            )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                load_config(Path(directory) / "missing.json")
            with patch.dict(os.environ, {"IMPACT_HOME": directory}):
                with self.assertRaises(FileNotFoundError):
                    load_config(Path(directory) / "sources.json")


class StrictJsonContract(unittest.TestCase):
    def test_nonfinite_values_are_rejected_in_open_advisory_fields(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            for field in ("remediation", "exposure", "version", "extension"):
                with self.subTest(value=str(value), field=field):
                    document = normalized()
                    claim = document["assessments"][0]
                    if field == "remediation":
                        claim["remediations"] = [{"details": "Synthetic", "date": value}]
                    elif field == "exposure":
                        claim["exposure"] = [{"PRIVATE_SENTINEL": value}]
                    elif field == "version":
                        claim["versions"] = [{"expression": "1.x", "publisher_extra": value}]
                    else:
                        document["extensions"] = {"PRIVATE_SENTINEL": value}
                    with self.assertRaises(NormalizationError) as error:
                        validate_advisory(document)
                    self.assertIn("finite numbers", str(error.exception))
                    self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))
                    registry = PluginRegistry()
                    registry.register(VendorPlugin("acme", "Acme", ("acme.example",), structured))
                    with self.assertRaises(NormalizationError):
                        registry.finalize(document, URL, "acme")

    def test_malformed_source_is_rejected_before_any_storage_write(self):
        raw = source()
        raw["vulnerabilities"][0]["remediations"] = [
            {"category": "vendor_fix", "details": "Synthetic", "date": float("nan")}
        ]
        registry = PluginRegistry()
        registry.register(VendorPlugin("acme", "Acme", ("acme.example",), structured))
        with connect(":memory:") as db:
            with self.assertRaises(NormalizationError):
                ingest(db, json.dumps(raw), URL, registry.normalize, "acme")
            self.assertEqual(db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM revisions").fetchone()[0], 0)

    def test_bad_publication_preserves_last_good_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = publish(dataset(), root)
            for location in ("report", "advisory"):
                data = dataset()
                if location == "report":
                    data["counts"]["PRIVATE_SENTINEL"] = float("inf")
                else:
                    data["records"][0]["assessments"][0]["remediations"] = [
                        {"details": "Synthetic", "date": float("nan")}
                    ]
                with self.assertRaises(ValueError):
                    publish(data, root)
                self.assertEqual((root / "current").resolve(), generation.resolve())
                self.assertEqual(len(list((root / "generations").iterdir())), 1)

    def test_cli_uses_the_same_guard_and_preserves_finite_values_and_literal_text(self):
        from infrastructure_impact.cli import main

        document = normalized()
        document["extensions"] = {"literal": "NaN / Infinity", "finite": 1.25e100}
        self.assertIs(validate_advisory(document), document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "advisory.json"
            document["assessments"][0]["remediations"] = [
                {"details": "Synthetic", "date": float("inf")}
            ]
            path.write_text(json.dumps(document))
            with self.assertRaises(NormalizationError):
                main(["validate", str(path)])


if __name__ == "__main__":
    unittest.main()
