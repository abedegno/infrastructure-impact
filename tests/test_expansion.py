"""Evidence, scope, freshness and private-hosted-state acceptance checks."""

import importlib.util
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from infrastructure_impact.adapters.common import iso_date
from infrastructure_impact.adapters.compat import auto
from infrastructure_impact.application.catalogue import catalogue
from infrastructure_impact.application.disclosure import (
    add_fix_evidence,
    import_release_note,
    latest_documents,
    register_observation,
    signals,
    verify_candidate,
)
from infrastructure_impact.application.evaluation import evaluate
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.storage.repository import connect, evidence

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("hosted_job", ROOT / "ops/hosted_job.py")
hosted = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hosted)


class ExpansionTests(unittest.TestCase):
    def test_freshness_is_collection_age_not_advisory_date(self):
        with connect(":memory:") as db:
            at = datetime(2026, 10, 26, tzinfo=timezone.utc)
            db.execute(
                "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details) VALUES(?,?,?,?,?)",
                (
                    "cisco",
                    "https://cisco.com/test",
                    (at - timedelta(hours=37)).isoformat(),
                    "ok",
                    "test",
                ),
            )
            result = catalogue(db, [], {"vendors": []}, at)
            cisco = next(v for v in result["vendors"] if v["vendor"] == "cisco")
            self.assertEqual(cisco["freshness"], "stale")
            self.assertTrue(
                next(v for v in result["vendors"] if v["vendor"] == "hpe")["known_gaps"]
            )

    def test_arista_nested_headings_do_not_apply_unaffected_to_low_impact(self):
        raw = b"""<h1>Security Advisory example</h1><p>CVE-2022-0778</p><h2>Vulnerability Assessment</h2>
<h4>The following products are affected by CVE-2022-0778:</h4><ul><li>Example router</li></ul>
<h4>The following products are NOT affected:</h4><ul><li>Example AP</li></ul>
<h4>The following products have low impact:</h4><ul><li>Example manager</li></ul>"""
        r = auto(raw, "https://www.arista.com/test", "arista")
        self.assertEqual(
            {a["product"]: a["status"] for a in r["assessments"]},
            {"Example router": "affected", "Example AP": "unaffected"},
        )
        self.assertEqual(iso_date("April 26 th 2022"), "2022-04-26")

    def test_panorama_per_cve_exception_overrides_shared_table(self):
        doc = {
            "cveMetadata": {"cveId": "CVE-2021-44228"},
            "containers": {
                "cna": {
                    "title": "CVE-2021-44228 and CVE-2021-45105",
                    "descriptions": [
                        {"value": "Panorama appliances are not impacted by CVE-2021-45105."}
                    ],
                    "affected": [
                        {
                            "vendor": "Example",
                            "product": "PAN-OS on Panorama",
                            "versions": [{"version": "9.0", "status": "affected"}],
                        }
                    ],
                }
            },
        }
        r = auto(json.dumps(doc), "https://security.paloaltonetworks.com/test", "paloalto")
        statuses = {a["cve_id"]: a["status"] for a in r["assessments"]}
        self.assertEqual(statuses, {"CVE-2021-44228": "affected", "CVE-2021-45105": "unaffected"})

    def test_golden_case_evaluation_never_claims_global_precision(self):
        result = evaluate([])
        self.assertEqual(result["passed"], 0)
        self.assertIsNone(result["global_precision"])
        self.assertTrue(all(c["outcome"] == "source_missing" for c in result["cases"]))
        self.assertEqual(len({c["id"] for c in result["cases"]}), result["total"])

    def test_release_reversions_and_idempotence_have_real_observation_order(self):
        with connect(":memory:") as db:
            a, b = b"<p>Initial release.</p>", b"<p>Security fix CVE-2025-12345.</p>"
            for raw in (a, b, a, b, b):
                import_release_note(db, raw, "https://www.arista.com/release", "arista", "Router")
            revisions = [s for s in signals(db) if s["kind"] == "release_note_revision"]
            self.assertEqual(len(revisions), 3)
            self.assertEqual(revisions[0]["cves_added"], ["CVE-2025-12345"])
            self.assertEqual(revisions[1]["cves_removed"], ["CVE-2025-12345"])
            self.assertIn("CVE-2025-12345", latest_documents(db)[0]["text"])

    def test_review_requires_independent_availability_and_disclosure_search(self):
        with connect(":memory:") as db:
            first = evidence(db, b"release listing", "https://www.arista.com/releases")["id"]
            second = evidence(db, b"product CVE link", "https://www.arista.com/advisory")["id"]
            add_fix_evidence(
                db,
                "arista",
                "Router",
                "CVE-2025-12345",
                "1.1",
                "2025-01-01",
                first,
                second,
                "Specific linkage",
            )
            claimed = register_observation(
                db,
                first,
                "arista",
                "Router",
                "1.1",
                "2025-01-01",
                "publisher_date_claim",
                "Table row 1",
            )
            with self.assertRaises(ValueError):
                verify_candidate(db, 1, claimed, "Searched official archive", "Review")
            observed = register_observation(
                db,
                first,
                "arista",
                "Router",
                "1.1",
                "2025-01-01",
                "public_release_listing",
                "Table row 1",
            )
            with self.assertRaises(ValueError):
                verify_candidate(db, 1, observed, "", "Review")
            verify_candidate(
                db,
                1,
                observed,
                "Official archive, release index and earlier related advisories searched",
                "Review",
            )
            self.assertEqual(
                db.execute("SELECT review_status FROM fix_evidence").fetchone()[0], "verified"
            )

    def test_same_snapshot_does_not_count_as_independent_release_evidence(self):
        with connect(":memory:") as db:
            ev = evidence(db, b"one bulletin", "https://www.arista.com/advisory")["id"]
            add_fix_evidence(
                db, "arista", "Router", "CVE-2025-12345", "1.1", "2025-01-01", ev, ev, "Link"
            )
            observation = register_observation(
                db, ev, "arista", "Router", "1.1", "2025-01-01", "public_release_listing", "Row"
            )
            with self.assertRaises(ValueError):
                verify_candidate(db, 1, observation, "Archive searched", "Review")

    def test_project_path_assets_and_private_backup_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "source.sqlite3"
            with connect(database) as db:
                data = state(db)
            with patch.dict(os.environ, {"IMPACT_BASE_PATH": "/impact/"}):
                generation = publish(data, root / "public")
            html = (generation / "index.html").read_text()
            self.assertIn('src="/impact/assets/', html)
            self.assertNotIn('src="/snapshot.js"', html)
            self.assertIn('href="/impact/assets/', html)
            self.assertTrue((generation / "catalogue.json").exists())
            hosted.backup(root / "private", database)
            target = root / "restore/vault.sqlite3"
            self.assertTrue(hosted.restore(root / "private", target))
            with connect(target, read_only=True) as restored:
                self.assertEqual(restored.execute("PRAGMA quick_check").fetchone()[0], "ok")
            manifest = json.loads((root / "private/current.json").read_text())
            archive = root / "private" / manifest["archive"]
            archive.write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                hosted.restore(root / "private", root / "another.sqlite3")


if __name__ == "__main__":
    unittest.main()


class EncryptedStateTests(unittest.TestCase):
    def test_encrypted_backup_roundtrip_and_wrong_key_rejection(self):
        from cryptography.fernet import Fernet, InvalidToken

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "vault.sqlite3"
            with connect(database) as db:
                evidence(db, b"PRIVATE RAW SENTINEL", "https://www.arista.com/test")
            key = Fernet.generate_key()
            receipt = hosted.backup(root / "encrypted", database, key)
            self.assertEqual(receipt["encryption"], "fernet-v1")
            archive = root / "encrypted" / receipt["archive"]
            self.assertNotIn(b"PRIVATE RAW SENTINEL", archive.read_bytes())
            self.assertTrue(hosted.restore(root / "encrypted", root / "recovered.sqlite3", key))
            with self.assertRaises(InvalidToken):
                hosted.restore(root / "encrypted", root / "wrong.sqlite3", Fernet.generate_key())
            with self.assertRaises(ValueError):
                hosted.restore(root / "encrypted", root / "no-key.sqlite3")

    def test_public_runner_rejects_plaintext_state(self):
        from cryptography.fernet import Fernet

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "vault.sqlite3"
            connect(database).close()
            hosted.backup(root / "private", database)
            with self.assertRaises(ValueError):
                hosted.restore(root / "private", root / "public.sqlite3", Fernet.generate_key())
