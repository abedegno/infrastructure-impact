import copy
import json
import unittest
from contextlib import closing
from pathlib import Path
from impact import connect, ingest, latest, normalize

RAW = (Path(__file__).resolve().parents[1] / "tests/fixtures/pan-cna.json").read_text()
SOURCE = "https://security.paloaltonetworks.com/json/CVE-2026-109618"


class ImpactTests(unittest.TestCase):
    def test_synthetic_advisory_keeps_score_scenarios_and_custom_versions(self):
        result = normalize(json.loads(RAW), SOURCE, "2026-10-23")
        self.assertEqual([m["score"] for m in result["metrics"]], [8.7, 7.1, 9.2])
        pan = next(p for p in result["products"] if p["product"] == "PAN-OS")
        self.assertEqual(pan["patch_availability"], "not_evaluated")
        self.assertEqual(pan["versions"][0]["lessThan"], "12.2.4-h1")

    def test_explicit_affected_status_overrides_default_unaffected(self):
        result = normalize(json.loads(RAW), SOURCE, "2026-10-23")
        panorama = next(p for p in result["products"] if p["product"] == "Panorama")
        self.assertEqual(panorama["default_status"], "unaffected")
        self.assertEqual(panorama["status"], "affected")

    def test_duplicate_import_and_new_revision_preserve_history(self):
        with closing(connect(":memory:")) as db:
            self.assertTrue(ingest(db, RAW, SOURCE))
            self.assertFalse(ingest(db, RAW, SOURCE))
            changed = copy.deepcopy(json.loads(RAW))
            changed["containers"]["cna"]["affected"][0]["versions"][0]["status"] = "affected"
            self.assertTrue(ingest(db, json.dumps(changed), SOURCE))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0], 2)
            self.assertEqual(len(latest(db)), 1)
            self.assertEqual(latest(db)[0]["products"][0]["status"], "affected")

    def test_missing_assessment_is_unknown(self):
        record = json.loads(RAW)
        record["containers"]["cna"]["affected"] = [{"vendor": "Example", "product": "Unknown"}]
        self.assertEqual(normalize(record, SOURCE, "now")["products"][0]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
