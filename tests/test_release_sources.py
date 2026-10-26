"""Cloud access diagnostics and independent firmware metadata boundaries."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError

from checks.operations_report import summarize
from infrastructure_impact.application.query import state
from infrastructure_impact.application.release_assets import (
    ingest_listing,
    listings,
    validate_asset,
)
from infrastructure_impact.collection.errors import (
    AccessVerificationRequired,
    check_access_response,
    failure_code,
)
from infrastructure_impact.domain import NormalizationError
from infrastructure_impact.storage.repository import collection_result, connect

URL = "https://support.checkpoint.com/results/download/12345"


def listing(date="2024-07-18"):
    data = {
        "title": "R81.10.10 Build 123456789 for Example Appliances",
        "datePublished": date,
        "product": "Example Firewall",
        "models": "Example 1, Example 2",
        "fileName": "example.img",
        "sha256": "a" * 64,
        "isEntitle": "PRIVATE FIELD SENTINEL",
    }
    return (
        '<!doctype html><script id="__NEXT_DATA__">'
        + json.dumps({"props": {"pageProps": {"data": data}}})
        + "</script>"
    ).encode()


class ReleaseSourceTests(unittest.TestCase):
    def test_access_challenge_is_not_a_parser_layout_change(self):
        raw = b'<!doctype html><html>JavaScript is disabled. Verify you are not a robot.<script src="https://example.token.awswaf.com/challenge.js"></script></html>'
        with self.assertRaises(AccessVerificationRequired) as caught:
            check_access_response(raw)
        self.assertEqual(failure_code(caught.exception), "access_verification_required")
        self.assertEqual(failure_code(HTTPError(URL, 403, "Forbidden", {}, None)), "access_denied")
        check_access_response(
            b'{"description":"JavaScript is disabled not a robot token.awswaf.com"}'
        )

    def test_listing_excludes_entitlement_and_never_creates_cve_assessments(self):
        with connect(":memory:") as db:
            record = ingest_listing(db, listing(), URL, "checkpoint")
            self.assertNotIn("PRIVATE FIELD SENTINEL", json.dumps(record))
            self.assertEqual(record["platforms"], ["Example 1", "Example 2"])
            self.assertEqual(record["availability_basis"], "publisher_dated_listing")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM fix_evidence").fetchone()[0], 0)
            self.assertEqual(len(listings(db)), 1)
            self.assertEqual(
                state(db)["research"]["release_assets"][0]["artifact_sha256"], "a" * 64
            )

    def test_listing_reversions_do_not_leave_a_superseded_date_current(self):
        with connect(":memory:") as db:
            for date in ["2024-07-18", "2024-07-21", "2024-07-18", "2024-07-18"]:
                ingest_listing(db, listing(date), URL, "checkpoint")
            self.assertEqual(listings(db)[0]["reported_published_at"], "2024-07-18")
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM release_asset_observations").fetchone()[0], 3
            )

    def test_invalid_date_and_added_cve_claim_fail_schema_validation(self):
        with connect(":memory:") as db:
            with self.assertRaises(NormalizationError):
                ingest_listing(db, listing("yesterday"), URL, "checkpoint")
            record = ingest_listing(db, listing(), URL, "checkpoint")
            record["cve_id"] = "CVE-2025-12345"
            with self.assertRaises(NormalizationError):
                validate_asset(record)

    def test_source_diagnostic_code_survives_public_query(self):
        with connect(":memory:") as db:
            collection_result(
                db,
                "checkpoint",
                URL,
                "error",
                "Interactive verification required",
                "access_verification_required",
            )
            self.assertEqual(state(db)["health"][0]["error_code"], "access_verification_required")

    def test_observation_window_does_not_invent_elapsed_time_or_uptime(self):
        first = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
        run = {
            "createdAt": first.isoformat(),
            "conclusion": "success",
            "event": "workflow_dispatch",
        }
        early = summarize([run], [], first + timedelta(hours=3), 3000)
        self.assertFalse(early["seven_day_window_complete"])
        self.assertEqual(early["collections"]["scheduled"], 0)
        self.assertFalse(early["storage_review_required"])
        late = summarize([run], [], first + timedelta(days=7), 600000)
        self.assertTrue(late["seven_day_window_complete"])
        self.assertTrue(late["storage_review_required"])


if __name__ == "__main__":
    unittest.main()
