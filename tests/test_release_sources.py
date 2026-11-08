"""Cloud access diagnostics and independent firmware metadata boundaries."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError

import pytest

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


def test_public_default_kev_configuration_and_resources_match():
    from infrastructure_impact.collection.config import validate_config
    from infrastructure_impact.settings import PACKAGE

    root = Path(__file__).resolve().parent.parent
    public = json.loads((root / "sources.json").read_text())
    bundled = json.loads((PACKAGE / "resources/sources.json").read_text())
    assert public == bundled
    validate_config(public)
    assert next(s for s in public["reference_sources"] if s["source_id"] == "cisa-kev") == {
        "source_id": "cisa-kev",
        "url": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
        "enabled": True,
    }
    assert (PACKAGE / "web/kev.js").is_file()
    schema = json.loads((PACKAGE / "schemas/kev-v1.json").read_text())
    assert "publication" in schema["required"]


if __name__ == "__main__":
    unittest.main()


def test_distribution_checks_switching_assets_against_installed_wheel():
    from checks import distribution

    root = Path(__file__).resolve().parent.parent
    assert hasattr(distribution, "public_resource_fingerprints"), (
        "Missing switching wheel resource gate"
    )
    resources = distribution.public_resource_fingerprints(root)
    required = [
        "web/switching-contracts.js",
        "web/switching.js",
        "web/switching-view.js",
        "resources/switching-study.json",
        "resources/switching-source-bindings.json",
        "resources/switching-extraction-review.json",
        "migrations/011_switching_collection.sql",
        "schemas/switching-study-v1.json",
        "schemas/switching-evidence-v1.json",
        "schemas/switching-comparison-v1.json",
        "schemas/switching-summary-v1.json",
        "schemas/switching-inputs-v1.json",
    ]
    import hashlib

    for name in required:
        assert (
            resources[name]
            == hashlib.sha256((root / "infrastructure_impact" / name).read_bytes()).hexdigest()
        )


# Export must fail before a Git checkout can hide tracked nonpublic work behind
# the copy allowlist. Synthetic checkouts exercise the actual Git inventory.
def release_checkout(tmp_path):
    import subprocess

    from checks import release

    root = tmp_path / "source"
    root.mkdir()
    for name in release.FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic public source\n")
    for name in release.DIRECTORIES:
        (root / name).mkdir(exist_ok=True)
    (root / ".gitignore").write_text(".superpowers/\n__pycache__/\n*.pyc\n")
    (root / "LICENSE").write_text("Apache License\n")
    fixtures = root / "tests/fixtures"
    fixtures.mkdir()
    (fixtures / "manifest.json").write_text("[]")
    (fixtures / "README.md").write_text("Synthetic fixtures\n")
    (root / "infrastructure_impact/web").mkdir()
    (root / "web").symlink_to("infrastructure_impact/web", target_is_directory=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "add", "--all"], check=True, capture_output=True)
    return root


def run_release(monkeypatch, root, destination):
    import sys

    from checks import release

    monkeypatch.setattr(release, "ROOT", root)
    monkeypatch.setattr(sys, "argv", ["release.py", "--output", str(destination)])
    release.main()


def test_release_accepts_public_tracked_inventory_and_canonical_web(tmp_path, monkeypatch, capsys):
    root = release_checkout(tmp_path)
    destination = tmp_path / "export"
    run_release(monkeypatch, root, destination)
    assert (destination / "README.md").read_text() == "synthetic public source\n"
    assert (destination / "web").readlink() == Path("infrastructure_impact/web")
    assert json.loads(capsys.readouterr().out)["private_artifact_checks"] == "passed"


def test_release_rejects_force_tracked_workspace_before_export(tmp_path, monkeypatch):
    import subprocess

    root = release_checkout(tmp_path)
    artifact = root / ".superpowers/internal-workspace/report.md"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("SYNTHETIC PRIVATE SENTINEL")
    subprocess.run(["git", "-C", str(root), "add", "-f", str(artifact)], check=True)
    destination = tmp_path / "export"
    with pytest.raises(ValueError) as caught:
        run_release(monkeypatch, root, destination)
    assert "internal-workspace" not in str(caught.value)
    assert "SENTINEL" not in str(caught.value)
    assert str(root) not in str(caught.value)
    assert not destination.exists()


@pytest.mark.parametrize(
    "name", ["docs/__pycache__/artifact", "checks/stale.pyc", "docs/link", "web"]
)
def test_release_rejects_tracked_ignored_artifacts_and_symlinks(tmp_path, monkeypatch, name):
    import subprocess

    root = release_checkout(tmp_path)
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if name == "web":
        path.unlink()
        path.symlink_to("docs", target_is_directory=True)
    elif name == "docs/link":
        path.symlink_to("../README.md")
    else:
        path.write_text("SYNTHETIC PRIVATE SENTINEL")
    subprocess.run(["git", "-C", str(root), "add", "-f", str(path)], check=True)
    destination = tmp_path / "export"
    with pytest.raises(ValueError) as caught:
        run_release(monkeypatch, root, destination)
    assert name not in str(caught.value)
    assert not destination.exists()


def test_release_source_tarball_retains_existing_export_behavior(tmp_path, monkeypatch, capsys):
    import shutil

    root = release_checkout(tmp_path)
    shutil.rmtree(root / ".git")
    (root / "untracked-workspace").mkdir()
    (root / "untracked-workspace/report").write_text("synthetic non-exported file")
    destination = tmp_path / "export"
    run_release(monkeypatch, root, destination)
    assert not (destination / "untracked-workspace").exists()
    assert json.loads(capsys.readouterr().out)["private_artifact_checks"] == "passed"
