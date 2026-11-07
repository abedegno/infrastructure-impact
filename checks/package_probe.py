"""Executed outside the checkout against installed wheels, including an extension."""

import hashlib
import json
import os
import tempfile
from contextlib import closing
from importlib.metadata import version
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
    if os.environ.get("IMPACT_EXPECTED_PACKAGE_VERSION"):
        assert version("infrastructure-impact") == os.environ["IMPACT_EXPECTED_PACKAGE_VERSION"]
    from infrastructure_impact.recovery_policy import vault_limit
    from infrastructure_impact.storage.profiling import storage_profile

    assert vault_limit("large") == 1024 * 1024 * 1024
    with connect(":memory:") as profiled:
        assert storage_profile(profiled)["schema_version"] == 1
    from infrastructure_impact.application.sbom import inspect as inspect_sbom

    observation = inspect_sbom(
        json.dumps(
            dict(
                bomFormat="CycloneDX",
                specVersion="1.7",
                components=[dict(name="synthetic-library", version="1.0")],
            )
        ).encode()
    )
    assert observation["returned_components"] == 1 and observation["inventory_verified"] is False
    registry = default_registry()
    assert "acme" in registry.names() and "f5" in registry.names()
    assert registry.get("acme").research_evidence is None
    assert registry.get("acme").current_evidence_policy is None
    assert registry.get("aruba").parse_release_history is not None
    assert registry.get("arista").parse_release_history is not None
    package = Path(infrastructure_impact.__file__).parent
    for name, digest in json.loads(
        os.environ.get("IMPACT_EXPECTED_PUBLIC_RESOURCES", "{}")
    ).items():
        assert hashlib.sha256((package / name).read_bytes()).hexdigest() == digest, name
    # Exact import remains an installed-ID-only operator CLI, with closed schemas.
    from infrastructure_impact.application.target_import_contracts import preview_bytes
    from infrastructure_impact.collection.target_import_profiles import PROFILE_ID, profile

    selected = profile(PROFILE_ID)
    assert len(selected.targets) == 174
    assert selected.metadata() == json.loads(
        (package / "resources/target-imports" / (PROFILE_ID + ".json")).read_bytes()
    )
    assert {t.vendor for t in selected.targets} == {"aruba", "cisco"}
    assert all(
        (package / "schemas" / ("target-import-" + name + "-v1.json")).is_file()
        for name in ("manifest", "preview", "result")
    )
    # Unreleased local reconciliation commands/resources work without checkout imports.
    from infrastructure_impact.cli import main as cli_main
    from infrastructure_impact.reconciliation.report import ReportError, validate_report
    from infrastructure_impact.reconciliation.selectors import load_selectors

    assert len(load_selectors()["families"]) == 3
    try:
        validate_report({})
    except ReportError as error:
        assert error.code == "invalid_report"
    else:
        raise AssertionError("Installed report schema accepted an invalid report")
    with tempfile.TemporaryDirectory() as probe_directory:
        probe = Path(probe_directory).resolve()
        for command in ("verify", "scan", "baseline", "report"):
            try:
                cli_main(["cve-reconcile", command, "--help"])
            except SystemExit as error:
                assert error.code == 0
        config = probe / "config.json"
        config.write_text('{"vendors": []}')
        database = probe / "vault.sqlite3"
        with closing(connect(database)) as probe_db:
            probe_db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        cli_main(
            [
                "cve-reconcile",
                "baseline",
                "--database",
                str(database),
                "--config",
                str(config),
                "--output",
                str(probe / "baseline.json"),
            ]
        )
        for command in ("preview", "stage"):
            try:
                cli_main(["target-import", command, "--help"])
            except SystemExit as error:
                assert error.code == 0
        target_preview = probe / "target-preview.json"
        assert (
            cli_main(
                [
                    "target-import",
                    "preview",
                    "--database",
                    str(database),
                    "--profile",
                    PROFILE_ID,
                    "--output",
                    str(target_preview),
                ]
            )
            == 0
        )
        assert preview_bytes(json.loads(target_preview.read_bytes())) == target_preview.read_bytes()
        from infrastructure_impact.reconciliation.baseline import load_baseline

        assert load_baseline(probe / "baseline.json")["revisions"] == []
    for base_path in ("/", "/infrastructure-impact/"):
        target_import_candidate_probe(base_path=base_path)
    configured = json.loads((package / "resources/sources.json").read_text())
    assert next(s for s in configured["reference_sources"] if s["source_id"] == "cisa-kev") == {
        "source_id": "cisa-kev",
        "url": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
        "enabled": True,
    }
    if os.environ.get("IMPACT_DISTRIBUTION_SOURCE_ROOT"):
        assert not package.resolve().is_relative_to(
            Path(os.environ["IMPACT_DISTRIBUTION_SOURCE_ROOT"]).resolve()
        )
    if os.environ.get("IMPACT_EXPECTED_NORMALIZER_FINGERPRINTS"):
        expected = json.loads(os.environ["IMPACT_EXPECTED_NORMALIZER_FINGERPRINTS"])
        assert {vendor: registry.fingerprint(vendor) for vendor in expected} == expected
    assert registry.fingerprint_scheme("acme") == "legacy-package-v1"
    # Installed operator schema and dynamic external-plugin inventory use no checkout.
    from jsonschema import Draft202012Validator

    from infrastructure_impact.application.coverage_gaps import report as coverage_report

    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "operator.sqlite3"
        with closing(connect(database)) as probe_db:
            probe_db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        before = database.read_bytes()
        with connect(database, read_only=True) as operator:
            inventory = coverage_report(operator, {"vendors": []}, vendor="acme")
            assert operator.execute("PRAGMA query_only").fetchone()[0] == 1
        Draft202012Validator(
            json.loads((package / "schemas/coverage-gaps-v1.json").read_text())
        ).validate(inventory)
        assert inventory["scope"] == {"vendor": "acme", "sample_limit": 32}
        assert inventory["sources"] == []
        assert database.read_bytes() == before

    from infrastructure_impact.application.build_inventory import audit, template

    inventory = template("acme", "Example Router", "1.0", "ExampleSSL", "routing")
    assert audit(inventory)["inventory_verified"] is False
    assert (package / "schemas/build-inventory-submission-v1.json").is_file()
    component_url = "https://security.acme.example/components.json"
    component_raw = json.dumps(
        {
            "component_reference": {
                "state": "scoped",
                "blocks": [
                    {
                        "locator": "Example component row",
                        "text": "Synthetic OpenSSH 9.4 reference",
                        "cves": [],
                    }
                ],
                "components": {"openssh": ["9.4"]},
                "component_scope": "Synthetic example router release; no installed-device or CVE inference.",
            }
        }
    ).encode()
    component = registry.normalize_component_inventory(component_raw, component_url, "acme")
    assert component["schema_version"] == 1 and component["components"] == {"openssh": ["9.4"]}
    for name in ("browser-capture-v1.json", "release-history-v1.json"):
        assert (package / "schemas" / name).is_file()
    assert (package / "migrations/004_browser_captures.sql").is_file()
    assert (package / "migrations/006_archive_scope.sql").is_file()
    assert (package / "migrations/007_source_observations.sql").is_file()
    assert (package / "migrations/008_reference_documents.sql").is_file()
    assert (package / "migrations/009_source_selections.sql").is_file()
    assert (package / "migrations/010_archive_parser_replay.sql").is_file()
    assert (package / "resources/studies/openssh-service-2023-2026.json").is_file()
    assert (package / "resources/archive-source-review.json").is_file()
    assert (package / "schemas/comparison-eligibility-v1.json").is_file()
    assert (package / "schemas/component-inventory-v1.json").is_file()
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
    assert set(data["vendors"]) == set(registry.names())
    assert data["current_evidence"]["counts"] == {"current": 1, "excluded": 0, "retained_total": 1}
    assert data["retained_advisories"] == []
    assert not any(p["vendor"] == "acme" for p in data["current_evidence"]["policies"])
    from infrastructure_impact.application.current_evidence import (
        validate_report as validate_current,
    )
    from infrastructure_impact.collection.maintenance_profiles import profile

    assert len(profile("arista-reviewed-2024-0099-0103-v1").allowed_urls) == 3
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
        assert (root / "current/schemas/component-inventory-v1.json").exists()
        assert (root / "current/scorecards.json").exists()
        assert (root / "current/comparison-eligibility.json").exists()
        for filename in (
            "comparison-eligibility-summary.json",
            "product-groups.json",
            "extraction-validation.json",
            "review-packet.json",
            "publisher-history.json",
            "product-cohorts.json",
            "disclosure-review.json",
            "research-dossiers.json",
            "kev.json",
        ):
            assert (root / "current" / filename).exists()
        summary_path = root / "current/comparison-eligibility-summary.json"
        status, _, summary_body = app.route(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/comparison-eligibility-summary.json"}
        )
        assert status == 200 and summary_body == summary_path.read_bytes()
        eligibility_summary = json.loads(summary_body)
        assert (
            eligibility_summary["source_detail"]["sha256"]
            == hashlib.sha256(
                (root / "current/comparison-eligibility.json").read_bytes()
            ).hexdigest()
        )
        assert eligibility_summary["expected_vendor_ids"] == sorted(data["vendors"])
        for filename in (
            "comparison-eligibility-summary-v1.json",
            "product-groups-v1.json",
            "publisher-history-v1.json",
            "extraction-review-v1.json",
            "review-submission-v1.json",
            "static-index-v1.json",
            "vendor-gaps-v1.json",
            "family-completeness-v1.json",
            "comparison-readiness-v1.json",
            "fix-leads-v1.json",
            "component-studies-v1.json",
            "source-selection-v1.json",
            "product-cohort-definition-v1.json",
            "product-cohorts-v1.json",
            "disclosure-review-v1.json",
            "research-dossier-definition-v1.json",
            "research-dossiers-v1.json",
            "kev-v1.json",
        ):
            assert (root / "current/schemas" / filename).exists()
        for contract in (root / "current/schemas").glob("*.json"):
            status, _, contract_body = app.route(
                {
                    "REQUEST_METHOD": "GET",
                    "PATH_INFO": "/schemas/" + contract.name,
                    "QUERY_STRING": "",
                }
            )
            assert status == 200 and contract_body == contract.read_bytes(), contract.name
        snapshot = json.loads((root / "current/snapshot.json").read_text())
        current = json.loads((root / "current/current-evidence.json").read_text())
        validate_current(
            current, publication=snapshot["publication"], generated_at=snapshot["generated_at"]
        )
        index = json.loads((root / "current/data/index.json").read_text())
        capability = index["current_evidence"]
        descriptor = capability["report"]
        raw_part = (root / "current" / descriptor["path"]).read_bytes()
        assert hashlib.sha256(raw_part).hexdigest() == descriptor["sha256"]
        assert len(raw_part) == descriptor["bytes"]
        assert json.loads(raw_part)["data"] == current and capability["retained"] == []
        for path in ("/api/v1/current-evidence", "/api/v1/retained-advisories"):
            for query in ("", "vendor=acme", "cves=CVE-2025-12345", "format=json", "format=csv"):
                if path.endswith("current-evidence") and query:
                    continue
                status, _, body = app.route(
                    {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": query}
                )
                assert status == 200, (path, query)
                if path.endswith("current-evidence"):
                    assert json.loads(body) == current
                elif query != "format=csv":
                    value = json.loads(body)
                    assert value["record_scope"] == "retained_latest_excluded"
                    assert value.get("items", value.get("records")) == []
                response_headers = []
                head = b"".join(
                    app(
                        {"REQUEST_METHOD": "HEAD", "PATH_INFO": path, "QUERY_STRING": query},
                        lambda status, headers: response_headers.extend(headers),
                    )
                )
                assert head == b"" and ("Content-Length", str(len(body))) in response_headers
            status, _, _ = app.route(
                {"REQUEST_METHOD": "POST", "PATH_INFO": path, "QUERY_STRING": ""}
            )
            assert status == 405
        for name in ("lossless-json.js", "current-evidence.js"):
            status, _, body = app.route(
                {"REQUEST_METHOD": "GET", "PATH_INFO": "/" + name, "QUERY_STRING": ""}
            )
            assert status == 200 and body == (package / "web" / name).read_bytes()
            assert (root / "current" / name).read_bytes() == body
        assert (package / "schemas/current-evidence-v1.json").is_file()
        openapi = json.loads((package / "resources/openapi.json").read_text())
        for path in ("/api/v1/current-evidence", "/api/v1/retained-advisories"):
            assert set(openapi["paths"][path]) >= {"get", "head"}
        from infrastructure_impact.application.kev import validate_report

        kev = json.loads((root / "current/kev.json").read_text())
        validate_report(kev)
        assert (
            kev["publication"]
            == json.loads((root / "current/snapshot.json").read_text())["publication"]
        )
        assert kev["source"]["availability"] != "available"
        for path in ("/api/v1/kev", "/kev.json"):
            status, _, body = app.route(
                {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": ""}
            )
            assert status == 200
            served = json.loads(body)
            validate_report(served)
            assert served["publication"] == kev["publication"]
        status, _, body = app.route(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/kev.js", "QUERY_STRING": ""}
        )
        assert status == 200 and body == (package / "web/kev.js").read_bytes()
        from infrastructure_impact.application.switching_evidence import validate_comparison

        study = json.loads((root / "current/switching-comparison.json").read_text())
        validate_comparison(study, publication=kev["publication"], generated_at=kev["generated_at"])
        assert study["availability"] == "available"
        assert all(row["counts"]["advisories"] == 0 for row in study["rows"])
        status, _, body = app.route(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/v1/switching-comparison",
                "QUERY_STRING": "",
            }
        )
        assert status == 200 and json.loads(body)["representation"] == "summary"
        for name in ("switching-contracts.js", "switching.js", "switching-view.js"):
            status, _, body = app.route(
                {"REQUEST_METHOD": "GET", "PATH_INFO": "/" + name, "QUERY_STRING": ""}
            )
            assert status == 200 and body == (package / "web" / name).read_bytes()
        from infrastructure_impact.application.research_dossiers import research_dossiers

        assert (package / "web/research-dossiers.js").is_file()
        assert (package / "resources/research-dossiers.json").is_file()
        for filename in ("research-dossier-definition-v1.json", "research-dossiers-v1.json"):
            assert (package / "schemas" / filename).is_file()
        derived = research_dossiers(data)
        assert len(derived["dossiers"]) == 3
        assert all(
            not t["statements"] for d in derived["dossiers"] for t in d["comparison_targets"]
        )
        assert all(not d["sources"] for d in derived["dossiers"])
        assert all(
            t["vendor"] != "acme" for d in derived["dossiers"] for t in d["comparison_targets"]
        )
        exported = json.loads((root / "current/research-dossiers.json").read_text())
        assert exported["definition_sha256"] == derived["definition_sha256"]
        assert (
            exported["publication"]
            == json.loads((root / "current/snapshot.json").read_text())["publication"]
        )
        for path in ("/api/v1/research-dossiers", "/research-dossiers.json"):
            status, _, dossier_body = app.route(
                {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": ""}
            )
            assert status == 200 and json.loads(dossier_body) == exported
        status, _, dossier_body = app.route(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/v1/research-dossiers",
                "QUERY_STRING": "vendor=acme",
            }
        )
        assert status == 200 and json.loads(dossier_body)["dossiers"] == []
        status, _, script_body = app.route(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/research-dossiers.js", "QUERY_STRING": ""}
        )
        assert status == 200 and script_body == (package / "web/research-dossiers.js").read_bytes()
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
                "external_component_hook": True,
                "vendors": len(registry.names()),
                "schema_validated": True,
                "database_and_publication": True,
                "public_api": True,
                "kev_resources_and_api": True,
                "switching_resources_and_api": True,
                "optional_research_hook_compatible": True,
                "optional_current_evidence_hook_compatible": True,
                "current_evidence_resources_and_api": True,
            }
        )
    )


def target_import_candidate_probe(*, base_path="/"):
    """Run the real worker from the isolated wheel using authored source bytes only."""
    import sqlite3
    import sys
    from contextlib import closing

    from infrastructure_impact.adapters.common import assessment, base
    from infrastructure_impact.application import target_import, target_import_stage
    from infrastructure_impact.application.import_candidate import _monitor_path
    from infrastructure_impact.collection.target_import_profiles import (
        TargetImportProfile,
        TargetImportTarget,
    )
    from infrastructure_impact.settings import PACKAGE

    assert _monitor_path() == PACKAGE / "_standalone/public_health.py"
    assert (PACKAGE / "publication_codec.py").read_bytes() == (
        PACKAGE / "_standalone/publication_codec.py"
    ).read_bytes()
    assert not any(Path(p).name == "checks" for p in sys.path)
    raw = {k: v.encode() for k, v in json.loads(os.environ["IMPACT_TARGET_IMPORT_PROBE"]).items()}
    urls = {
        "aruba": "https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-013.txt",
        "cisco": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fast-Zqr6DD5/csaf/cisco-sa-fast-Zqr6DD5.json",
    }
    targets = []
    for vendor, url in urls.items():
        normalized = default_registry().normalize(raw[vendor], url, vendor)
        targets.append(
            TargetImportTarget(
                vendor,
                normalized["advisory_id"],
                url,
                url.split("/csaf/")[0],
                hashlib.sha256(raw[vendor]).hexdigest(),
                tuple(sorted(normalized["cves"])),
                "2026-11-06T12:00:00Z",
                "2026-11-06T12:00:00Z",
            )
        )
    selected = TargetImportProfile("synthetic-wheel-v1", "1", tuple(targets), 2)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        home = root / "source"
        database = home / "data/intel.sqlite3"
        record = base(
            "juniper",
            "https://www.juniper.net/synthetic/retained",
            "RETAINED",
            "Authored baseline",
            "2025-01-01T00:00:00Z",
        )
        record["cves"] = ["CVE-2024-6387"]
        record["assessments"] = [assessment("CVE-2024-6387", "Junos OS", "affected", "Synthetic")]
        with closing(connect(database)) as db:
            ingest(db, b"authored baseline", record["source_url"], lambda *a: record, "juniper")
        before = database.read_bytes()
        with patch.object(target_import, "registered_profile", return_value=selected):
            accepted = target_import.preview(database, selected.profile_id)
        # Supplying authored bodies is the sole acquisition substitute. No external HTTP.
        with (
            patch.object(
                target_import_stage.transport,
                "fetch",
                side_effect=lambda db, url, vendor, **kw: raw[vendor],
            ),
            patch.dict(
                os.environ,
                {
                    "PATH": str(root / "no-node"),
                    "IMPACT_SOURCES": str(root / "HOSTILE"),
                    "IMPACT_BASE_PATH": "https://hostile.invalid/",
                },
            ),
        ):
            result = target_import_stage.stage(
                database,
                selected,
                accepted["fingerprint"],
                root / "stage",
                lock_home=home,
                accepted_preview=accepted,
                base_path=base_path,
            )
        assert result["outcome"] == "completed", result
        assert result["candidate"]["archive_monitor_passed"] is True
        assert 'src="' + base_path + "assets/" in (root / "stage/public/index.html").read_text()
        published = json.loads((root / "stage/public/snapshot.json").read_bytes())
        run = published["collector"]["last_run"]
        details = json.loads(run["details"])
        assert (run["outcome"], run["imported"], run["failures"]) == ("ok", 2, 0)
        assert details["scope"] == "exact_target_ingestion"
        assert details["unchanged"] == 0 and details["profile_id"] == selected.profile_id
        assert set(details["acquisition"].values()) == {"not_run"}
        assert database.read_bytes() == before
        missing_monitor_probe(root)
        with closing(sqlite3.connect(root / "stage/private/data/intel.sqlite3")) as db:
            assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 3


def missing_monitor_probe(root):
    """A disposable installed-package copy missing either companion must fail closed."""
    import shutil
    import subprocess
    import sys

    from infrastructure_impact.settings import PACKAGE

    for missing in ("public_health.py", "switching_health.py", "publication_codec.py"):
        isolated = root / ("broken-" + missing)
        package = isolated / "infrastructure_impact"
        shutil.copytree(PACKAGE, package, ignore=shutil.ignore_patterns("__pycache__"))
        (package / "_standalone" / missing).unlink()
        stage = isolated / "stage"
        home = stage / "private/home"
        home.mkdir(parents=True)
        database = stage / "private/data/intel.sqlite3"
        database.parent.mkdir()
        shutil.copyfile(root / "stage/private/data/intel.sqlite3", database)
        for name in ("target-import-context.json", "target-import-request.json"):
            shutil.copyfile(root / "stage/private/home" / name, home / name)
        # Test-only bootstrapping selects this disposable incomplete wheel layout.
        code = "import sys;sys.path.insert(0,sys.argv.pop(1));sys.argv=sys.argv[1:];from infrastructure_impact.application.import_candidate import main;main()"
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                code,
                str(isolated),
                "probe",
                "--worker",
                str(database),
                str(stage / "public"),
            ],
            cwd=isolated,
            check=True,
            capture_output=True,
        )
        failure = json.loads((home / "target-import-verification.json").read_bytes())
        assert failure["candidate"]["outcome"] == "monitor_unavailable", failure
        assert failure["candidate_validated"] is False
        assert not (stage / "public").exists()


if __name__ == "__main__":
    main()
