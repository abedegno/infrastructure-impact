"""Offline replay previews, partial failures and lineage must stay defensible."""

import hashlib
import json
import sqlite3
import sys
from contextlib import closing
from dataclasses import replace

import pytest

from infrastructure_impact.application import replay as maintenance
from infrastructure_impact.plugins import FeedBatch, PluginRegistry, VendorPlugin
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.storage.locking import writer_lock
from infrastructure_impact.storage.repository import connect, ingest, latest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("IMPACT_HOME", str(tmp_path))
    monkeypatch.setenv("IMPACT_DATABASE", str(tmp_path / "evidence.sqlite3"))
    for name in ("IMPACT_SNAPSHOT", "IMPACT_BASE_PATH", "IMPACT_DELIVERY_MODE"):
        monkeypatch.setenv(name, "")

    def no_fetch(*args, **kwargs):
        pytest.fail("Offline replay must not retrieve a source")

    monkeypatch.setattr("infrastructure_impact.collection.service.fetch", no_fetch)
    monkeypatch.setattr("infrastructure_impact.collection.transport.fetch", no_fetch)


def source(identity):
    return json.dumps(
        {
            "document": {
                "title": "Synthetic",
                "tracking": {
                    "id": identity,
                    "status": "final",
                    "initial_release_date": "2024-01-01",
                },
            },
            "product_tree": {
                "full_product_names": [{"product_id": "router", "name": "Synthetic router"}]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2099-12345",
                    "product_status": {"known_affected": ["router"]},
                    "remediations": [
                        {
                            "category": "vendor_fix",
                            "details": "Upgrade to 2.0",
                            "date": "2025-01-01",
                        }
                    ],
                }
            ],
        }
    ).encode()


def seed(
    identity, *, vendor="aruba", current=False, invalid=False, registry=None, source_format=None
):
    registry = registry or default_registry()
    host = {
        "aruba": "www.arubanetworks.com",
        "juniper": "supportportal.juniper.net",
        "acme": "security.acme.example",
    }[vendor]
    url = "https://" + host + "/" + identity + ".json"
    raw = source(identity)
    document = registry.normalize(raw, url, vendor)
    if not current:
        document["adapter_version"] = "synthetic-earlier-code"
        document["assessments"][0]["remediations"][0]["availability"] = "vendor_reports_fixed"
    if source_format:
        document["source_format"] = source_format
    if invalid:
        raw = b"PRIVATE SOURCE MUST NOT ENTER ERROR MESSAGES"
    with closing(connect()) as db:
        ingest(db, raw, url, lambda *args: document, vendor)
        with db:
            db.execute(
                "UPDATE evidence SET observed_at='2020-01-01T00:00:00Z' WHERE source_url=?", (url,)
            )
    return document


def counts():
    with closing(connect(read_only=True)) as db:
        return {
            name: db.execute("SELECT count(*) FROM " + name).fetchone()[0]
            for name in (
                "revisions",
                "evidence",
                "source_observations",
                "changes",
                "schema_migrations",
            )
        }


def test_dry_run_is_read_only_without_migrations_lock_or_capture_changes(tmp_path, monkeypatch):
    seed("A")
    before = counts()
    path = tmp_path / "evidence.sqlite3"
    fingerprint = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "infrastructure_impact.storage.repository.migrate",
        lambda *args: pytest.fail("Preview must not migrate"),
    )
    report = maintenance.replay_report(dry_run=True)
    assert report["would_reparse"] == 1 and report["semantic_changes"] == 1
    assert report["reparsed_revisions"] == 0 and report["failed"] == 0
    assert counts() == before and hashlib.sha256(path.read_bytes()).hexdigest() == fingerprint
    assert not (tmp_path / "data/collector.lock").exists()


def test_partial_failure_does_not_block_later_valid_record_or_forge_source_checks():
    seed("A", invalid=True)
    seed("B")
    before = counts()
    with closing(connect(read_only=True)) as db:
        original = {r["advisory_id"]: r for r in latest(db)}
    report = maintenance.replay_report()
    assert report["attempted"] == 2 and report["failed"] == 1 and report["reparsed_revisions"] == 1
    assert report["outcome"] == "partial"
    assert report["failures"][0]["advisory_id"] == "A"
    assert "PRIVATE SOURCE" not in json.dumps(report)
    after = counts()
    assert (
        after["evidence"] == before["evidence"]
        and after["source_observations"] == before["source_observations"]
    )
    with closing(connect(read_only=True)) as db:
        records = {r["advisory_id"]: r for r in latest(db)}
        assert db.execute("SELECT kind FROM changes").fetchone()[0] == "parser_reinterpretation"
    assert records["A"] == original["A"]
    for identity in original:
        assert records[identity]["sha256"] == original[identity]["sha256"]
        assert records[identity]["source_observed_at"] == "2020-01-01T00:00:00Z"
    assert records["B"]["assessments"][0]["remediations"][0]["availability"] == "planned"
    assert maintenance.replay_report()["reparsed_revisions"] == 0


def test_metadata_identity_only_change_adds_no_publisher_change_event():
    document = seed("A", current=True)
    document["adapter_version"] = "synthetic-old-metadata"
    with closing(connect()) as db:
        ingest(db, source("A"), document["source_url"], lambda *args: document, "aruba")
        before = db.execute("SELECT count(*) FROM changes").fetchone()[0]
    report = maintenance.replay_report()
    assert report["reparsed_revisions"] == 1 and report["semantic_changes"] == 0
    with closing(connect(read_only=True)) as db:
        assert db.execute("SELECT count(*) FROM changes").fetchone()[0] == before


def test_limit_vendor_force_and_current_identity_filters():
    seed("A")
    seed("B")
    seed("C", current=True)
    seed("J", vendor="juniper")
    report = maintenance.replay_report(vendor="aruba", limit=1)
    assert report["selected_records"] == 3 and report["already_current"] == 1
    assert (
        report["candidates"] == 2
        and report["attempted"] == 1
        and report["remaining_candidates"] == 1
    )
    report = maintenance.replay_report(vendor="aruba", limit=10)
    assert report["reparsed_revisions"] == 1
    report = maintenance.replay_report(vendor="aruba", force=True)
    assert report["attempted"] == report["unchanged"] == 3 and report["reparsed_revisions"] == 0
    with closing(connect(read_only=True)) as db:
        assert (
            next(r for r in latest(db) if r["vendor"] == "juniper")["adapter_version"]
            == "synthetic-earlier-code"
        )


def test_changed_advisory_identity_requires_review_without_duplicate_insert(monkeypatch):
    seed("A")
    registry = default_registry()

    def renamed(raw, url, vendor):
        result = registry.normalize(raw, url, vendor)
        result["advisory_id"] = "NEW-IDENTITY"
        return result

    changed = PluginRegistry()
    for plugin in registry.all():
        changed.register(
            replace(plugin, parse_document=renamed) if plugin.id == "aruba" else plugin
        )
    monkeypatch.setattr(maintenance, "default_registry", lambda: changed)
    before = counts()
    report = maintenance.replay_report()
    assert (
        report["failed"] == 1
        and report["failures"][0]["error_code"] == "stable_identity_requires_review"
    )
    assert counts() == before


def test_missing_feed_identity_remains_retained_for_review(monkeypatch):
    registry = PluginRegistry()
    registry.register(
        VendorPlugin(
            "acme",
            "Synthetic",
            ("acme.example",),
            structured,
            parse_feed=lambda *args: FeedBatch((), frozenset(), "Synthetic feed"),
        )
    )
    seed("A", vendor="acme", registry=registry, source_format="RSS discovery metadata")
    monkeypatch.setattr(maintenance, "default_registry", lambda: registry)
    before = counts()
    report = maintenance.replay_report()
    assert report["failed"] == 1 and report["reparsed_revisions"] == 0 and counts() == before


def test_removed_vendor_plugin_does_not_block_other_installed_vendors():
    registry = PluginRegistry()
    registry.register(VendorPlugin("acme", "Synthetic", ("acme.example",), structured))
    seed("A", vendor="acme", registry=registry)
    seed("B")
    report = maintenance.replay_report()
    assert report["failed"] == 1 and report["reparsed_revisions"] == 1
    assert report["failures"][0]["error_code"] == "vendor_plugin_unavailable"
    assert report["failures"][0]["current_normalizer_fingerprint"] is None


def test_writer_contention_skips_before_opening_or_creating_database(tmp_path):
    with writer_lock() as acquired:
        assert acquired
        report = maintenance.replay_report()
    assert report["outcome"] == "skipped_writer_lock"
    assert not (tmp_path / "evidence.sqlite3").exists()


def test_storage_write_errors_are_fatal_instead_of_layout_gaps(monkeypatch):
    seed("A")

    def failed_write(*args):
        raise sqlite3.OperationalError("Synthetic disk failure")

    monkeypatch.setattr(maintenance, "ingest", failed_write)
    with pytest.raises(sqlite3.OperationalError):
        maintenance.replay_report()


@pytest.mark.parametrize("limit", [0, -1, 10001, True])
def test_invalid_limits_do_not_create_a_database(tmp_path, limit):
    with pytest.raises(ValueError, match="limit"):
        maintenance.replay_report(limit=limit)
    assert not (tmp_path / "evidence.sqlite3").exists()


def test_failure_examples_are_bounded_and_independent_of_success_examples():
    for i in range(23):
        seed(f"A{i:02}", invalid=True)
    report = maintenance.replay_report()
    assert report["failed"] == 23 and len(report["failures"]) == 20
    assert report["failures_truncated"] and report["examples_truncated"]


def test_oversized_identifier_is_bounded_in_report_without_changing_stored_identity():
    identity = "SYNTHETIC-" + "x" * 400
    seed(identity)
    report = maintenance.replay_report(dry_run=True)
    assert len(report["examples"][0]["advisory_id"]) == 240
    assert report["examples"][0]["identity_label_truncated"]
    with closing(connect(read_only=True)) as db:
        assert latest(db)[0]["advisory_id"] == identity


def test_cli_preview_reports_partial_work_and_does_not_apply(capsys):
    from infrastructure_impact.cli import main

    seed("A", invalid=True)
    seed("B")
    before = counts()
    with pytest.raises(SystemExit) as error:
        main(["reparse", "--dry-run", "--limit", "10"])
    assert error.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["would_reparse"] == 1 and report["reparsed_revisions"] == 0 and counts() == before


def test_feed_replay_selects_exactly_its_retained_identity(monkeypatch):
    registry = PluginRegistry()
    registry.register(VendorPlugin("acme", "Synthetic", ("acme.example",), structured))
    seed("A", vendor="acme", registry=registry, source_format="RSS discovery metadata")
    url = "https://security.acme.example/A.json"
    selected = registry.normalize(source("A"), url, "acme")
    unrelated = registry.normalize(source("OTHER"), url, "acme")
    final = PluginRegistry()
    final.register(
        replace(
            registry.get("acme"),
            parse_feed=lambda *args: FeedBatch(
                (unrelated, selected), frozenset(), "Synthetic feed"
            ),
        )
    )
    monkeypatch.setattr(maintenance, "default_registry", lambda: final)
    report = maintenance.replay_report()
    assert report["reparsed_revisions"] == 1 and not report["failed"]
    with closing(connect(read_only=True)) as db:
        assert [r["advisory_id"] for r in latest(db)] == ["A"]


def test_hosted_maintenance_runs_after_restore_and_before_collection(tmp_path, monkeypatch, capsys):
    from cryptography.fernet import Fernet

    import infrastructure_impact.worker as worker
    from ops import hosted_job as hosted

    seed("A")
    key = Fernet.generate_key()
    state = tmp_path / "state"
    hosted.backup(state, tmp_path / "evidence.sqlite3", key)

    def collect():
        with closing(connect(read_only=True)) as db:
            record = latest(db)[0]
        assert record["adapter_version"] == default_registry().fingerprint("aruba")
        assert record["source_observed_at"] == "2020-01-01T00:00:00Z"
        assert record["assessments"][0]["remediations"][0]["availability"] == "planned"
        return {"outcome": "partial", "failures": 0}

    monkeypatch.setattr(worker, "collect_once", collect)
    monkeypatch.setenv("IMPACT_STATE_KEY", key.decode())
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hosted_job.py",
            "--state-dir",
            str(state),
            "--output",
            str(tmp_path / "public"),
            "--encrypted-state",
            "--reparse-limit",
            "1000",
        ],
    )
    hosted.main()
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines[0]["normalization_maintenance"]["reparsed_revisions"] == 1
    assert lines[-1]["private_recovery"] == "verified"
    assert lines[-1]["normalization_maintenance"]["retrieval_observations_added"] == 0


def test_unapproved_cve_free_parser_result_is_partial_before_storage(monkeypatch):
    seed("A")
    seed("B")
    original = default_registry()
    changed = PluginRegistry()

    def parse(raw, url, vendor):
        document = original.get(vendor).parse_document(raw, url, vendor)
        if document["advisory_id"] == "A":
            document.update(cves=[], assessments=[])
        return document

    for plugin in original.all():
        changed.register(replace(plugin, parse_document=parse) if plugin.id == "aruba" else plugin)
    monkeypatch.setattr(maintenance, "default_registry", lambda: changed)
    before = counts()
    report = maintenance.replay_report()
    assert report["failed"] == 1 and report["reparsed_revisions"] == 1
    assert report["failures"][0]["error_code"] == "unsupported_or_invalid_document"
    after = counts()
    assert after["revisions"] == before["revisions"] + 1
    assert after["evidence"] == before["evidence"]
    with closing(connect(read_only=True)) as db:
        assert next(r for r in latest(db) if r["advisory_id"] == "A")["cves"]


def test_approved_unlinked_notice_passes_reparse_preflight():
    original = default_registry()
    url = "https://www.arubanetworks.com/A.json"
    document = original.normalize(source("A"), url, "aruba")
    document.update(cves=[], assessments=[])
    registry = PluginRegistry()
    registry.register(
        replace(
            original.get("aruba"),
            parse_document=lambda *args: document,
            retain_unlinked_notice=lambda doc: doc["advisory_id"] == "A",
        )
    )
    record = {"vendor": "aruba", "source_url": url, "advisory_id": "A", "source_format": "CSAF"}
    assert maintenance.normalized_record(registry, record, b"synthetic")["cves"] == []


def test_shared_feed_cache_preserves_identity_ambiguity_and_capture_boundaries():
    original = default_registry()
    url = "https://www.arubanetworks.com/index.json"
    documents = [
        original.normalize(source(identity), url, "aruba") for identity in ("A", "B", "D", "D")
    ]
    calls = []

    def parse_feed(raw, source_url, limit, cohort):
        calls.append((raw, source_url))
        return FeedBatch(tuple(documents), frozenset(), "Synthetic shared index")

    registry = PluginRegistry()
    registry.register(replace(original.get("aruba"), parse_feed=parse_feed))
    record = {
        "vendor": "aruba",
        "source_url": url,
        "source_format": "RSS discovery metadata",
        "evidence_id": 1,
    }
    cache = {}
    for identity in ("A", "B"):
        result = maintenance.normalized_record(
            registry, dict(record, advisory_id=identity), b"one", feed_cache=cache
        )
        assert result["advisory_id"] == identity
    assert len(calls) == 1
    for identity in ("D", "missing"):
        with pytest.raises(maintenance.ReparseIdentityError):
            maintenance.normalized_record(
                registry, dict(record, advisory_id=identity), b"one", feed_cache=cache
            )
    assert len(calls) == 1
    maintenance.normalized_record(
        registry, dict(record, advisory_id="A", evidence_id=2), b"two", feed_cache=cache
    )
    assert len(calls) == 2
    with pytest.raises(ValueError, match="different source URL"):
        maintenance.normalized_record(
            registry,
            dict(record, advisory_id="A", source_url=url + "?other"),
            b"one",
            feed_cache=cache,
        )
    assert len(calls) == 3


def test_hosted_vendor_scope_preserves_unselected_vendor_and_capture_times(
    tmp_path, monkeypatch, capsys
):
    from cryptography.fernet import Fernet

    import infrastructure_impact.worker as worker
    from ops import hosted_job as hosted

    seed("A", vendor="aruba")
    seed("J", vendor="juniper")
    key = Fernet.generate_key()
    state = tmp_path / "state"
    hosted.backup(state, tmp_path / "evidence.sqlite3", key)

    def collect():
        with closing(connect(read_only=True)) as db:
            records = {r["vendor"]: r for r in latest(db)}
        assert records["aruba"]["adapter_version"] == default_registry().fingerprint("aruba")
        assert records["juniper"]["adapter_version"] == "synthetic-earlier-code"
        assert all(r["source_observed_at"] == "2020-01-01T00:00:00Z" for r in records.values())
        return dict(outcome="partial", failures=0)

    monkeypatch.setattr(worker, "collect_once", collect)
    monkeypatch.setenv("IMPACT_STATE_KEY", key.decode())
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hosted_job.py",
            "--state-dir",
            str(state),
            "--output",
            str(tmp_path / "public"),
            "--encrypted-state",
            "--reparse-limit",
            "1",
            "--reparse-vendor",
            "aruba",
        ],
    )
    hosted.main()
    reports = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    report = reports[0]["normalization_maintenance"]
    assert report["vendor"] == "aruba" and report["selected_records"] == 1
    assert report["reparsed_revisions"] == 1 and report["network_requests"] == 0
    assert report["retrieval_observations_added"] == 0


@pytest.mark.parametrize("scope,budget", [("aruba", "0"), ("uninstalled", "1"), ("", "1")])
def test_invalid_hosted_vendor_scope_fails_before_recovery(tmp_path, monkeypatch, scope, budget):
    from ops import hosted_job as hosted

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid maintenance scope must not open recovery state")

    monkeypatch.setattr(hosted, "state_backend", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hosted_job.py",
            "--state-dir",
            str(tmp_path / "state"),
            "--output",
            str(tmp_path / "public"),
            "--reparse-limit",
            budget,
            "--reparse-vendor",
            scope,
        ],
    )
    with pytest.raises(SystemExit) as error:
        hosted.main()
    assert error.value.code == 2 and not (tmp_path / "state").exists()
