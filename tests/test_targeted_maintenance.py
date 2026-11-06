"""Exact-target maintenance uses synthetic sources and explicit disposable vaults."""

import importlib
import json
from contextlib import closing
from hashlib import sha256
from pathlib import Path
from urllib.error import HTTPError

import pytest
from test_arista_current_evidence import alternate_bytes, primary_bytes
from test_arista_reconciliation import html

from infrastructure_impact.adapters.arista_reconciliation import CSAF103, URL99, URL103
from infrastructure_impact.application import maintenance
from infrastructure_impact.cli import main
from infrastructure_impact.collection import transport
from infrastructure_impact.collection.maintenance_profiles import profile
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.storage.locking import writer_lock
from infrastructure_impact.storage.repository import connect, evidence, ingest, latest

PROFILE = "arista-reviewed-2024-0099-0103-v1"


def test_preview_selects_closed_profile_without_writes(tmp_path):
    database = tmp_path / "public.sqlite"
    with closing(connect(database)) as db:
        db.commit()
    before = database.read_bytes()
    output = tmp_path / "preview.json"
    status = None
    try:
        status = main(
            [
                "maintenance",
                "preview",
                "--database",
                str(database),
                "--profile",
                PROFILE,
                "--output",
                str(output),
            ]
        )
    except SystemExit as error:
        status = error.code
    assert status in (None, 0), "registered maintenance preview must succeed"
    receipt = json.loads(output.read_bytes())
    assert receipt["profile_id"] == PROFILE
    assert [t["advisory_id"] for t in receipt["targets"]] == [
        "19862-security-advisory-0099",
        "19917-security-advisory-0103",
    ]
    assert receipt["targets"][0]["cves"] == ["CVE-2024-27890", "CVE-2024-27892"]
    assert receipt["targets"][1]["cves"] == ["CVE-2024-6858"]
    assert database.read_bytes() == before


@pytest.fixture
def vault(tmp_path, monkeypatch):
    path = tmp_path / "public.sqlite"
    raw = alternate_bytes()
    monkeypatch.setattr(
        importlib.import_module("infrastructure_impact.plugins.arista_current_evidence"),
        "REVIEWED_SHA256",
        sha256(raw).hexdigest(),
    )
    registry = default_registry()
    with closing(connect(path)) as db:
        legacy = registry.finalize(structured(raw, CSAF103, "arista"), CSAF103, "arista")
        legacy["adapter_version"] = "synthetic-historical"
        ingest(db, raw, CSAF103, lambda *_: legacy, "arista")
    return path


def deny_fetch(*args, **kwargs):
    pytest.fail("network boundary reached before request was validated")


def bodies_fetcher(bodies):
    called = []

    def retrieve(db, url, vendor, *, max_bytes, allowed_urls):
        assert vendor == "arista"
        assert max_bytes == 2_000_000
        assert allowed_urls == frozenset((URL99, URL103, CSAF103))
        called.append(url)
        assert len(called) <= 3
        value = bodies[url]
        if isinstance(value, Exception):
            raise value
        return value

    return retrieve, called


def sources():
    return {URL99: html(), URL103: primary_bytes(), CSAF103: alternate_bytes()}


def test_stale_preview_refuses_before_fetch(vault):
    accepted = maintenance.preview(vault, PROFILE)["fingerprint"]
    with closing(connect(vault)) as db:
        record = default_registry().normalize(html(), URL99, "arista")
        ingest(db, html(), URL99, lambda *_: record, "arista")
        with pytest.raises(maintenance.MaintenanceBaselineChanged):
            maintenance.apply_profile(db, profile(PROFILE), accepted, fetcher=deny_fetch)


def test_exact_targets_preserve_history_and_repeated_bytes_are_idempotent(vault):
    with closing(connect(vault)) as db:
        old_revisions = [tuple(r) for r in db.execute("SELECT * FROM revisions ORDER BY id")]
        old_evidence = [tuple(r) for r in db.execute("SELECT * FROM evidence ORDER BY id")]
        fetcher, called = bodies_fetcher(sources())
        accepted = maintenance.preview(vault, PROFILE)["fingerprint"]
        receipt = maintenance.apply_profile(db, profile(PROFILE), accepted, fetcher=fetcher)
        assert receipt["outcome"] == "completed"
        assert receipt["imported"] == 2
        assert receipt["unchanged"] == 0
        assert receipt["alternate_outcomes"] == [
            {"source_url": CSAF103, "outcome": "expected_scope_conflict"}
        ]
        assert set(called) == {URL99, URL103, CSAF103}
        assert [
            tuple(r) for r in db.execute("SELECT * FROM revisions ORDER BY id LIMIT 1")
        ] == old_revisions
        assert [
            tuple(r) for r in db.execute("SELECT * FROM evidence ORDER BY id LIMIT 1")
        ] == old_evidence
        assert len(receipt["decisions"]) == 1
        assert len(receipt["proof_fingerprints"]) == 2
        assert "raw_b64" not in json.dumps(receipt)
        assert "Original synthetic alternate" not in json.dumps(receipt)
        count = db.execute("SELECT count(*) FROM revisions").fetchone()[0]
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        again = maintenance.apply_profile(
            db,
            profile(PROFILE),
            maintenance.preview(vault, PROFILE)["fingerprint"],
            fetcher=bodies_fetcher(sources())[0],
        )
        assert (again["outcome"], again["imported"], again["unchanged"]) == ("completed", 0, 2)
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == count


@pytest.mark.parametrize("bad", [None, b"<html>PRIVATE_ERROR</html>", b"{}"])
def test_second_primary_invalid_means_no_normalized_writes(vault, bad):
    bodies = sources()
    bodies[URL103] = HTTPError(URL103, 404, "PRIVATE_ERROR", {}, None) if bad is None else bad
    with closing(connect(vault)) as db:
        before = [tuple(r) for r in db.execute("SELECT * FROM revisions")]
        receipt = maintenance.apply_profile(
            db,
            profile(PROFILE),
            maintenance.preview(vault, PROFILE)["fingerprint"],
            fetcher=bodies_fetcher(bodies)[0],
        )
        assert receipt["outcome"] == "failed_primary_validation"
        assert [tuple(r) for r in db.execute("SELECT * FROM revisions")] == before
        assert "PRIVATE_ERROR" not in json.dumps(receipt)


@pytest.mark.parametrize(
    "bad", [b"{}", b"{PRIVATE_ERROR", HTTPError(CSAF103, 503, "PRIVATE_ERROR", {}, None)]
)
def test_old_proof_does_not_mask_current_attempt_alternate_failure(vault, bad):
    with closing(connect(vault)) as db:
        maintenance.apply_profile(
            db,
            profile(PROFILE),
            maintenance.preview(vault, PROFILE)["fingerprint"],
            fetcher=bodies_fetcher(sources())[0],
        )
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        bodies = sources() | {CSAF103: bad}
        fetcher, called = bodies_fetcher(bodies)
        receipt = maintenance.apply_profile(
            db,
            profile(PROFILE),
            maintenance.preview(vault, PROFILE)["fingerprint"],
            fetcher=fetcher,
        )
        assert receipt["outcome"] == "failed_alternate_validation"
        assert called.count(CSAF103) == 1
        assert receipt["alternate_outcomes"][0]["outcome"] == "failed"
        assert "PRIVATE_ERROR" not in json.dumps(receipt)


def test_selection_drift_refuses_before_http(vault):
    from infrastructure_impact.collection.service import resolve_document, retain_resolution

    accepted = maintenance.preview(vault, PROFILE)["fingerprint"]
    with closing(connect(vault)) as db:
        resolved = resolve_document(
            db, URL103, "arista", fetcher=lambda db, url, vendor: sources()[url]
        )
        retain_resolution(db, "arista", URL103, resolved)
        with pytest.raises(maintenance.MaintenanceBaselineChanged):
            maintenance.apply_profile(db, profile(PROFILE), accepted, fetcher=deny_fetch)


def test_unknown_profile_and_malformed_preview_never_open_db(tmp_path, monkeypatch):
    monkeypatch.setattr(maintenance, "connect", deny_fetch)
    with pytest.raises(ValueError, match="unknown_maintenance_profile"):
        maintenance.preview(tmp_path / "absent.sqlite", "arbitrary")
    bad = tmp_path / "bad.json"
    bad.write_text('{"fingerprint":"' + "a" * 64 + '"}')
    with pytest.raises(ValueError, match="invalid_maintenance_preview"):
        maintenance.load_preview(bad, profile(PROFILE))


def test_cli_writer_contention_and_existing_output(vault, tmp_path, monkeypatch):
    monkeypatch.setenv("IMPACT_HOME", str(tmp_path))
    accepted = tmp_path / "preview.json"
    accepted.write_text(json.dumps(maintenance.preview(vault, PROFILE)))
    output = tmp_path / "out.json"
    with writer_lock() as acquired:
        assert acquired
        status = main(
            [
                "maintenance",
                "apply",
                "--database",
                str(vault),
                "--profile",
                PROFILE,
                "--preview",
                str(accepted),
                "--output",
                str(output),
            ]
        )
    assert status == 1
    assert json.loads(output.read_text())["outcome"] == "skipped_writer_lock"
    with pytest.raises(SystemExit):
        main(
            [
                "maintenance",
                "preview",
                "--database",
                str(vault),
                "--profile",
                PROFILE,
                "--output",
                str(output),
            ]
        )


def test_profile_perimeter_rejects_hostile_same_host_redirect_before_open(tmp_path, monkeypatch):
    class Opener:
        def open(self, request, timeout):
            redirect.redirect_request(
                request, None, 302, "Found", {}, "https://www.arista.com/assets/unrelated.json"
            )
            pytest.fail("hostile redirect accepted")

    def build(handler):
        nonlocal redirect
        redirect = handler
        return Opener()

    redirect = None
    monkeypatch.setattr(transport, "build_opener", build)
    with closing(connect(tmp_path / "public.sqlite")) as db:
        with pytest.raises(ValueError, match="redirect"):
            transport.fetch(db, URL99, "arista", allowed_urls=profile(PROFILE).allowed_urls)


def test_transport_cached_304_and_retry_bounds(tmp_path, monkeypatch):
    calls = []
    status = 503

    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            raise HTTPError(request.full_url, status, "Unavailable", {}, None)

    monkeypatch.setattr(transport, "build_opener", lambda *_: Opener())
    monkeypatch.setattr(transport.time, "sleep", lambda *_: None)
    with closing(connect(tmp_path / "public.sqlite")) as db:
        with pytest.raises(HTTPError):
            transport.fetch(db, URL99, "arista", allowed_urls=profile(PROFILE).allowed_urls)
        assert calls == [URL99, URL99]
        status = 304
        ev = evidence(db, b"x" * 2_000_001, URL99)
        db.execute("INSERT INTO http_cache VALUES(?,?,?,?)", (URL99, "tag", None, ev["id"]))
        db.commit()
        with pytest.raises(ValueError, match="Cached document"):
            transport.fetch(
                db, URL99, "arista", max_bytes=2_000_000, allowed_urls=profile(PROFILE).allowed_urls
            )


def test_missing_legacy_never_accepts_zero_exclusion_cleanup(tmp_path):
    path = tmp_path / "empty-public.sqlite"
    with closing(connect(path)) as db:
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        preview = maintenance.preview(path, PROFILE)
        assert any(i["code"] == "missing_reviewed_legacy_record" for i in preview["issues"])
        receipt = maintenance.apply_profile(
            db, profile(PROFILE), preview["fingerprint"], fetcher=bodies_fetcher(sources())[0]
        )
        assert receipt["outcome"] == "failed_cleanup_proof"
        assert receipt["imported"] == 2
        assert receipt["decisions"] == []


def test_apply_receipt_encoder_rejects_private_or_forged_fields(vault):
    with closing(connect(vault)) as db:
        receipt = maintenance.apply_profile(
            db,
            profile(PROFILE),
            maintenance.preview(vault, PROFILE)["fingerprint"],
            fetcher=bodies_fetcher(sources())[0],
        )
    encoded = maintenance.receipt_bytes(receipt)
    assert encoded.endswith(b"\n")
    with pytest.raises(ValueError):
        maintenance.receipt_bytes(receipt | {"raw_b64": "PRIVATE"})
    forged = json.loads(encoded)
    forged["decisions"][0]["proofs"][0]["source_sha256"] = "f" * 64
    with pytest.raises(ValueError):
        maintenance.receipt_bytes(forged)


def test_preview_no_migration_lock_http_or_observation_time_binding(vault, monkeypatch):
    from infrastructure_impact.storage import locking, repository

    monkeypatch.setattr(repository, "migrate", deny_fetch)
    monkeypatch.setattr(locking, "writer_lock", deny_fetch)
    monkeypatch.setattr(transport, "fetch", deny_fetch)
    first = maintenance.preview(vault, PROFILE)
    monkeypatch.setattr(maintenance, "now", lambda: "2026-11-07T00:00:00Z")
    second = maintenance.preview(vault, PROFILE)
    assert first["fingerprint"] == second["fingerprint"]
    assert first["observed_at"] != second["observed_at"]


def test_profile_document_bounds_before_ingestion(vault):
    bodies = sources() | {URL99: b"x" * 2_000_001}
    with closing(connect(vault)) as db:
        receipt = maintenance.apply_profile(
            db,
            profile(PROFILE),
            maintenance.preview(vault, PROFILE)["fingerprint"],
            fetcher=bodies_fetcher(bodies)[0],
        )
        assert receipt["outcome"] == "failed_primary_validation"
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 1


def test_write_failure_receipt_preserves_prior_independent_import(vault, monkeypatch):
    import sqlite3

    from infrastructure_impact.storage import repository

    real_ingest = repository.ingest
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise sqlite3.OperationalError("PRIVATE_SQL_ERROR")
        return real_ingest(*args, **kwargs)

    monkeypatch.setattr(repository, "ingest", fail_second)
    with closing(connect(vault)) as db:
        receipt = maintenance.apply_profile(
            db,
            profile(PROFILE),
            maintenance.preview(vault, PROFILE)["fingerprint"],
            fetcher=bodies_fetcher(sources())[0],
        )
        assert receipt["outcome"] == "failed_storage"
        assert receipt["imported"] == 1
        assert len(latest(db)) == 2
        assert "PRIVATE_SQL_ERROR" not in json.dumps(receipt)


@pytest.mark.parametrize(
    "mutation", ["unknown_field", "duplicate_key", "bad_targets", "bad_fingerprint", "deep_json"]
)
def test_cli_malformed_preview_refuses_before_database(vault, tmp_path, monkeypatch, mutation):
    value = maintenance.preview(vault, PROFILE)
    if mutation == "unknown_field":
        value["raw_b64"] = "PRIVATE"
    elif mutation == "bad_targets":
        value["targets"][0]["source_url"] = "https://www.arista.com/unreviewed"
    elif mutation == "bad_fingerprint":
        value["baseline_fingerprint"] = "0" * 64
    raw = json.dumps(value)
    if mutation == "duplicate_key":
        raw = raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    if mutation == "deep_json":
        raw = "[" * 10000 + "]" * 10000
    accepted = tmp_path / "invalid.json"
    accepted.write_text(raw)
    from infrastructure_impact.storage import locking, repository

    monkeypatch.setattr(repository, "connect", deny_fetch)
    monkeypatch.setattr(locking, "writer_lock", deny_fetch)
    with pytest.raises(SystemExit) as error:
        main(
            [
                "maintenance",
                "apply",
                "--database",
                str(vault),
                "--profile",
                PROFILE,
                "--preview",
                str(accepted),
                "--output",
                str(tmp_path / "receipt.json"),
            ]
        )
    assert error.value.code == 2


def test_symlink_output_refuses_before_database(tmp_path, monkeypatch):
    from infrastructure_impact.storage import repository

    monkeypatch.setattr(repository, "connect", deny_fetch)
    target = tmp_path / "valuable.json"
    target.write_text("unchanged")
    output = tmp_path / "symlink.json"
    output.symlink_to(target)
    with pytest.raises(SystemExit):
        main(
            [
                "maintenance",
                "preview",
                "--database",
                str(tmp_path / "absent.sqlite"),
                "--profile",
                PROFILE,
                "--output",
                str(output),
            ]
        )
    assert target.read_text() == "unchanged"


def test_closed_profile_rejects_caller_url_expansion(vault):
    from dataclasses import replace

    selected = replace(
        profile(PROFILE),
        allowed_urls=profile(PROFILE).allowed_urls | {"https://www.arista.com/unreviewed"},
    )
    with closing(connect(vault)) as db, pytest.raises(ValueError, match="unregistered"):
        maintenance.apply_profile(
            db, selected, maintenance.preview(vault, PROFILE)["fingerprint"], fetcher=deny_fetch
        )


def test_report_decision_bound_fails_instead_of_truncating(vault):
    with closing(connect(vault)) as db:
        receipt = maintenance.apply_profile(
            db,
            profile(PROFILE),
            maintenance.preview(vault, PROFILE)["fingerprint"],
            fetcher=bodies_fetcher(sources())[0],
        )
    receipt["decisions"] *= 1001
    with pytest.raises(ValueError):
        maintenance.receipt_bytes(receipt)


def test_preview_never_creates_source_sqlite_sidecars(vault):
    before = {p.name: p.read_bytes() for p in vault.parent.iterdir()}
    maintenance.preview(vault, PROFILE)
    after = {p.name: p.read_bytes() for p in vault.parent.iterdir()}
    assert after == before


def test_preview_refuses_nonempty_live_wal_without_opening_source(vault):
    with closing(connect(vault)) as db:
        db.execute("CREATE TABLE concurrent_source_write(value)")
        db.commit()
        assert Path(str(vault) + "-wal").stat().st_size > 0
        with pytest.raises(ValueError, match="maintenance_checkpoint_required"):
            maintenance.preview(vault, PROFILE)


def test_preview_refuses_source_change_during_streaming_copy(vault, monkeypatch):
    import shutil

    real_copy = shutil.copyfileobj

    def changing_copy(source, destination, *args, **kwargs):
        real_copy(source, destination, *args, **kwargs)
        with vault.open("ab") as stream:
            stream.write(b"concurrent source change")

    monkeypatch.setattr(shutil, "copyfileobj", changing_copy)
    with pytest.raises(ValueError, match="maintenance_baseline_changed"):
        maintenance.preview(vault, PROFILE)
