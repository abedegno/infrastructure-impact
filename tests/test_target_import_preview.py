"""Offline, synthetic vaults prove exact import preview preservation and binding."""

import json
import shutil
import sqlite3
from contextlib import closing
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from infrastructure_impact.application import target_import_contracts as contracts
from infrastructure_impact.collection.target_import_profiles import PROFILE_ID, profile
from infrastructure_impact.storage.repository import connect, evidence


def implementation():
    from infrastructure_impact.application import target_import

    return target_import


@pytest.fixture
def vault(tmp_path):
    database = tmp_path / "source.sqlite3"
    target = profile(PROFILE_ID).targets[0]
    with closing(connect(database)) as db:
        for vendor, advisory, url in (
            (target.vendor, target.advisory_id, target.fetch_url),
            ("juniper", "synthetic-other", "https://supportportal.juniper.net/synthetic.json"),
        ):
            with db:
                ev = evidence(db, b"PRIVATE RAW BODY", url)
                document = {
                    "vendor": vendor,
                    "advisory_id": advisory,
                    "source_url": url,
                    "notes": "PRIVATE NORMALIZED TEXT",
                    "cves": ["CVE-2099-12345"],
                }
                db.execute(
                    "INSERT INTO revisions(evidence_id,vendor,advisory_id,source_url,observed_at,normalized) VALUES(?,?,?,?,?,?)",
                    (ev["id"], vendor, advisory, url, "2026-11-07T00:00:00Z", json.dumps(document)),
                )
                selection = db.execute(
                    "INSERT INTO source_selections(vendor,requested_url,observed_at,reason,selected_evidence_id) VALUES(?,?,?,?,?)",
                    (vendor, url, "2026-11-07T00:00:00Z", "synthetic choice", ev["id"]),
                ).lastrowid
                db.execute(
                    "INSERT INTO source_selection_views(selection_id,evidence_id,source_format,adapter_version,assessments) VALUES(?,?,?,?,?)",
                    (selection, ev["id"], "CSAF", "synthetic-v1", 1),
                )
                db.execute(
                    "INSERT INTO source_selection_issues(selection_id,source_url,error_code) VALUES(?,?,?)",
                    (selection, url + "/alternate", "source_access"),
                )
                db.execute(
                    "INSERT INTO http_cache VALUES(?,?,?,?)", (url, "etag-v1", "date", ev["id"])
                )
                db.execute(
                    "INSERT INTO source_observations(vendor,source_url,checked_at,evidence_id,http_status) VALUES(?,?,?,?,?)",
                    (vendor, url, "2026-11-07T00:00:00Z", ev["id"], 200),
                )
    return database


def test_preview_opens_only_readonly_copy_and_preserves_source(vault, monkeypatch):
    module = implementation()
    import infrastructure_impact.collection.transport as transport
    import infrastructure_impact.storage.locking as locking
    import infrastructure_impact.storage.repository as repository
    from infrastructure_impact.settings import Paths

    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in vault.parent.iterdir()}
    original = sqlite3.connect

    def copied_only(path, *args, **kwargs):
        assert str(vault) not in str(path)
        assert "mode=ro" in str(path) and kwargs.get("uri") is True
        return original(path, *args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("Preview reached ambient startup or a writer/network boundary")

    monkeypatch.setattr(sqlite3, "connect", copied_only)
    monkeypatch.setattr(repository, "migrate", forbidden)
    monkeypatch.setattr(locking, "writer_lock", forbidden)
    monkeypatch.setattr(transport, "fetch", forbidden)
    monkeypatch.setattr(Paths, "from_env", forbidden)
    result = module.preview(vault, PROFILE_ID)
    raw = contracts.preview_bytes(result)
    assert result["format"] == "impact-target-import-preview"
    assert len(result["targets"]) == 174
    assert len(result["targets"][0]["before_keys"]) == 1
    assert len(result["targets"][1]["before_keys"]) == 0
    assert b"PRIVATE" not in raw and str(vault).encode() not in raw
    installed = Path(__file__).parents[1] / "infrastructure_impact/resources/sources.json"
    assert result["source_config_fingerprint"] == sha256(installed.read_bytes()).hexdigest()
    assert {
        p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in vault.parent.iterdir()
    } == before


@pytest.mark.parametrize("suffix", ["-wal", "-journal"])
def test_nonempty_journal_rejected_before_sqlite(vault, monkeypatch, suffix):
    module = implementation()
    Path(str(vault) + suffix).write_bytes(b"uncheckpointed")
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: pytest.fail("opened SQLite"))
    with pytest.raises(ValueError, match="target_import_checkpoint_required"):
        module.preview(vault, PROFILE_ID)


@pytest.mark.parametrize("change", ["source", "journal", "replacement"])
def test_concurrent_copy_change_rejected(vault, monkeypatch, change):
    module = implementation()
    original = shutil.copyfileobj

    def changing(source, destination, *args, **kwargs):
        original(source, destination, *args, **kwargs)
        if change == "source":
            with vault.open("ab") as stream:
                stream.write(b"concurrent")
        elif change == "journal":
            Path(str(vault) + "-journal").write_bytes(b"concurrent")
        else:
            replacement = vault.with_suffix(".replacement")
            replacement.write_bytes(vault.read_bytes())
            replacement.replace(vault)

    monkeypatch.setattr(shutil, "copyfileobj", changing)
    with pytest.raises(ValueError, match="target_import_baseline_changed"):
        module.preview(vault, PROFILE_ID)


def test_unknown_profile_precedes_filesystem_access(tmp_path, monkeypatch):
    module = implementation()
    monkeypatch.setattr(Path, "resolve", lambda *a, **k: pytest.fail("filesystem startup"))
    with pytest.raises(ValueError, match="unknown_target_import_profile"):
        module.preview(tmp_path / "missing", "unknown")


def test_source_symlink_rejected(vault):
    link = vault.with_name("link.sqlite3")
    link.symlink_to(vault)
    with pytest.raises(ValueError, match="unsafe_input_path"):
        implementation().preview(link, PROFILE_ID)


# Each mutation represents an independent input to the full candidate or target retrieval.
@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE revisions SET normalized=json_set(normalized,'$.notes','changed') WHERE vendor='juniper'",
        "INSERT INTO revisions(evidence_id,vendor,advisory_id,source_url,observed_at,normalized) SELECT evidence_id,vendor,advisory_id,source_url,observed_at,normalized FROM revisions WHERE vendor='juniper'",
        "UPDATE source_selections SET reason='changed' WHERE vendor='aruba'",
        "UPDATE source_selections SET reason='changed' WHERE vendor='juniper'",
        "UPDATE source_selection_views SET assessments=2 WHERE selection_id=(SELECT id FROM source_selections WHERE vendor='juniper')",
        "UPDATE source_selection_issues SET error_code='normalization' WHERE selection_id=(SELECT id FROM source_selections WHERE vendor='juniper')",
        "UPDATE evidence SET sha256='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' WHERE source_url LIKE '%juniper%'",
        "UPDATE source_observations SET http_status=304 WHERE vendor='aruba'",
        "UPDATE http_cache SET etag='etag-v2' WHERE url NOT LIKE '%juniper%'",
        "UPDATE http_cache SET evidence_id=NULL WHERE url NOT LIKE '%juniper%'",
    ],
)
def test_independent_inventory_selection_and_target_http_drift_changes_binding(vault, sql):
    module = implementation()
    accepted = module.preview(vault, PROFILE_ID)["fingerprint"]
    with closing(connect(vault)) as db, db:
        db.execute(sql)
    assert module.preview(vault, PROFILE_ID)["fingerprint"] != accepted


def test_manifest_config_and_each_normalizer_are_bound(vault, monkeypatch):
    module = implementation()
    selected = profile(PROFILE_ID)
    with closing(connect(vault, read_only=True)) as db:
        baseline = module.binding(db, selected)
        assert (
            module.binding(db, replace(selected, version="2"))["fingerprint"]
            != baseline["fingerprint"]
        )
        for vendor in ("aruba", "cisco"):
            registry = module.default_registry()
            original = registry.fingerprint
            with monkeypatch.context() as patch:
                patch.setattr(
                    registry, "fingerprint", lambda v: "d" * 64 if v == vendor else original(v)
                )
                patch.setattr(module, "default_registry", lambda: registry)
                assert module.binding(db, selected)["fingerprint"] != baseline["fingerprint"]
        with monkeypatch.context() as patch:
            patch.setattr(module, "source_config_fingerprint", lambda: "f" * 64)
            assert module.binding(db, selected)["fingerprint"] != baseline["fingerprint"]


def test_preview_observation_time_is_not_bound(vault, monkeypatch):
    module = implementation()
    first = module.preview(vault, PROFILE_ID)
    monkeypatch.setattr(module, "now", lambda: "2099-01-01T00:00:00Z")
    second = module.preview(vault, PROFILE_ID)
    assert first["observed_at"] != second["observed_at"]
    assert first["fingerprint"] == second["fingerprint"]


@pytest.mark.parametrize("raw", [b"{bad", b"x" * 2_000_001])
def test_bad_preview_receipt_never_reaches_database_startup(tmp_path, monkeypatch, raw):
    implementation()
    path = tmp_path / "preview.json"
    path.write_bytes(raw)
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: pytest.fail("opened SQLite"))
    with pytest.raises(ValueError):
        contracts.load_preview(path, profile(PROFILE_ID))


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE evidence SET sha256='dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' WHERE source_url LIKE '%/proof-only'",
        "UPDATE source_selection_views SET evidence_id=(SELECT id FROM evidence WHERE source_url LIKE '%/replacement') WHERE selection_id=(SELECT id FROM source_selections WHERE vendor='juniper') AND source_format='CSAF'",
        "UPDATE source_selections SET selected_evidence_id=(SELECT id FROM evidence WHERE source_url LIKE '%/proof-only') WHERE vendor='juniper'",
    ],
)
def test_other_vendor_proof_capture_drift_without_normalized_record_change(vault, sql):
    module = implementation()
    with closing(connect(vault)) as db, db:
        capture = evidence(
            db, b"PRIVATE UNNORMALIZED ALTERNATE", "https://supportportal.juniper.net/proof-only"
        )
        evidence(db, b"PRIVATE REPLACEMENT", "https://supportportal.juniper.net/replacement")
        selection = db.execute(
            "SELECT id FROM source_selections WHERE vendor='juniper'"
        ).fetchone()[0]
        db.execute(
            "INSERT INTO source_selection_views(selection_id,evidence_id,source_format,adapter_version,assessments) VALUES(?,?,?,?,?)",
            (selection, capture["id"], "text", "synthetic-proof-v1", 2),
        )
        revisions = [tuple(row) for row in db.execute("SELECT * FROM revisions ORDER BY id")]
    accepted = module.preview(vault, PROFILE_ID)["fingerprint"]
    with closing(connect(vault)) as db, db:
        db.execute(sql)
        assert [
            tuple(row) for row in db.execute("SELECT * FROM revisions ORDER BY id")
        ] == revisions
    assert module.preview(vault, PROFILE_ID)["fingerprint"] != accepted


def test_installed_config_content_drift_is_hashed_without_ambient_config(
    vault, tmp_path, monkeypatch
):
    module = implementation()
    package = tmp_path / "synthetic-package"
    (package / "resources").mkdir(parents=True)
    source = package / "resources/sources.json"
    source.write_bytes(b'{"synthetic":1}')
    monkeypatch.setattr(module, "PACKAGE", package)
    first = module.preview(vault, PROFILE_ID)
    source.write_bytes(b'{"synthetic":2}')
    second = module.preview(vault, PROFILE_ID)
    assert first["source_config_fingerprint"] == sha256(b'{"synthetic":1}').hexdigest()
    assert second["source_config_fingerprint"] == sha256(b'{"synthetic":2}').hexdigest()
    assert first["fingerprint"] != second["fingerprint"]


def test_empty_journals_are_preserved_and_do_not_require_checkpoint(vault):
    for suffix in ("-wal", "-journal"):
        Path(str(vault) + suffix).write_bytes(b"")
    before = {p.name: p.read_bytes() for p in vault.parent.iterdir()}
    implementation().preview(vault, PROFILE_ID)
    assert {p.name: p.read_bytes() for p in vault.parent.iterdir()} == before
