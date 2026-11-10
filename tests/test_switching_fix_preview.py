"""Authored retained bytes only: no hosted state, vendor requests or ingestion."""

import copy
import hashlib
import importlib
import json
import os
import sqlite3

import pytest
from test_switching_fix_expansion_arista import SAMPLES, authored

from infrastructure_impact import remediation_bindings
from infrastructure_impact.plugins.arista import parse

COMMIT = "a" * 40
AT = "2026-11-10T12:00:00Z"


def helper():
    return importlib.import_module("ops.switching_fix_preview")


@pytest.fixture
def retained(tmp_path, monkeypatch):
    sample = SAMPLES[1]  # 0099 has two independently owned CVE clauses.
    raw = authored(sample)
    database = tmp_path / "intel.sqlite3"
    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE evidence(id INTEGER PRIMARY KEY,source_url TEXT,sha256 TEXT,
                              observed_at TEXT,raw BLOB);
        CREATE TABLE source_observations(id INTEGER PRIMARY KEY,vendor TEXT,
                              source_url TEXT,evidence_id INTEGER,checked_at TEXT);
        CREATE TABLE revisions(id INTEGER PRIMARY KEY,vendor TEXT,advisory_id TEXT,
                              source_url TEXT,evidence_id INTEGER,observed_at TEXT,normalized TEXT);
    """)
    url = sample["source_url"]
    db.execute(
        "INSERT INTO evidence VALUES (1,?,?,?,?)", (url, hashlib.sha256(raw).hexdigest(), AT, raw)
    )
    db.execute(
        "INSERT INTO revisions VALUES(1,'arista',?,?,1,?,?)",
        (sample["advisory_id"], url, AT, json.dumps(parse(raw, url, "arista"))),
    )
    db.commit()
    original = remediation_bindings.definition()
    selected = next(s for s in original["sources"] if s["advisory_id"] == sample["advisory_id"])
    monkeypatch.setattr(
        remediation_bindings,
        "definition",
        lambda: {"schema_version": 1, "sources": [copy.deepcopy(selected)]},
    )
    yield database, db, sample
    db.close()


def test_real_extraction_proves_same_affected_fields_and_owned_fixes(retained):
    _, db, _ = retained
    sources = helper()._sources(db)
    assert len(sources) == 1
    source = sources[0]
    assert source["affected_fields_unchanged"] is True
    assert source["before"]["reviewed_links"] == 0
    assert source["after"]["reviewed_links"] == 2
    assert source["after"]["affected_cves"] == source["before"]["affected_cves"] == 2
    assert source["retrieved_at"] == AT


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("missing", "source_missing"),
        ("hash", "source_drift"),
        ("identity", "source_drift"),
        ("identity_vendor", "source_drift"),
        ("source_only", "source_missing"),
        ("planned", "source_drift"),
        ("affected", "affected_changed"),
        ("truncated", "source_drift"),
    ],
)
def test_missing_drift_and_changed_affected_scope_fail_closed(
    retained, monkeypatch, mutation, code
):
    _, db, sample = retained
    if mutation == "missing":
        db.execute("DELETE FROM revisions")
        db.execute("DELETE FROM evidence")
    elif mutation == "hash":
        db.execute("UPDATE evidence SET sha256=?", ("f" * 64,))
    elif mutation in {"identity", "identity_vendor"}:
        doc = parse(authored(sample), sample["source_url"], "arista")
        doc["vendor" if mutation == "identity_vendor" else "advisory_id"] = "PRIVATE/foreign"
        db.execute("UPDATE revisions SET normalized=?", (json.dumps(doc),))
    elif mutation == "source_only":
        db.execute("DELETE FROM revisions")
    elif mutation == "planned":
        raw = authored(sample).replace(b"has been fixed", b"will be fixed")
        db.execute("UPDATE evidence SET raw=?,sha256=?", (raw, hashlib.sha256(raw).hexdigest()))
    else:
        from infrastructure_impact.plugins.registry import default_registry

        registry = default_registry()
        original = registry.research_evidence

        def extract(*args):
            value = original(*args)
            claim = next(c for c in value["claims"] if c["status"] == "affected")
            if mutation == "truncated":
                claim["issues"].append("evidence_text_truncated")
            elif any(c["status"] == "fixed" for c in value["claims"]):
                claim["conditions"].append("PRIVATE changed affected condition")
            return value

        monkeypatch.setattr(registry, "research_evidence", extract)
    with pytest.raises(ValueError, match="^" + code + "$ ".strip()):
        helper()._sources(db)


def test_new_observation_chooses_a_b_a_retained_bytes(retained):
    _, db, sample = retained
    db.execute(
        "INSERT INTO evidence SELECT 2,source_url,?, ?, ? FROM evidence WHERE id=1",
        ("b" * 64, "2026-11-10T13:00:00Z", b"PRIVATE stale capture"),
    )
    db.execute(
        "INSERT INTO source_observations VALUES(1,'arista',?,1,?)",
        (sample["source_url"], "2026-11-10T14:00:00Z"),
    )
    source = helper()._sources(db)[0]
    assert source["retrieved_at"] == "2026-11-10T14:00:00Z"
    assert source["after"]["reviewed_links"] == 2


def test_receipt_rejects_unknown_private_fields_and_oversize():
    module = helper()
    value = module._empty(COMMIT)
    assert len(module.receipt_bytes(value)) <= 65536
    for bad in (
        {**value, "raw": "PRIVATE"},
        {**value, "failure_code": "PRIVATE/path"},
        {**value, "sources": ["PRIVATE" * 20000]},
    ):
        with pytest.raises((ValueError, TypeError)):
            module.receipt_bytes(bad)


def test_missing_database_preview_is_closed_and_does_not_create_database(tmp_path):
    database = tmp_path / "missing.sqlite3"
    result = helper().preview(database, tmp_path / "public", COMMIT)
    assert result["outcome"] == "failed"
    assert result["failure_code"] == "database_missing"
    assert result["network_requests"] == result["revisions_written"] == 0
    assert not database.exists()
    assert "PRIVATE" not in helper().receipt_bytes(result).decode()


def test_all_eight_authored_sources_use_real_typed_extraction(retained, monkeypatch):
    from test_reviewed_remediation_bindings import SAMPLES as CSAF

    _, db, _ = retained
    db.execute("DELETE FROM revisions")
    db.execute("DELETE FROM evidence")
    data, owned, index = copy.deepcopy(remediation_bindings._metadata())
    for i, sample in enumerate([*CSAF, *SAMPLES], 1):
        vendor = "aruba" if "data" in sample else "arista"
        url = sample["source_url"]
        raw = json.dumps(sample["data"]).encode() if vendor == "aruba" else authored(sample)
        digest = hashlib.sha256(raw).hexdigest()
        doc = (
            {"advisory_id": sample["advisory_id"]} if vendor == "aruba" else parse(raw, url, vendor)
        )
        db.execute("INSERT INTO evidence VALUES(?,?,?,?,?)", (i, url, digest, AT, raw))
        db.execute(
            "INSERT INTO revisions VALUES(?,?,?,?,?,?,?)",
            (i, vendor, sample["advisory_id"], url, i, AT, json.dumps(doc)),
        )
        # Authored CSAF bytes use explicit test-only pins, never production bytes.
        if vendor == "aruba":
            for source in data["sources"]:
                if source["advisory_id"] == sample["advisory_id"]:
                    source["source_sha256"] = digest
            owned[vendor, sample["advisory_id"]]["source_sha256"] = digest
            for key, rule in index.items():
                if key[:2] == (vendor, sample["advisory_id"]):
                    rule["source_sha256"] = digest
    monkeypatch.setattr(remediation_bindings, "_metadata", lambda: (data, owned, index))
    monkeypatch.setattr(remediation_bindings, "definition", lambda: copy.deepcopy(data))
    sources = helper()._sources(db)
    assert len(sources) == 8
    assert [s["after"]["reviewed_links"] for s in sources] == [5, 4, 5, 15, 5, 1, 2, 1]
    assert all(s["before"]["reviewed_links"] == 0 for s in sources)
    assert all(s["affected_fields_unchanged"] for s in sources)


def test_preview_reuses_single_build_and_all_mandatory_gates(retained, monkeypatch, tmp_path):
    from infrastructure_impact.application import (
        import_candidate,
        publication,
        publication_v2,
        query,
        source_audit,
    )
    from infrastructure_impact.storage import audit, repository

    database, db, _ = retained
    db.commit()
    calls = []
    at = "2026-11-10T12:00:00+00:00"
    monkeypatch.setattr(repository, "now", lambda: at)

    def build(public, *, publication_format):
        assert publication_format == "v2"
        assert query.now() == source_audit.now() == at
        assert os.environ["IMPACT_DATABASE"] == str(database)
        assert "GH_TOKEN" not in os.environ and "IMPACT_STATE_KEY" not in os.environ
        calls.append("build")

    class Reader:
        def switching_overview(self, *, evaluated_at):
            assert evaluated_at == at
            return {
                "rows": [
                    {"vendor": v, "counts": {k: 1 for k in helper().COHORT_FIELDS}}
                    for v in ("cisco", "aruba", "arista")
                ]
            }

    def inspect(public, facts):
        calls.append("inspect")
        facts.update(
            generation="1" * 32,
            manifest_sha256="2" * 64,
            public_bytes=1000,
            expanded_bytes=700,
            compressed_bytes=200,
        )
        return Reader()

    def monitors(public, home, facts, *, base_path):
        assert base_path == "/infrastructure-impact/"
        calls.append("monitors")
        facts.update(
            default_monitor_passed=True, archive_monitor_passed=True, default_checked_bytes=400
        )

    monkeypatch.setattr(audit, "audit", lambda: calls.append("audit"))
    monkeypatch.setattr(publication, "build", build)
    monkeypatch.setattr(publication_v2, "inspect_bundle", inspect)
    monkeypatch.setattr(import_candidate, "_monitors", monitors)
    monkeypatch.setattr(publication_v2, "native_parity", lambda *args: calls.append("parity"))
    # Any accidental collection/normalization or network transport must fail.
    monkeypatch.setattr(repository, "ingest", lambda *args: pytest.fail("ingestion forbidden"))
    import socket

    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("network forbidden"))
    monkeypatch.setenv("GH_TOKEN", "PRIVATE")
    monkeypatch.setenv("IMPACT_STATE_KEY", "PRIVATE")
    original = database.read_bytes()
    result = helper().preview(database, tmp_path / "public", COMMIT)
    assert result["outcome"] == "passed"
    assert result["database_unchanged"] is True
    assert database.read_bytes() == original
    assert calls == ["audit", "build", "inspect", "monitors", "parity"]
    assert len(result["cohort"]) == 3
    assert "PRIVATE" not in helper().receipt_bytes(result).decode()


def test_gate_failure_and_database_mutation_cannot_pass(retained, monkeypatch, tmp_path):
    from infrastructure_impact.storage import audit

    database, db, _ = retained
    db.commit()

    def corrupt():
        with database.open("ab") as stream:
            stream.write(b"PRIVATE mutated")
        raise RuntimeError("PRIVATE/path failure")

    monkeypatch.setattr(audit, "audit", corrupt)
    result = helper().preview(database, tmp_path / "public", COMMIT)
    assert result["failure_code"] == "database_changed"
    assert result["database_unchanged"] is False
    assert "PRIVATE" not in helper().receipt_bytes(result).decode()


@pytest.mark.parametrize("failure", ["none", "audit", "inventory", "monitor", "parity", "capacity"])
def test_authored_database_passes_real_v2_inventory_parity_and_loopback_monitors(
    retained, monkeypatch, tmp_path, failure
):
    import socket
    from contextlib import closing

    from infrastructure_impact.plugins.registry import default_registry
    from infrastructure_impact.storage import repository

    _, _, sample = retained
    database = tmp_path / "full.sqlite3"
    raw = authored(sample)
    with closing(repository.connect(database)) as db:
        repository.ingest(db, raw, sample["source_url"], default_registry().normalize, "arista")
        from infrastructure_impact.adapters.common import assessment, base

        record = base(
            "juniper",
            "https://www.juniper.net/synthetic/preview",
            "RETAINED",
            "Authored cohort baseline",
            "2026-11-01T00:00:00Z",
        )
        record["cves"] = ["CVE-2024-6387"]
        record["assessments"] = [assessment("CVE-2024-6387", "Junos OS", "affected", "Synthetic")]
        repository.ingest(
            db, b"authored cohort baseline", record["source_url"], lambda *args: record, "juniper"
        )
        db.commit()

    def forbidden(*args, **kwargs):
        pytest.fail("preview must not ingest or normalize retained bytes")

    monkeypatch.setattr(repository, "ingest", forbidden)
    monkeypatch.setattr(default_registry(), "normalize", forbidden)
    connect = socket.socket.connect

    def loopback_only(self, address):
        assert address[0] == "127.0.0.1", "external network forbidden"
        return connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", loopback_only)
    if failure != "none":
        from infrastructure_impact.application import import_candidate, publication_v2
        from infrastructure_impact.storage import audit

        module, name = {
            "audit": (audit, "audit"),
            "inventory": (publication_v2, "inspect_bundle"),
            "monitor": (import_candidate, "_monitors"),
            "parity": (publication_v2, "native_parity"),
            "capacity": (import_candidate, "_monitors"),
        }[failure]

        def reject(*args, **kwargs):
            if failure == "capacity":
                raise import_candidate.CapacityFailure("PRIVATE capacity failure")
            raise ValueError("PRIVATE gate failure")

        monkeypatch.setattr(module, name, reject)
    before = database.read_bytes()
    result = helper().preview(database, tmp_path / "full-public", COMMIT)
    if failure != "none":
        assert result["outcome"] == "failed"
        assert result["gates"]["candidate_validated"] is False
        if failure == "audit":
            assert result["gates"]["audit_passed"] is False
        assert result["failure_code"] == {
            "audit": "audit_failed",
            "capacity": "capacity_failed",
        }.get(failure, "candidate_failed")
        assert result["database_unchanged"] and database.read_bytes() == before
        assert "PRIVATE" not in helper().receipt_bytes(result).decode()
        return
    assert result["outcome"] == "passed", result["failure_code"]
    assert result["gates"]["candidate"]["default_monitor_passed"] is True
    assert result["gates"]["candidate"]["archive_monitor_passed"] is True
    assert result["gates"]["candidate"]["parity_passed"] is True
    assert result["database_unchanged"] and database.read_bytes() == before
    assert {r["vendor"] for r in result["cohort"]} == {"cisco", "aruba", "arista"}


def test_cli_writes_bounded_new_receipt_and_returns_failure_without_database(tmp_path):
    import subprocess
    import sys

    output = tmp_path / "result.json"
    args = [
        sys.executable,
        "-m",
        "ops.switching_fix_preview",
        "--database",
        str(tmp_path / "absent.sqlite3"),
        "--public",
        str(tmp_path / "public"),
        "--output",
        str(output),
        "--source-commit",
        COMMIT,
    ]
    run = subprocess.run(args, capture_output=True, text=True)
    assert run.returncode == 1
    raw = output.read_bytes()
    assert len(raw) <= 65536
    assert json.loads(raw)["failure_code"] == "database_missing"
    output.write_text("PRIVATE existing output")
    run = subprocess.run(args, capture_output=True, text=True)
    assert run.returncode != 0
    assert output.read_text() == "PRIVATE existing output"


def test_receipt_validation_is_fresh_for_nested_private_mutations(retained):
    _, db, _ = retained
    value = helper()._empty(COMMIT)
    value["sources"] = helper()._sources(db)
    helper().receipt_bytes(value)
    for mutation in ("source_url", "retrieved_at", "before", "new_private_field"):
        bad = copy.deepcopy(value)
        bad["sources"][0][mutation] = "PRIVATE/path"
        with pytest.raises((ValueError, TypeError)):
            helper().receipt_bytes(bad)


def test_0140_actual_truncated_affected_scope_is_rejected(retained, monkeypatch):
    _, db, _ = retained
    sample = copy.deepcopy(SAMPLES[0])
    raw = authored(sample).replace(
        b"Publisher configuration qualification.",
        b"Publisher configuration qualification. " + b"x" * 4001,
    )
    url = sample["source_url"]
    doc = parse(raw, url, "arista")
    db.execute(
        "UPDATE evidence SET source_url=?,raw=?,sha256=?",
        (url, raw, hashlib.sha256(raw).hexdigest()),
    )
    db.execute(
        "UPDATE revisions SET advisory_id=?,source_url=?,normalized=?",
        (sample["advisory_id"], url, json.dumps(doc)),
    )
    spec = next(
        s
        for s in remediation_bindings._metadata()[0]["sources"]
        if s["advisory_id"] == sample["advisory_id"]
    )
    monkeypatch.setattr(
        remediation_bindings,
        "definition",
        lambda: {"schema_version": 1, "sources": [copy.deepcopy(spec)]},
    )
    from infrastructure_impact.plugins.registry import default_registry

    claims = default_registry().research_evidence(raw, url, "arista", doc)["claims"]
    assert any(
        "evidence_text_truncated" in c["issues"] for c in claims if c["status"] == "affected"
    )
    with pytest.raises(ValueError, match="^source_drift$"):
        helper()._sources(db)
