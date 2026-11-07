"""Complete candidate gates use only authored evidence and private temporary stages."""

import importlib
import importlib.util
import json
import sqlite3
from contextlib import closing
from hashlib import sha256

import pytest
from test_arista_current_evidence import arista_case  # noqa: F401
from test_current_evidence_delivery import delivery_db  # noqa: F401
from test_target_import_stage import receipt, serve, setup, snapshot  # noqa: F401

from infrastructure_impact.application import target_import_stage


def implementation():
    name = "infrastructure_impact.application.import_candidate"
    assert importlib.util.find_spec(name) is not None, "complete candidate verifier is absent"
    return importlib.import_module(name)


@pytest.fixture
def candidate(setup, monkeypatch, request):  # noqa: F811
    database, selected, raws, output, home = setup
    from infrastructure_impact.adapters.common import assessment, base
    from infrastructure_impact.storage.repository import connect, ingest

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
        with db:
            db.execute(
                "INSERT INTO correction_proposals(sha256,proposal,review_status) VALUES(?,?,?)",
                ("f" * 64, "PRIVATE_PENDING_REVIEW", "pending"),
            )
    if getattr(request, "param", None) == "stale":
        from test_kev_collection import RAW

        from infrastructure_impact.references.registry import KEV_URL
        from infrastructure_impact.references.storage import ingest as reference_ingest

        with closing(connect(database)) as db:
            reference_ingest(db, RAW, "cisa-kev")
            with db:
                db.execute(
                    "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details) VALUES(?,?,?,?,?)",
                    (
                        "upstream",
                        KEV_URL,
                        "2020-01-01T00:00:00Z",
                        "ok",
                        "authored stale observation",
                    ),
                )
    serve(monkeypatch, selected, raws)
    accepted = receipt(database, selected)
    before = snapshot(database)
    # Ingestion-only fixture leaves the authentic preservation context for the real gate.
    with monkeypatch.context() as patch:
        patch.setattr(
            target_import_stage,
            "verify",
            lambda *a: {
                "audit_passed": None,
                "capacity_passed": None,
                "candidate_validated": False,
            },
        )
        result = target_import_stage.stage(
            database,
            selected,
            accepted["fingerprint"],
            output,
            lock_home=home,
            accepted_preview=accepted,
        )
    assert result["staged_database"] is None
    yield output / "private/data/intel.sqlite3", output / "public", selected
    assert snapshot(database) == before


def test_complete_candidate_builds_with_hostile_parent_roots(candidate, tmp_path, monkeypatch):
    module = implementation()
    sentinel = tmp_path / "HOSTILE"
    sentinel.mkdir()
    (sentinel / "preserve").write_text("untouched")
    for name in ("IMPACT_HOME", "IMPACT_SOURCES", "IMPACT_DATABASE", "IMPACT_PUBLICATIONS"):
        monkeypatch.setenv(name, str(sentinel))
    from infrastructure_impact.application import query, reporting

    monkeypatch.setattr(query, "ROOT", sentinel)
    assert reporting is not None
    result = module.verify(*candidate)
    assert result["audit_passed"] is True
    assert result["capacity_passed"] is True
    assert result["candidate_validated"] is True, result
    facts = result["candidate"]
    assert facts["outcome"] == "passed"
    assert facts["default_monitor_passed"] and facts["archive_monitor_passed"]
    assert facts["parity_passed"]
    assert 0 < facts["compressed_bytes"] < 8_000_000
    assert facts["expanded_bytes"] < 128_000_000
    assert facts["public_bytes"] > facts["expanded_bytes"]
    public = candidate[1]
    assert facts["manifest_sha256"] == sha256((public / "manifest.json").read_bytes()).hexdigest()
    assert list(p.name for p in sentinel.iterdir()) == ["preserve"]
    assert json.loads((public / "kev.json").read_bytes())["source"]["availability"] == "missing"
    assert "/HOSTILE" not in json.dumps(result)


@pytest.mark.parametrize(
    "damage", ["evidence", "observation", "source", "cve", "version", "context"]
)
def test_candidate_rejects_identity_and_preservation_damage(candidate, damage):
    module = implementation()
    database, public, selected = candidate
    if damage == "context":
        path = database.parent.parent / "home/target-import-context.json"
        data = json.loads(path.read_bytes())
        data["binding"]["manifest_fingerprint"] = "0" * 64
        path.write_text(json.dumps(data))
    else:
        with closing(sqlite3.connect(database)) as db, db:
            if damage == "evidence":
                db.execute("UPDATE evidence SET raw=x'00' WHERE id=1")
            elif damage == "observation":
                db.execute("UPDATE evidence SET observed_at='2026-01-01T00:00:00Z' WHERE id=1")
            else:
                row = db.execute(
                    "SELECT id,normalized FROM revisions WHERE vendor='aruba' ORDER BY id LIMIT 1"
                ).fetchone()
                data = json.loads(row[1])
                if damage == "source":
                    data["source_url"] += "?changed"
                elif damage == "cve":
                    data["cves"] = ["CVE-2025-99999"]
                else:
                    data["assessments"][0]["versions"] = [{"expression": "invented version"}]
                db.execute(
                    "UPDATE revisions SET normalized=? WHERE id=?", (json.dumps(data), row[0])
                )
    result = module.verify(database, public, selected)
    assert result["candidate_validated"] is not True
    assert result["candidate"]["outcome"] != "passed"
    assert "staged_database" not in result


@pytest.mark.parametrize(
    "size,name", [(8_000_001, "snapshot.json.gz"), (128_000_001, "snapshot.json")]
)
def test_capacity_measures_full_archive_bound_without_loading_it(tmp_path, size, name):
    module = implementation()
    path = tmp_path / name
    with path.open("wb") as stream:
        stream.truncate(size)
    with pytest.raises(module.CapacityFailure):
        module._measure(path, 8_000_000 if name.endswith(".gz") else 128_000_000)


@pytest.mark.parametrize("missing", ["public_health.py", "switching_health.py"])
def test_missing_installed_monitor_companion_fails_explicitly(tmp_path, monkeypatch, missing):
    module = implementation()
    package = tmp_path / "infrastructure_impact"
    pair = package / "_standalone"
    pair.mkdir(parents=True)
    for name in ("public_health.py", "switching_health.py"):
        if name != missing:
            (pair / name).write_text("# authored placeholder")
    monkeypatch.setattr(module, "PACKAGE", package)
    with pytest.raises(module.MonitorUnavailable):
        module._monitor_path()


def test_new_review_or_exclusion_rows_are_not_permitted(candidate):
    module = implementation()
    database, public, selected = candidate
    with closing(sqlite3.connect(database)) as db, db:
        db.execute(
            "INSERT INTO correction_proposals(sha256,proposal,review_status) VALUES(?,?,?)",
            ("e" * 64, "invented approval", "approved"),
        )
    assert module.verify(database, public, selected)["candidate_validated"] is False


def test_public_output_symlink_never_writes_outside_stage(candidate, tmp_path):
    module = implementation()
    database, public, selected = candidate
    target = tmp_path / "untouched"
    target.mkdir()
    home = database.parent.parent / "home"
    (home / "publications").symlink_to(target, target_is_directory=True)
    assert module.verify(database, public, selected)["candidate_validated"] is not True
    assert list(target.iterdir()) == []


def test_worker_pass_cannot_exceed_capacity_contract():
    module = implementation()
    value = module._empty("passed")
    value.update(audit_passed=True, capacity_passed=True, candidate_validated=True)
    value["candidate"].update(
        generation="a" * 32,
        manifest_sha256="b" * 64,
        public_bytes=150_000_000,
        expanded_bytes=128_000_001,
        compressed_bytes=8_000_001,
        default_checked_bytes=20_000_001,
        default_monitor_passed=True,
        archive_monitor_passed=True,
        parity_passed=True,
    )
    with pytest.raises(ValueError):
        module.validate_result(value)


@pytest.mark.parametrize(
    "damage", ["manifest", "part", "schema", "csv", "selection", "switching", "private_extra"]
)
def test_corrupt_public_candidate_is_rejected(candidate, monkeypatch, damage):
    module = implementation()
    database, public, selected = candidate
    assert module.verify(database, public, selected)["candidate_validated"] is True
    manifest_path = public / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    index = json.loads((public / "data/index.json").read_bytes())
    if damage == "manifest":
        manifest["generation"] = "0" * 32
    elif damage == "private_extra":
        (public / "raw-private.txt").write_text("PRIVATE_SOURCE_BYTES")
        manifest["sha256"]["raw-private.txt"] = sha256(b"PRIVATE_SOURCE_BYTES").hexdigest()
    else:
        name = {
            "part": index["bootstrap"]["path"],
            "schema": "schemas/advisory-v2.json",
            "csv": "impact.csv",
            "selection": "snapshot.json",
            "switching": "switching-comparison.json",
        }[damage]
        path = public / name
        if damage == "csv":
            path.write_bytes(path.read_bytes().replace(b"affected", b"unaffected"))
        else:
            value = json.loads(path.read_bytes())
            if damage == "part":
                value["publication"]["id"] = "0" * 32
            elif damage == "schema":
                value["required"] = []
            elif damage == "selection":
                value["records"][0]["assessments"][0]["status"] = "unaffected"
            else:
                value["definition"]["version"] = "invented"
            path.write_text(json.dumps(value))
        # Rehash CSV/switching to prove semantic checks exceed transport integrity.
        if damage in ("csv", "switching"):
            manifest["sha256"][name] = sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    home = database.parent.parent / "home"
    for key, value in module._environment(database, public, home).items():
        if key.startswith("IMPACT_"):
            monkeypatch.setenv(key, value)
    from infrastructure_impact.application import query, source_audit

    data = json.loads((public / "snapshot.json").read_bytes())
    monkeypatch.setattr(query, "now", lambda: data["generated_at"])
    monkeypatch.setattr(source_audit, "now", lambda: data["generated_at"])
    with pytest.raises(ValueError):
        checked = module._inspect_bundle(public, module._empty()["candidate"])
        module._parity(database, public, home, checked)


def test_authored_candidate_browser_json_csv_and_switching_parity(candidate):
    import csv
    import io
    import subprocess
    from datetime import datetime

    from test_kev_delivery import ADAPTER
    from test_switching_delivery import delivery

    from infrastructure_impact.exports import assessment_export, csv_export, select, switching_csv
    from infrastructure_impact.settings import PACKAGE

    module = implementation()
    assert module.verify(*candidate)["candidate_validated"] is True
    public = candidate[1]
    snapshot = json.loads((public / "snapshot.json").read_bytes())
    evaluated = (
        datetime.fromisoformat(snapshot["generated_at"])
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    ids = sorted(snapshot["all_cves"])
    urls = ["/api/export.json?cves=" + ",".join(ids), "/api/export.csv?cves=" + ",".join(ids)]
    fixed_clock = "const RealDate=Date;c.Date=class extends RealDate {constructor(...a){super(...(a.length?a:[x.evaluated_at]));}static now(){return +new RealDate(x.evaluated_at);}};vm.createContext(c);"
    script = ADAPTER.replace("vm.createContext(c);", fixed_clock)
    browser_json, browser_csv = json.loads(
        subprocess.check_output(
            ["node", "-e", script],
            input=json.dumps(
                dict(
                    root=str(public),
                    web=str(PACKAGE / "web"),
                    queries=urls,
                    evaluated_at=snapshot["generated_at"],
                )
            ).encode(),
        )
    )
    assert browser_json["status"] == browser_csv["status"] == 200
    native = select(snapshot, ids, evaluated_at=evaluated)
    assert json.loads(browser_json["body"])["records"] == assessment_export(native)["records"]
    left = list(csv.DictReader(io.StringIO(csv_export(native))))
    right = list(csv.DictReader(io.StringIO(browser_csv["body"])))
    assert left == right
    hydrated = delivery(public)
    assert hydrated["value"] == json.loads((public / "switching-comparison.json").read_bytes())
    script = "const fs=require('fs'),vm=require('vm');const c={window:{}};vm.createContext(c);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),c);process.stdout.write(c.window.InfrastructureSwitching.csvExport(JSON.parse(fs.readFileSync(0,'utf8'))));"
    browser_switching_csv = subprocess.check_output(
        ["node", "-e", script, str(PACKAGE / "web/switching.js")],
        input=json.dumps(hydrated["value"]).encode(),
    ).decode()
    assert browser_switching_csv == switching_csv(hydrated["value"])


@pytest.mark.parametrize("candidate", ["stale"], indirect=True)
def test_stale_kev_and_pending_review_are_preserved(candidate):
    module = implementation()
    database, public, selected = candidate
    assert module.verify(database, public, selected)["candidate_validated"] is True
    kev = json.loads((public / "kev.json").read_bytes())
    assert kev["source"]["availability"] == "stale"
    assert kev["source"]["checked_at"] == "2020-01-01T00:00:00Z"
    assert set(kev["selection"]["membership"].values()) == {"unknown"}
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("SELECT review_status FROM correction_proposals").fetchall() == [
            ("pending",)
        ]
    assert b"PRIVATE_PENDING_REVIEW" not in (public / "snapshot.json").read_bytes()


@pytest.mark.parametrize(
    "name,size,key",
    [
        ("snapshot.json", 128_000_001, "expanded_bytes"),
        ("snapshot.json.gz", 8_000_001, "compressed_bytes"),
    ],
)
def test_complete_artifact_capacity_retains_failure_measurements(candidate, name, size, key):
    module = implementation()
    assert module.verify(*candidate)["candidate_validated"] is True
    public = candidate[1]
    with (public / name).open("wb") as stream:
        stream.truncate(size)
    facts = module._empty()["candidate"]
    with pytest.raises(module.CapacityFailure):
        module._inspect_bundle(public, facts)
    assert facts[key] == size
    assert facts["public_bytes"] >= size


def test_receipt_rejects_forged_candidate_outcome():
    from test_target_import_contracts import result
    from test_target_import_profiles import manifest

    from infrastructure_impact.application.target_import_contracts import result_bytes
    from infrastructure_impact.collection.target_import_profiles import from_manifest

    module = implementation()
    selected = from_manifest(manifest())
    value = result(selected)
    value["candidate"] = module._empty("passed")["candidate"]
    with pytest.raises(ValueError):
        result_bytes(value, selected=selected)


@pytest.mark.parametrize("payload", [None, b"{}", b'{"x":NaN}', b'{"x":1,"x":2}', b" " * 16_385])
def test_worker_missing_or_malformed_result_fails_closed(candidate, monkeypatch, payload):
    import subprocess

    module = implementation()
    database, public, selected = candidate
    home = database.parent.parent / "home"

    def fake_worker(*args, **kwargs):
        if payload is not None:
            (home / module.RESULT).write_bytes(payload)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(module.subprocess, "run", fake_worker)
    result = module.verify(database, public, selected)
    assert result["candidate"]["outcome"] == "worker_failed"
    assert result["candidate_validated"] is not True
    assert not public.exists()


def test_native_public_gate_preserves_and_rejects_changed_exclusion(
    delivery_db, tmp_path, monkeypatch  # noqa: F811
):
    from infrastructure_impact.application import query, source_audit
    from infrastructure_impact.application.publication import publish

    module = implementation()
    database = tmp_path / "retained.sqlite3"
    with closing(sqlite3.connect(database)) as disk:
        delivery_db.backup(disk)
    home = tmp_path / "home"
    home.mkdir()
    public_root = tmp_path / "publications"
    for key, value in module._environment(database, tmp_path / "public", home).items():
        if key.startswith("IMPACT_"):
            monkeypatch.setenv(key, value)
    at = "2026-11-07T12:00:00Z"
    monkeypatch.setattr(query, "now", lambda: at)
    monkeypatch.setattr(source_audit, "now", lambda: at)
    public = publish(query.state(delivery_db), root=public_root)
    snapshot = json.loads((public / "snapshot.json").read_bytes())
    assert snapshot["current_evidence"]["counts"]["excluded"] == 1
    module._parity(database, public, home, snapshot)
    snapshot["records"].append(snapshot["retained_advisories"][0]["record"])
    with pytest.raises(ValueError, match="native public facts differ"):
        module._parity(database, public, home, snapshot)
