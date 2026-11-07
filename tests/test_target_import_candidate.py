"""Complete candidate gates use only authored evidence and private temporary stages."""

import importlib
import importlib.util
import json
import sqlite3
from contextlib import closing
from hashlib import sha256

import pytest
from test_arista_current_evidence import arista_case  # noqa: F401
from test_current_evidence_delivery import delivery_db as _delivery_db
from test_target_import_stage import receipt, serve, snapshot
from test_target_import_stage import setup as _setup

from infrastructure_impact.application import target_import_stage

delivery_db = _delivery_db
setup = _setup


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
                "INSERT INTO pipeline_runs(started_at,finished_at,outcome,imported,failures,details) VALUES(?,?,?,?,?,?)",
                (
                    "2020-01-01T00:00:00Z",
                    "2020-01-01T00:01:00Z",
                    "partial",
                    99,
                    7,
                    "prior full collection",
                ),
            )
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
    if getattr(request, "param", None) == "unchanged_one":
        from infrastructure_impact.plugins.registry import default_registry

        target = selected.targets[0]
        with closing(connect(database)) as db:
            ingest(
                db,
                raws[target.vendor],
                target.fetch_url,
                default_registry().normalize,
                target.vendor,
            )
    serve(monkeypatch, selected, raws)
    accepted = receipt(database, selected)
    before = snapshot(database)
    # Save the pre-verification state; the injected gate failure must mark only
    # the rejected fixture stage, not the checkpoint used for real worker tests.
    checkpoint = []

    def pending(database, *args):
        checkpoint.append(database.read_bytes())
        return {"audit_passed": None, "capacity_passed": None, "candidate_validated": False}

    with monkeypatch.context() as patch:
        patch.setattr(target_import_stage, "verify", pending)
        result = target_import_stage.stage(
            database,
            selected,
            accepted["fingerprint"],
            output,
            lock_home=home,
            accepted_preview=accepted,
        )
    assert result["staged_database"] is None
    (output / "private/data/intel.sqlite3").write_bytes(checkpoint[0])
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


@pytest.mark.parametrize("extra_byte", [0, 1])
def test_aggregate_public_capacity_boundary_retains_measurements(candidate, extra_byte):
    module = implementation()
    assert module.verify(*candidate)["candidate_validated"] is True
    public = candidate[1]
    manifest_path = public / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())

    # Eight sparse assets exceed the Pages bound together, never the per-file bound.
    # Hash zeros once for the seven equal assets without allocating a GB of RAM/disk.
    chunk = b"\0" * 1_000_000

    def zero_digest(size):
        digest = sha256()
        full, remainder = divmod(size, len(chunk))
        for _ in range(full):
            digest.update(chunk)
        digest.update(chunk[:remainder])
        return digest.hexdigest()

    common_hash = zero_digest(125_000_000)
    for number in range(8):
        name = f"padding-{number}.bin"
        with (public / name).open("wb") as stream:
            stream.truncate(125_000_000)
        manifest["sha256"][name] = common_hash
    manifest_path.write_text(json.dumps(manifest))
    total = sum(path.stat().st_size for path in public.rglob("*") if path.is_file())
    last = public / "padding-7.bin"
    final_size = 125_000_000 + 1_000_000_000 + extra_byte - total
    with last.open("wb") as stream:
        stream.truncate(final_size)
    manifest["sha256"][last.name] = zero_digest(final_size)
    manifest_path.write_text(json.dumps(manifest))
    assert all(path.stat().st_size < 128_000_000 for path in public.rglob("*") if path.is_file())
    facts = module._empty()["candidate"]
    if extra_byte:
        with pytest.raises(module.CapacityFailure, match="public site"):
            module._inspect_bundle(public, facts)
        assert facts["parity_passed"] is facts["default_monitor_passed"] is None
        assert facts["archive_monitor_passed"] is None
    else:
        assert module._inspect_bundle(public, facts)["publication"]["id"] == manifest["generation"]
    assert facts["public_bytes"] == 1_000_000_000 + extra_byte
    assert facts["generation"] == manifest["generation"]
    assert facts["manifest_sha256"] == sha256(manifest_path.read_bytes()).hexdigest()
    assert facts["expanded_bytes"] == (public / "snapshot.json").stat().st_size
    assert facts["compressed_bytes"] == (public / "snapshot.json.gz").stat().st_size


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
    delivery_db,
    tmp_path,
    monkeypatch,  # noqa: F811
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


@pytest.mark.parametrize("candidate", ["unchanged_one"], indirect=True)
def test_candidate_reports_only_actual_exact_target_pipeline(candidate):
    from datetime import datetime

    module = implementation()
    database, public, selected = candidate
    result = module.verify(database, public, selected)
    assert result["candidate_validated"] is True
    context = json.loads((database.parent.parent / "home/target-import-context.json").read_bytes())
    snapshot = json.loads((public / "snapshot.json").read_bytes())
    run = snapshot["collector"]["last_run"]
    assert run["id"] != 1, "candidate still exposes the prior full collection"
    assert run["outcome"] == "ok" and run["imported"] == 1 and run["failures"] == 0
    assert run["started_at"] == context["operation_started_at"]
    assert run["finished_at"] == context["operation_finished_at"]
    assert datetime.fromisoformat(run["started_at"]) <= datetime.fromisoformat(run["finished_at"])
    details = json.loads(run["details"])
    assert details == {
        "operation": "target_import",
        "scope": "exact_target_ingestion",
        "profile_id": selected.profile_id,
        "profile_version": selected.version,
        "manifest_fingerprint": selected.fingerprint,
        "request_fingerprint": context["binding"]["fingerprint"],
        "target_count": 2,
        "imported": 1,
        "unchanged": 1,
        "acquisition": dict.fromkeys(("benchmark", "feeds", "archive", "cve", "kev"), "not_run"),
        "candidate_acceptance": "separate_stage_result",
    }
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("SELECT * FROM pipeline_runs WHERE id=1").fetchone() == (
            1,
            "2020-01-01T00:00:00Z",
            "2020-01-01T00:01:00Z",
            "partial",
            99,
            7,
            "prior full collection",
        )
        assert db.execute("SELECT COUNT(*) FROM pipeline_runs").fetchone()[0] == 2
    assert not (database.parent.parent / "home/benchmark/results.csv").exists()


@pytest.mark.parametrize("damage", ["extra", "count", "scope", "timestamp", "context_status"])
def test_pipeline_append_must_match_exact_target_work(candidate, damage):
    module = implementation()
    database, public, selected = candidate
    with closing(sqlite3.connect(database)) as db, db:
        rows = db.execute("SELECT id,details FROM pipeline_runs ORDER BY id").fetchall()
        assert len(rows) == 2, "isolated exact-target pipeline row missing"
        run_id, details = rows[-1]
        if damage == "extra":
            db.execute(
                "INSERT INTO pipeline_runs(started_at,outcome) VALUES('2026-01-01T00:00:00Z','ok')"
            )
        elif damage == "count":
            db.execute("UPDATE pipeline_runs SET imported=99 WHERE id=?", (run_id,))
        elif damage == "scope":
            value = json.loads(details)
            value["acquisition"]["benchmark"] = "completed"
            db.execute("UPDATE pipeline_runs SET details=? WHERE id=?", (json.dumps(value), run_id))
        elif damage == "timestamp":
            db.execute(
                "UPDATE pipeline_runs SET started_at='2020-01-01T00:00:00Z' WHERE id=?", (run_id,)
            )
        else:
            path = database.parent.parent / "home/target-import-context.json"
            context = json.loads(path.read_bytes())
            context["targets"][0]["status"] = "unchanged"
            # Even mutually consistent context/run counts cannot fabricate unchanged work.
            value = json.loads(details)
            value.update(imported=1, unchanged=1)
            db.execute(
                "UPDATE pipeline_runs SET imported=1,details=? WHERE id=?",
                (target_import_stage.canonical_json(value).decode(), run_id),
            )
            path.write_text(json.dumps(context))
    assert module.verify(database, public, selected)["candidate_validated"] is False
    assert not public.exists()


@pytest.mark.parametrize("changed_start", [False, True])
def test_failed_candidate_marks_only_owned_isolated_pipeline_error(
    setup, monkeypatch, changed_start
):  # noqa: F811
    database, selected, raws, output, home = setup
    with closing(sqlite3.connect(database)) as db, db:
        db.execute(
            "INSERT INTO pipeline_runs(started_at,outcome,details) VALUES(?,?,?)",
            ("2020-01-01T00:00:00Z", "partial", "keep old row"),
        )
        prior = db.execute("SELECT * FROM pipeline_runs").fetchall()
    accepted = receipt(database, selected)
    original = snapshot(database)
    serve(monkeypatch, selected, raws)

    def reject(staged, *args):
        if changed_start:
            with closing(sqlite3.connect(staged)) as db, db:
                db.execute("UPDATE pipeline_runs SET started_at='2020-02-01T00:00:00Z' WHERE id=2")
        return {"audit_passed": True, "capacity_passed": False, "candidate_validated": False}

    monkeypatch.setattr(target_import_stage, "verify", reject)
    result = target_import_stage.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert result["failure_code"] == "candidate_capacity"
    assert result["staged_database"] is result["public_directory"] is None
    assert snapshot(database) == original
    with closing(sqlite3.connect(output / "private/data/intel.sqlite3")) as db:
        rows = db.execute("SELECT * FROM pipeline_runs ORDER BY id").fetchall()
    assert rows[:1] == prior
    assert len(rows) == 2, "failure has no owned scoped pipeline receipt"
    assert rows[1][3:6] == ("error", 2, 0)
    detail = json.loads(rows[1][6])
    assert detail["failure"] == {"phase": "candidate_verification", "code": "candidate_capacity"}
    assert detail["imported"] == 2 and detail["unchanged"] == 0


@pytest.mark.parametrize("base_path", ["/", "/infrastructure-impact/"])
def test_fresh_worker_uses_private_explicit_render_prefix(candidate, monkeypatch, base_path):
    module = implementation()
    database, public, selected = candidate
    path = database.parent.parent / "home/target-import-context.json"
    context = json.loads(path.read_bytes())
    context["base_path"] = base_path
    path.write_text(json.dumps(context))
    monkeypatch.setenv("IMPACT_BASE_PATH", "https://hostile.invalid/elsewhere/")
    result = module.verify(database, public, selected)
    assert result["candidate_validated"] is True, result
    html = (public / "index.html").read_text()
    assert 'href="' + base_path + "assets/" in html
    assert "hostile.invalid" not in html


def test_prefixed_monitor_refuses_extra_root_routes_and_private_paths(candidate, monkeypatch):
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    module = implementation()
    database, public, selected = candidate
    home = database.parent.parent / "home"
    path = home / "target-import-context.json"
    context = json.loads(path.read_bytes())
    context["base_path"] = "/infrastructure-impact/"
    path.write_text(json.dumps(context))
    result = module.verify(database, public, selected)
    assert result["candidate_validated"] is True
    real = module.subprocess.run
    seen = []

    def checked_run(argv, **kwargs):
        origin = argv[3]
        assert origin.endswith("/infrastructure-impact/")
        host = origin.removesuffix("/infrastructure-impact/")
        for route in (
            "/",
            "/manifest.json",
            "/private/data/intel.sqlite3",
            "/infrastructure-impact/../private/data/intel.sqlite3",
            "/infrastructure-impact/%2e%2e/private/data/intel.sqlite3",
        ):
            with pytest.raises(HTTPError) as error:
                urlopen(host + route, timeout=5)
            assert error.value.code == 404
        with pytest.raises(HTTPError) as error:
            urlopen(
                Request(origin + "manifest.json", headers={"Host": "external.invalid"}), timeout=5
            )
        assert error.value.code == 404
        seen.append(origin)
        return real(argv, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", checked_run)
    module._monitors(public, home, result["candidate"], base_path="/infrastructure-impact/")
    assert len(seen) == 2
