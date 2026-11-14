"""Authored sources and real SQLite exercise isolated all-target staging."""

import importlib
import importlib.util
import io
import json
import sqlite3
from contextlib import closing
from hashlib import sha256
from pathlib import Path
from urllib.error import HTTPError

import pytest
from test_aruba_text_coverage import signed_text
from test_cisco_platform_scope import document
from test_target_import_contracts import passing_candidate
from test_target_import_profiles import manifest

from infrastructure_impact.application import target_import
from infrastructure_impact.application.target_import_contracts import result_bytes
from infrastructure_impact.collection import transport
from infrastructure_impact.collection.target_import_profiles import from_manifest
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.storage.locking import writer_lock
from infrastructure_impact.storage.repository import connect, evidence, ingest


def implementation():
    name = "infrastructure_impact.application.target_import_stage"
    assert importlib.util.find_spec(name) is not None, "isolated staging is absent"
    return importlib.import_module(name)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    value = manifest()
    raws = {"aruba": signed_text(), "cisco": json.dumps(document()).encode()}
    for t in value["targets"]:
        if t["vendor"] == "aruba":
            t["advisory_id"] = "ARUBA-PSA-2021-013"
            t["fetch_url"] = t["fetch_url"].replace("999", "013")
            t["discovery_url"] = t["fetch_url"]
            t["cve_ids"] = [f"CVE-2021-9000{i}" for i in range(1, 5)]
        else:
            t["advisory_id"] = "cisco-sa-fast-Zqr6DD5"
            t["fetch_url"] = t["fetch_url"].replace("cisco-sa-synthetic-test", t["advisory_id"])
            t["discovery_url"] = t["fetch_url"].split("/csaf/")[0]
            t["cve_ids"] = ["CVE-2021-1375", "CVE-2021-1376"]
        t["source_sha256"] = sha256(raws[t["vendor"]]).hexdigest()
    selected = from_manifest(value)
    home = tmp_path / "source"
    database = home / "data/intel.sqlite3"
    with closing(connect(database)) as db:
        with db:
            evidence(db, b"old raw preserved", "https://example.com/old")
    Path(str(database) + "-wal").touch()
    Path(str(database) + "-journal").touch()
    monkeypatch.setattr(target_import, "registered_profile", lambda _: selected)
    return database, selected, raws, tmp_path / "stage", home


def snapshot(database):
    return {
        suffix: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_ctime_ns)
        if p.exists()
        else None
        for suffix in ("", "-wal", "-shm", "-journal")
        for p in [Path(str(database) + suffix)]
    }


def receipt(database, selected):
    return target_import.preview(database, selected.profile_id)


class Response(io.BytesIO):
    status = 200
    headers = {"Content-Type": "text/plain", "ETag": "test-etag"}


def serve(monkeypatch, selected, raws, *, first_error=False, block=False, cached=False):
    times = []
    now = [0.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(transport.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))
    by_url = {t.fetch_url: raws[t.vendor] for t in selected.targets}

    class Opener:
        def open(self, request, timeout):
            assert timeout == 25 and request.full_url in by_url
            times.append(now[0])
            if first_error and len(times) == 1:
                raise HTTPError(request.full_url, 500, "private error", {}, io.BytesIO(b"error"))
            if block and len(times) == 2:
                raise HTTPError(request.full_url, 403, "private access", {}, io.BytesIO(b"blocked"))
            if cached:
                raise HTTPError(request.full_url, 304, "cached", {}, io.BytesIO())
            return Response(by_url[request.full_url])

    monkeypatch.setattr(transport, "build_opener", lambda *args: Opener())
    return times


def passing_verifier(database, public, selected):
    assert database.name == "intel.sqlite3" and public.name == "public"
    assert (database.parent.parent / "home/target-import-context.json").is_file()
    public.mkdir(exist_ok=True)
    (public / "index.html").write_text("authored test candidate")
    return {
        "audit_passed": True,
        "candidate_validated": True,
        "capacity_passed": True,
        "candidate": passing_candidate(),
    }


def run(setup, monkeypatch, *, verify=True, fingerprint=None):
    module = implementation()
    database, selected, raws, output, home = setup
    if verify:
        monkeypatch.setattr(module, "verify", passing_verifier)
    accepted = receipt(database, selected)
    expected = fingerprint or accepted["fingerprint"]
    before = snapshot(database)
    result = module.stage(
        database, selected, expected, output, lock_home=home, accepted_preview=accepted
    )
    assert snapshot(database) == before
    assert json.loads(result_bytes(result, selected=selected)) == result
    return result


@pytest.mark.parametrize("bad", ["sha", "cve", "identity", "layout"])
def test_late_failure_never_inserts_any_normalized_record(setup, monkeypatch, bad):
    database, selected, raws, output, home = setup
    changed = document()
    if bad == "sha":
        raws["cisco"] += b" "
    elif bad == "cve":
        changed["vulnerabilities"][0]["cve"] = "CVE-2021-99999"
    elif bad == "identity":
        changed["document"]["tracking"]["id"] = "cisco-sa-other"
    else:
        changed = {"not": "an advisory"}
    if bad != "sha":
        raws["cisco"] = json.dumps(changed).encode()
        value = selected.metadata()
        value["targets"][1]["source_sha256"] = sha256(raws["cisco"]).hexdigest()
        selected = from_manifest(value)
        setup = database, selected, raws, output, home
        monkeypatch.setattr(target_import, "registered_profile", lambda _: selected)
    serve(monkeypatch, selected, raws)
    result = run(setup, monkeypatch)
    assert result["outcome"] == "failed"
    assert (
        result["failure_code"]
        == {
            "sha": "source_drift",
            "cve": "identity",
            "identity": "identity",
            "layout": "normalization",
        }[bad]
    )
    assert result["staged_database"] is None
    with closing(sqlite3.connect(output / "private/data/intel.sqlite3")) as db:
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 0
        assert (
            db.execute("SELECT raw FROM evidence WHERE id=1").fetchone()[0] == b"old raw preserved"
        )


def test_success_preserves_history_and_replay_is_unchanged(setup, monkeypatch):
    database, selected, raws, output, home = setup
    for t in selected.targets:
        with closing(connect(database)) as db:
            ingest(db, raws[t.vendor], t.fetch_url, default_registry().normalize, t.vendor)
            with db:
                db.execute("UPDATE evidence SET observed_at='2020-01-01T00:00:00Z'")
    with closing(sqlite3.connect(database)) as source:
        before = source.execute("SELECT * FROM revisions").fetchall()
    serve(monkeypatch, selected, raws)
    result = run(setup, monkeypatch)
    assert result["outcome"] == "completed" and result["counters"]["unchanged"] == 2
    with closing(sqlite3.connect(output / result["staged_database"])) as db:
        assert db.execute("SELECT * FROM revisions").fetchall() == before
        assert {r[0] for r in db.execute("SELECT observed_at FROM evidence")} == {
            "2020-01-01T00:00:00Z"
        }
        assert db.execute("SELECT COUNT(*) FROM source_selections").fetchone()[0] == 0
    context = json.loads((output / "private/home/target-import-context.json").read_text())
    assert context["preservation"]["source_unchanged"] is True
    assert context["preservation"]["existing_rows_unchanged"] is True
    proof = context["preservation"]
    assert proof["source_before"] == proof["source_after"]
    assert proof["source_before"][""]["sha256"] == sha256(database.read_bytes()).hexdigest()


def test_fast_retry_and_next_target_are_paced_at_actual_opens(setup, monkeypatch):
    _, selected, raws, _, _ = setup
    times = serve(monkeypatch, selected, raws, first_error=True)
    result = run(setup, monkeypatch)
    assert result["outcome"] == "completed" and result["counters"]["imported"] == 2
    assert times == [0.0, 1.0, 2.0]
    assert result["counters"]["http_attempts"] == 3
    assert result["counters"]["input_bytes"] == sum(map(len, raws.values()))


def test_second_attempt_access_block_is_bounded_and_preserves_source(setup, monkeypatch):
    _, selected, raws, _, _ = setup
    serve(monkeypatch, selected, raws, first_error=True, block=True)
    result = run(setup, monkeypatch)
    assert result["failure_code"] == "source_access"
    assert result["counters"]["http_attempts"] == 2
    assert result["targets"][1]["status"] == "not_attempted"
    assert "private access" not in json.dumps(result)


def test_stale_binding_never_reaches_http(setup, monkeypatch):
    monkeypatch.setattr(transport, "build_opener", lambda *a: pytest.fail("stale HTTP"))
    result = run(setup, monkeypatch, fingerprint="0" * 64)
    assert result["failure_code"] == "stale_preview"


@pytest.mark.parametrize("conflict", ["source", "hash", "cves"])
def test_existing_identity_cannot_be_downgraded(setup, monkeypatch, conflict):
    database, selected, raws, _, _ = setup
    t = selected.targets[0]
    normalized = default_registry().normalize(raws[t.vendor], t.fetch_url, t.vendor)
    url = t.fetch_url + "?other" if conflict == "source" else t.fetch_url
    normalized["source_url"] = url
    if conflict == "cves":
        normalized["cves"].append("CVE-2021-99999")
    with closing(connect(database)) as db:
        ingest(
            db,
            b"different" if conflict == "hash" else raws[t.vendor],
            url,
            lambda *a: normalized,
            t.vendor,
        )
    monkeypatch.setattr(transport, "build_opener", lambda *a: pytest.fail("conflict HTTP"))
    result = run(setup, monkeypatch)
    assert result["failure_code"] == "existing_identity_conflict"
    assert result["counters"]["imported"] == 0


def test_default_verifier_rejects_empty_monitor_cohort(setup, monkeypatch):
    _, selected, raws, _, _ = setup
    serve(monkeypatch, selected, raws)
    result = run(setup, monkeypatch, verify=False)
    assert result["outcome"] == "failed" and result["failure_code"] == "candidate_validation"
    assert result["staged_database"] is None


def test_lock_contention_no_stage_or_http(setup, monkeypatch):
    _, _, _, output, home = setup
    monkeypatch.setattr(transport, "build_opener", lambda *a: pytest.fail("locked HTTP"))
    with writer_lock(home=home):
        result = run(setup, monkeypatch)
    assert result["outcome"] == "skipped_writer_lock"
    assert not output.exists()


def test_existing_selection_cannot_be_replaced_by_different_capture(setup, monkeypatch):
    database, selected, raws, _, _ = setup
    t = selected.targets[0]
    with closing(connect(database)) as db:
        ingest(db, raws[t.vendor], t.fetch_url, default_registry().normalize, t.vendor)
        with db:
            ev = evidence(db, b"newer selected source", t.fetch_url)
            db.execute(
                "INSERT INTO source_selections(vendor,requested_url,observed_at,reason,selected_evidence_id) VALUES(?,?,?,?,?)",
                (t.vendor, t.fetch_url, "2026-11-07T00:00:00Z", "newer selection", ev["id"]),
            )
    monkeypatch.setattr(
        transport, "build_opener", lambda *a: pytest.fail("selection conflict HTTP")
    )
    result = run(setup, monkeypatch)
    assert result["failure_code"] == "existing_identity_conflict"


def test_ambient_roots_never_resolve_and_source_sqlite_never_opens(setup, monkeypatch):
    module = implementation()
    from infrastructure_impact.settings import Paths

    database, selected, raws, _, _ = setup
    expected = receipt(database, selected)["fingerprint"]
    monkeypatch.setattr(Paths, "from_env", lambda: pytest.fail("ambient settings accessed"))
    monkeypatch.setenv("IMPACT_SOURCES", "/root/PRIVATE-sources.json")
    original = sqlite3.connect

    def isolated(path, *args, **kwargs):
        assert str(database) not in str(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", isolated)
    serve(monkeypatch, selected, raws)
    monkeypatch.setattr(module, "verify", passing_verifier)
    result = run(setup, monkeypatch, fingerprint=expected)
    assert result["outcome"] == "completed"


def test_storage_exception_is_bounded(setup, monkeypatch):
    module = implementation()
    monkeypatch.setattr(
        module.shutil,
        "move",
        lambda *a: (_ for _ in ()).throw(OSError("/private/secret disk path")),
    )
    result = run(setup, monkeypatch)
    assert result["failure_code"] == "storage"
    assert "/private/secret" not in json.dumps(result)


@pytest.mark.parametrize("cached", [False, True])
def test_forty_megabyte_aggregate_includes_cached_inputs(setup, monkeypatch, cached):
    database, selected, raws, output, home = setup
    value = selected.metadata()
    template = value["targets"][1]
    expanded = {t.fetch_url: raws[t.vendor] for t in selected.targets if t.vendor == "aruba"}
    value["targets"] = [value["targets"][0]]
    for index in range(14):
        t = dict(template)
        t["advisory_id"] = f"cisco-sa-synthetic-{index:02d}"
        t["fetch_url"] = template["fetch_url"].replace(template["advisory_id"], t["advisory_id"])
        t["discovery_url"] = t["fetch_url"].split("/csaf/")[0]
        doc = document()
        doc["document"]["tracking"]["id"] = t["advisory_id"]
        raw = json.dumps(doc).encode().ljust(3_000_000, b" ")
        t["source_sha256"] = sha256(raw).hexdigest()
        value["targets"].append(t)
        expanded[t["fetch_url"]] = raw
    value["expected_target_count"] = 15
    selected = from_manifest(value)
    monkeypatch.setattr(target_import, "registered_profile", lambda _: selected)
    if cached:
        with closing(connect(database)) as db:
            with db:
                for url, raw in expanded.items():
                    ev = evidence(db, raw, url)
                    db.execute(
                        "INSERT INTO http_cache VALUES(?,?,?,?)", (url, "cached", None, ev["id"])
                    )

    class Opener:
        def open(self, request, timeout):
            if cached:
                raise HTTPError(request.full_url, 304, "cached", {}, io.BytesIO())
            return Response(expanded[request.full_url])

    monkeypatch.setattr(transport, "build_opener", lambda *a: Opener())
    monkeypatch.setattr(transport.time, "sleep", lambda _: None)
    result = run((database, selected, raws, output, home), monkeypatch)
    assert result["failure_code"] == "input_budget"
    assert result["counters"]["input_bytes"] == 39_000_000 + len(raws["aruba"])
    assert result["counters"]["received_bytes"] == (
        0 if cached else 42_000_000 + len(raws["aruba"])
    )
    with closing(sqlite3.connect(output / "private/data/intel.sqlite3")) as db:
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 0


def test_same_capture_old_parser_reinterprets_without_resetting_capture(setup, monkeypatch):
    database, selected, raws, output, _ = setup
    t = selected.targets[0]
    old = default_registry().normalize(raws[t.vendor], t.fetch_url, t.vendor)
    old["adapter_version"] = "old-parser"
    with closing(connect(database)) as db:
        ingest(db, raws[t.vendor], t.fetch_url, lambda *a: old, t.vendor)
        with db:
            db.execute("UPDATE evidence SET observed_at='2020-01-01T00:00:00Z'")
    serve(monkeypatch, selected, raws)
    result = run(setup, monkeypatch)
    assert result["outcome"] == "completed"
    with closing(sqlite3.connect(output / "private/data/intel.sqlite3")) as db:
        rows = db.execute(
            "SELECT evidence_id, normalized FROM revisions WHERE vendor=? ORDER BY id", (t.vendor,)
        ).fetchall()
        assert len(rows) == 2 and rows[0][0] == rows[1][0]
        assert json.loads(rows[0][1])["adapter_version"] == "old-parser"
        assert json.loads(rows[1][1])["adapter_version"] == default_registry().fingerprint(t.vendor)
        assert (
            db.execute("SELECT observed_at FROM evidence WHERE id=?", (rows[0][0],)).fetchone()[0]
            == "2020-01-01T00:00:00Z"
        )


def test_verifier_cannot_rewrite_preserved_rows_and_still_complete(setup, monkeypatch):
    module = implementation()
    database, selected, raws, output, home = setup
    serve(monkeypatch, selected, raws)
    accepted = receipt(database, selected)
    before = snapshot(database)

    def corrupt(database, public, profile):
        result = passing_verifier(database, public, profile)
        with closing(sqlite3.connect(database)) as db:
            with db:
                db.execute("UPDATE evidence SET raw=x'00' WHERE id=1")
        return result

    monkeypatch.setattr(module, "verify", corrupt)
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert snapshot(database) == before
    assert result["outcome"] == "failed" and result["failure_code"] == "storage"
    assert result["staged_database"] is None


def test_changed_database_after_preview_is_stale_before_http(setup, monkeypatch):
    module = implementation()
    database, selected, _, output, home = setup
    accepted = receipt(database, selected)
    with closing(connect(database)) as db:
        with db:
            ev = evidence(db, b"newer cache", selected.targets[0].fetch_url)
            db.execute(
                "INSERT INTO http_cache VALUES(?,?,?,?)",
                (selected.targets[0].fetch_url, "new", None, ev["id"]),
            )
    monkeypatch.setattr(transport, "build_opener", lambda *a: pytest.fail("stale HTTP"))
    before = snapshot(database)
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert snapshot(database) == before
    assert result["failure_code"] == "stale_preview"
    assert result["fingerprint"] == accepted["fingerprint"]


@pytest.mark.parametrize(
    "path_kind",
    [
        "input_symlink",
        "output_symlink",
        "overlap",
        "within_home",
        "home_symlink",
        "sidecar_symlink",
    ],
)
def test_unsafe_paths_never_reach_http_or_modify_source(setup, monkeypatch, path_kind):
    module = implementation()
    database, selected, _, output, home = setup
    accepted = receipt(database, selected)
    if path_kind == "input_symlink":
        linked = output.parent / "linked.sqlite3"
        linked.symlink_to(database)
        database = linked
    elif path_kind == "output_symlink":
        output.symlink_to(home, target_is_directory=True)
    elif path_kind == "overlap":
        output = database
    elif path_kind == "within_home":
        output = home / "stage"
    elif path_kind == "home_symlink":
        linked = output.parent / "linked-home"
        linked.symlink_to(home, target_is_directory=True)
        home = linked
    else:
        sidecar = Path(str(database) + "-wal")
        sidecar.unlink()
        sidecar.symlink_to(output.parent / "missing-target")
    monkeypatch.setattr(transport, "build_opener", lambda *a: pytest.fail("unsafe HTTP"))
    before = database.read_bytes()
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert result["failure_code"] == "storage"
    assert database.read_bytes() == before


def test_lock_failure_uses_accepted_request_without_source_read(setup, monkeypatch):
    module = implementation()
    database, selected, _, output, home = setup
    accepted = receipt(database, selected)
    monkeypatch.setattr(module, "_file_state", lambda *a: pytest.fail("locked input read"))
    with writer_lock(home=home):
        result = module.stage(
            database,
            selected,
            accepted["fingerprint"],
            output,
            lock_home=home,
            accepted_preview=accepted,
        )
    assert result["outcome"] == "skipped_writer_lock"
    assert result["baseline_fingerprint"] == accepted["baseline_fingerprint"]
    assert result["fingerprint"] == accepted["fingerprint"]
    assert set(result["checks"].values()) == {None}


def test_lock_path_symlink_is_rejected_before_lock_file_access(setup, monkeypatch):
    module = implementation()
    database, selected, _, output, home = setup
    accepted = receipt(database, selected)
    sentinel = output.parent / "private-lock-sentinel"
    sentinel.write_text("preserve")
    (home / "data/collector.lock").symlink_to(sentinel)
    monkeypatch.setattr(module, "writer_lock", lambda **kw: pytest.fail("unsafe lock path opened"))
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert result["failure_code"] == "storage" and sentinel.read_text() == "preserve"


def test_existing_discovery_selection_of_other_capture_blocks_import(setup, monkeypatch):
    module = implementation()
    database, selected, _, output, home = setup
    t = selected.targets[1]
    with closing(connect(database)) as db:
        with db:
            ev = evidence(db, b"newer alternative capture", t.discovery_url)
            db.execute(
                "INSERT INTO source_selections(vendor,requested_url,observed_at,reason,selected_evidence_id) VALUES(?,?,?,?,?)",
                (
                    t.vendor,
                    t.discovery_url,
                    "2026-11-07T00:00:00Z",
                    "explicit retained choice",
                    ev["id"],
                ),
            )
    accepted = receipt(database, selected)
    monkeypatch.setattr(
        transport, "build_opener", lambda *a: pytest.fail("discovery conflict HTTP")
    )
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert result["failure_code"] == "existing_identity_conflict"
    assert result["counters"]["imported"] == 0


def test_unavailable_old_selection_is_unknown_and_its_issues_survive(setup, monkeypatch):
    database, selected, raws, output, _ = setup
    t = selected.targets[0]
    with closing(connect(database)) as db:
        with db:
            db.execute(
                "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details,error_code) VALUES(?,?,?,?,?,?)",
                (
                    t.vendor,
                    t.fetch_url,
                    "2026-11-07T00:00:00Z",
                    "error",
                    "old source error",
                    "source_access",
                ),
            )
    serve(monkeypatch, selected, raws)
    result = run(setup, monkeypatch)
    assert result["outcome"] == "completed"
    with closing(sqlite3.connect(output / "private/data/intel.sqlite3")) as db:
        assert db.execute("SELECT selected_evidence_id FROM source_selections").fetchall() == []
        assert db.execute("SELECT error_code FROM collection_runs").fetchall() == [
            ("source_access",)
        ]


def test_partial_storage_failure_retains_actual_import_identity_only_in_stage(setup, monkeypatch):
    module = implementation()
    database, selected, raws, output, _ = setup
    serve(monkeypatch, selected, raws)
    original = module.ingest

    def fail_second(db, raw, url, adapter, vendor):
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 3
        if vendor == "cisco":
            raise sqlite3.OperationalError("private disk failure")
        return original(db, raw, url, adapter, vendor)

    monkeypatch.setattr(module, "ingest", fail_second)
    result = run(setup, monkeypatch)
    assert result["failure_code"] == "storage" and result["staged_database"] is None
    assert result["counters"]["imported"] == 1
    assert len(result["targets"][0]["after_keys"]) == 1
    assert result["targets"][1]["after_keys"] == []
    with closing(sqlite3.connect(output / "private/data/intel.sqlite3")) as db:
        assert db.execute("SELECT vendor FROM revisions").fetchall() == [("aruba",)]


def test_cli_stage_writes_bounded_result_with_private_permissions(setup, monkeypatch, capsys):
    module = implementation()
    from infrastructure_impact.application.target_import_contracts import preview_bytes
    from infrastructure_impact.cli import main
    from infrastructure_impact.collection import target_import_profiles

    database, selected, raws, output, home = setup
    accepted = receipt(database, selected)
    preview_path = output.parent / "accepted.json"
    preview_path.write_bytes(preview_bytes(accepted, selected=selected))
    monkeypatch.setattr(target_import_profiles, "profile", lambda _: selected)
    monkeypatch.setattr(module, "verify", passing_verifier)
    serve(monkeypatch, selected, raws)
    before = snapshot(database)
    code = main(
        [
            "target-import",
            "stage",
            "--database",
            str(database),
            "--profile",
            selected.profile_id,
            "--output",
            str(output),
            "--preview",
            str(preview_path),
            "--home",
            str(home),
        ]
    )
    result_path = output / "result.json"
    assert code == 0 and json.loads(capsys.readouterr().out) == json.loads(result_path.read_bytes())
    assert result_path.stat().st_mode & 0o777 == 0o600
    assert snapshot(database) == before


@pytest.mark.parametrize(
    "base_path",
    [
        "https://external.invalid/",
        "//host/",
        "/../",
        "/x/./",
        "/x?y/",
        "/x#y/",
        "/x%2fy/",
        "/missing-slash",
        None,
    ],
)
def test_invalid_render_prefix_refused_before_lock_or_source(setup, monkeypatch, base_path):
    database, selected, _, output, home = setup
    accepted = receipt(database, selected)
    module = implementation()
    monkeypatch.setattr(module, "writer_lock", lambda **kw: pytest.fail("invalid prefix lock"))
    with pytest.raises(ValueError, match="base_path"):
        module.stage(
            database,
            selected,
            accepted["fingerprint"],
            output,
            lock_home=home,
            accepted_preview=accepted,
            base_path=base_path,
        )
    assert not output.exists()


def test_recovery_capacity_is_checked_before_expensive_verifier(setup, monkeypatch):
    database, selected, raws, output, home = setup
    accepted = receipt(database, selected)
    before = snapshot(database)
    serve(monkeypatch, selected, raws)
    calls = []

    def unexpected(*args, **kwargs):
        calls.append(True)
        raise AssertionError("verifier must not run")

    module = implementation()
    monkeypatch.setattr(module, "verify", unexpected)
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
        vault_limit_bytes=1,
    )
    assert result["failure_code"] == "candidate_capacity"
    assert result["checks"]["capacity_passed"] is False
    assert not calls
    assert snapshot(database) == before
    assert result["staged_database"] is None and result["public_directory"] is None


@pytest.mark.parametrize("limit", [True, 0, -1, 2 * 1024**3 + 1])
def test_invalid_recovery_bound_rejected_before_stage_state(setup, limit):
    database, selected, _, output, home = setup
    accepted = receipt(database, selected)
    before = snapshot(database)
    with pytest.raises(ValueError):
        implementation().stage(
            database,
            selected,
            accepted["fingerprint"],
            output,
            lock_home=home,
            accepted_preview=accepted,
            vault_limit_bytes=limit,
        )
    assert not output.exists()
    assert snapshot(database) == before
