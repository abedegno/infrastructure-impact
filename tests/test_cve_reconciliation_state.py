"""Synthetic offline scans: atomic progress, bounded storage and capture integrity."""

import hashlib
import importlib
import json
import os
import sqlite3
from contextlib import contextmanager

import pytest
from test_cve_reconciliation_snapshot import git, official

from infrastructure_impact.reconciliation import snapshot


@pytest.fixture
def source(tmp_path, monkeypatch):
    repo = tmp_path / "input"
    repo.mkdir()
    git(repo, "init", "-q")
    bodies = []
    for number in range(1234, 1237):
        body = json.dumps(
            {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.1",
                "cveMetadata": {
                    "cveId": f"CVE-2026-{number}",
                    "state": "PUBLISHED",
                    "datePublished": "2026-02-03T00:00:00Z",
                },
                "containers": {
                    "cna": {
                        "affected": [
                            {
                                "vendor": "Cisco",
                                "product": "IOS XE",
                                "versions": [{"version": "x", "status": "unknown"}],
                            }
                        ]
                    }
                },
            }
        ).encode()
        path = repo / f"cves/2026/1xxx/CVE-2026-{number}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        bodies.append(body)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "synthetic")
    commit, _, _, _ = official(monkeypatch, snapshot, repo)
    receipt = tmp_path / "receipt.json"
    snapshot.verify_snapshot(repo, commit, receipt)

    def no_network(*args, **kwargs):
        raise AssertionError("offline scan attempted network")

    monkeypatch.setattr(snapshot.http.client, "HTTPSConnection", no_network)
    return dict(
        repository=repo,
        commit=commit,
        receipt_path=receipt,
        workspace=tmp_path / "workspace",
        start_date="2026-01-01",
        end_date="2026-12-31",
    ), bodies


def modules():
    return (
        importlib.import_module("infrastructure_impact.reconciliation.scan"),
        importlib.import_module("infrastructure_impact.reconciliation.state"),
    )


@pytest.fixture(
    params=[
        ("date", b"1e400"),
        ("date", b'"\\ud800"'),
        ("evidence", b"-1e400"),
        ("evidence", b'"\\udfff"'),
        ("date", b'{"\\ud800":["SOURCE_TEXT"]}'),
        ("evidence", b'{"\\udfff":["SOURCE_TEXT"]}'),
    ]
)
def uncommittable_source(source, monkeypatch, request):
    args, bodies = source
    location, token = request.param
    body = json.loads(bodies[0])
    if location == "date":
        body["cveMetadata"]["datePublished"] = "SYNTHETIC_UNSERIALIZABLE"
    else:
        body["containers"]["cna"]["affected"][0]["extra"] = {"nested": ["SYNTHETIC_UNSERIALIZABLE"]}
    raw = json.dumps(body).encode().replace(b'"SYNTHETIC_UNSERIALIZABLE"', token)
    path = args["repository"] / "cves/2026/1xxx/CVE-2026-1234.json"
    path.write_bytes(raw)
    git(args["repository"], "add", ".")
    git(args["repository"], "commit", "-qm", "synthetic uncommittable scalar")
    args["commit"], _, _, _ = official(monkeypatch, snapshot, args["repository"])
    args["receipt_path"] = args["receipt_path"].with_name("scalar-receipt.json")
    snapshot.verify_snapshot(args["repository"], args["commit"], args["receipt_path"])

    def no_network(*args, **kwargs):
        raise AssertionError("offline scan attempted network")

    monkeypatch.setattr(snapshot.http.client, "HTTPSConnection", no_network)
    return args, [raw, *bodies[1:]]


def test_invalid_scalars_commit_then_resume_past_following_valid_records(uncommittable_source):
    scan, state = modules()
    args, bodies = uncommittable_source
    partial = scan.scan_snapshot(**args, record_limit=1)
    assert partial["attempted"] == partial["invalid"] == partial["unresolved"] == 1
    assert partial["remaining"] == 2 and partial["candidate_findings"] == 0
    assert partial["stop_reason"] == "record_limit"
    complete = scan.scan_snapshot(**args)
    assert complete["attempted"] == 3 and complete["parsed"] == 2
    assert complete["invalid"] == complete["unresolved"] == 1
    assert complete["scan_complete"] and complete["remaining"] == 0
    assert complete["stop_reason"] == "complete" and complete["candidate_findings"] == 2
    with state.open_workspace(args["workspace"]) as reader:
        outcomes = list(reader.iter_outcomes())
        findings = list(reader.iter_findings())
        invalid = outcomes[0]
        assert invalid["capture_sha256"] is None and invalid["finding_count"] == 0
        assert invalid["source_sha256"] == hashlib.sha256(bodies[0]).hexdigest()
        assert invalid["metadata"]["diagnostic_codes"] == ["invalid_json_scalar"]
        assert invalid["metadata"]["dates"] == dict(
            dateReserved=None, datePublished=None, dateUpdated=None
        )
        assert [row["outcome"] for row in outcomes] == ["invalid", "parsed", "parsed"]
        assert reader.read_capture(hashlib.sha256(bodies[1]).hexdigest()) == bodies[1]
    before = (args["workspace"] / "state.sqlite3").read_bytes()
    resumed = scan.scan_snapshot(**args)
    assert resumed["invocation_attempted"] == resumed["invocation_consumed_bytes"] == 0
    assert resumed["scan_complete"] and resumed["invalid"] == 1
    assert (args["workspace"] / "state.sqlite3").read_bytes() == before
    with state.open_workspace(args["workspace"]) as reader:
        assert list(reader.iter_outcomes()) == outcomes
        assert list(reader.iter_findings()) == findings


def test_limits_stop_before_next_record_and_resume_exactly(source):
    scan, state = modules()
    args, bodies = source
    result = scan.scan_snapshot(**args, byte_limit=len(bodies[0]) - 1)
    assert result["attempted"] == 0
    assert result["stop_reason"] == "byte_limit"
    assert result["oversized"] == 0
    result = scan.scan_snapshot(**args, record_limit=1)
    assert result["attempted"] == 1 and result["remaining"] == 2
    assert result["consumed_bytes"] == len(bodies[0])
    result = scan.scan_snapshot(**args)
    assert result["attempted"] == 3 and result["scan_complete"]
    assert result["parsed"] == 3 and result["candidate_findings"] == 3
    with state.open_workspace(args["workspace"]) as reader:
        assert len(list(reader.iter_findings())) == 3
        assert [row["position"] for row in reader.iter_outcomes()] == [0, 1, 2]
        assert reader.read_capture(hashlib.sha256(bodies[0]).hexdigest()) == bodies[0]


@pytest.mark.parametrize("after", [False, True])
def test_crash_before_and_after_commit_is_idempotent(source, monkeypatch, after):
    scan, state = modules()
    args, _ = source
    original = state.Workspace.commit_record

    def crash(self, *a, **kw):
        if after:
            original(self, *a, **kw)
        raise RuntimeError("injected interruption")

    with monkeypatch.context() as patch:
        patch.setattr(state.Workspace, "commit_record", crash)
        with pytest.raises(RuntimeError):
            scan.scan_snapshot(**args)
    result = scan.scan_snapshot(**args)
    assert result["attempted"] == 3 and result["candidate_findings"] == 3
    assert len(list((args["workspace"] / "captures").glob("*.json"))) == 3


def test_changed_identity_rejected_without_state_mutation(source):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args, record_limit=1)
    before = (args["workspace"] / "state.sqlite3").read_bytes()
    with pytest.raises(state.StateError, match="identity_mismatch"):
        scan.scan_snapshot(**(args | {"start_date": "2026-02-01"}))
    assert (args["workspace"] / "state.sqlite3").read_bytes() == before


@pytest.mark.parametrize("target", ["capture", "counter", "finding", "outcome"])
def test_tampered_capture_or_counter_fails_resume(source, target):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args, record_limit=1)
    if target == "capture":
        next((args["workspace"] / "captures").glob("*.json")).write_bytes(b"tampered")
    else:
        with sqlite3.connect(args["workspace"] / "state.sqlite3") as db:
            if target == "counter":
                db.execute("UPDATE meta SET value='99' WHERE key='cursor'")
            elif target == "finding":
                db.execute("UPDATE findings SET payload='{}'")
            else:
                db.execute("UPDATE outcomes SET payload='{}'")
    with pytest.raises(state.StateError, match="integrity"):
        scan.scan_snapshot(**args)


def test_workspace_and_candidate_caps_are_not_exceeded(source, monkeypatch):
    scan, state = modules()
    args, _ = source
    monkeypatch.setattr(state, "MAX_FINDINGS", 1)
    first = scan.scan_snapshot(**args)
    assert first["attempted"] == 1 and first["stop_reason"] == "candidate_limit"
    second = scan.scan_snapshot(**args)
    assert second["attempted"] == 1
    monkeypatch.setattr(state, "MAX_FINDINGS", 100_000)
    monkeypatch.setattr(state, "MAX_WORKSPACE_BYTES", 160_000)
    result = scan.scan_snapshot(**args)
    retained = sum(p.stat().st_size for p in args["workspace"].rglob("*") if p.is_file())
    assert retained <= 160_000
    assert result["retained_bytes"] == retained


def test_one_writer_and_aliases_are_rejected(source):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args, record_limit=1)
    import fcntl

    with (args["workspace"] / ".lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(state.StateError, match="workspace_locked"):
            scan.scan_snapshot(**args)
    for bad in (args["repository"] / "output", args["receipt_path"].parent):
        with pytest.raises(state.StateError, match="unsafe_workspace"):
            scan.scan_snapshot(**(args | {"workspace": bad}))
    alias = args["workspace"].parent / "alias"
    alias.symlink_to(args["workspace"], target_is_directory=True)
    with pytest.raises(state.StateError, match="unsafe_workspace"):
        scan.scan_snapshot(**(args | {"workspace": alias}))


def test_offline_scan_records_missing_and_unsupported_without_false_zero(source, monkeypatch):
    scan, state = modules()
    args, bodies = source
    view = snapshot.open_snapshot(args["repository"], args["commit"], args["receipt_path"])
    # Missing loose blob after inventory acceptance, to exercise the actual batch protocol.
    entry = next(view.iter_entries())
    (args["repository"] / ".git" / "objects" / entry.oid[:2] / entry.oid[2:]).unlink()
    monkeypatch.setattr(scan, "open_snapshot", lambda *a: view)
    result = scan.scan_snapshot(**args)
    assert result["missing_object"] == 1 and result["parsed"] == 2
    assert result["scan_complete"] and result["unresolved"] == 1
    with state.open_workspace(args["workspace"]) as reader:
        assert next(reader.iter_outcomes())["outcome"] == "missing_object"


def test_batch_reader_closes_on_exception_and_rejects_nonmembers(source):
    args, bodies = source
    view = snapshot.open_snapshot(args["repository"], args["commit"], args["receipt_path"])
    with pytest.raises(RuntimeError):
        with view.blob_reader() as reader:
            assert reader.read_blob(next(view.iter_entries()), max_bytes=2_000_000) == bodies[0]
            raise RuntimeError("interrupt")
    with pytest.raises(snapshot.SnapshotError, match="reader_closed"):
        reader.read_blob(next(view.iter_entries()), max_bytes=2_000_000)
    with view.blob_reader() as reader:
        outsider = snapshot.Entry("wrong", "CVE-2026-1234", "a" * 40, 1)
        with pytest.raises(snapshot.SnapshotError, match="entry_not_in_snapshot"):
            reader.read_blob(outsider, max_bytes=2_000_000)
        assert reader.read_blob(next(view.iter_entries()), max_bytes=2_000_000) == bodies[0]


@pytest.mark.parametrize(
    "keyword,value",
    [("record_limit", 5001), ("byte_limit", 250000001), ("record_limit", True), ("byte_limit", -1)],
)
def test_invocation_limits_reject_above_ceiling_without_workspace(source, keyword, value):
    scan, state = modules()
    args, _ = source
    with pytest.raises(ValueError, match="invalid_scan_limit"):
        scan.scan_snapshot(**args, **{keyword: value})
    assert not args["workspace"].exists()


def test_preinventory_missing_object_preserves_existing_workspace(source):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args, record_limit=1)
    before = (args["workspace"] / "state.sqlite3").read_bytes()
    view = snapshot.open_snapshot(args["repository"], args["commit"], args["receipt_path"])
    entry = list(view.iter_entries())[1]
    (args["repository"] / ".git" / "objects" / entry.oid[:2] / entry.oid[2:]).unlink()
    with pytest.raises(snapshot.SnapshotError, match="invalid_tree_entry"):
        scan.scan_snapshot(**args)
    assert (args["workspace"] / "state.sqlite3").read_bytes() == before
    with state.open_workspace(args["workspace"]) as reader:
        assert reader.progress["attempted"] == 1
        assert not reader.progress["scan_complete"]


def test_atomic_capture_interruption_resumes(source, monkeypatch):
    scan, state = modules()
    args, _ = source
    original = os.replace

    def interrupted(src, dst):
        if str(dst).endswith(".json") and "captures" in str(dst):
            raise RuntimeError("interrupted before rename")
        return original(src, dst)

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", interrupted)
        with pytest.raises(RuntimeError, match="interrupted"):
            scan.scan_snapshot(**args)
    assert not list((args["workspace"] / "captures").iterdir())
    assert scan.scan_snapshot(**args)["scan_complete"]


def test_readonly_reader_rejects_uncommitted_capture_and_has_no_writer_methods(source):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args)
    with state.open_workspace(args["workspace"]) as reader:
        assert not hasattr(reader, "commit_record")
        assert not hasattr(reader, "stage")
        with pytest.raises(state.StateError, match="capture_not_committed"):
            reader.read_capture("a" * 64)


def test_amplified_findings_stop_with_no_unretained_progress(source, monkeypatch):
    scan, state = modules()
    args, _ = source
    original = scan.select_record

    def amplify(*a, **kw):
        result = original(*a, **kw)
        # Shared read-only reference data imitates the real Task2 container contract.
        reference = {"locator": "/containers/cna/references/0", "row": {"url": "x" * 2000}}
        base = result["findings"][0] | {"references": [reference]}
        result["findings"] = [base] * 100
        return result

    monkeypatch.setattr(scan, "select_record", amplify)
    monkeypatch.setattr(state, "MAX_WORKSPACE_BYTES", 200_000)
    result = scan.scan_snapshot(**args)
    assert result["stop_reason"] == "workspace_limit"
    assert result["attempted"] == result["candidate_findings"] == 0
    assert result["invocation_attempted"] == 1
    assert not list((args["workspace"] / "captures").iterdir())
    assert result["retained_bytes"] <= 200_000
    assert not (args["workspace"] / "pending.jsonl").exists()


@pytest.mark.parametrize("when", ["initialization", "transaction", "after_commit"])
def test_actual_process_exit_leaves_committed_prefix(source, when):
    import subprocess
    import sys

    scan, state = modules()
    args, _ = source
    source_args = {key: str(value) for key, value in args.items()}
    script = """
import os
from infrastructure_impact.reconciliation import state, scan
real_connect = state.sqlite3.connect
mode = WHEN
if mode in ('transaction', 'initialization'):
    def connect(*a, **kw):
        db = real_connect(*a, **kw)
        def crash(sql):
            if sql.startswith('INSERT INTO meta' if mode == 'initialization' else 'UPDATE meta'):
                os._exit(91)
        db.set_trace_callback(crash)
        return db
    state.sqlite3.connect = connect
else:
    original = state.Workspace.commit_record
    def commit(self, *a, **kw):
        original(self, *a, **kw)
        os._exit(91)
    state.Workspace.commit_record = commit
scan.scan_snapshot(**ARGS)
""".replace("WHEN", repr(when)).replace("ARGS", repr(source_args))
    process = subprocess.run([sys.executable, "-c", script], check=False)
    assert process.returncode == 91
    result = scan.scan_snapshot(**args)
    assert result["attempted"] == result["candidate_findings"] == 3
    with state.open_workspace(args["workspace"]) as reader:
        assert len(list(reader.iter_findings())) == 3


def test_batch_child_exits_on_early_stop_and_exception(source, monkeypatch):
    args, bodies = source
    view = snapshot.open_snapshot(args["repository"], args["commit"], args["receipt_path"])
    children = []
    original = snapshot.subprocess.Popen

    def track(*a, **kw):
        process = original(*a, **kw)
        children.append(process)
        return process

    monkeypatch.setattr(snapshot.subprocess, "Popen", track)
    with view.blob_reader() as reader:
        assert reader.read_blob(next(view.iter_entries()), max_bytes=2_000_000) == bodies[0]
    with pytest.raises(RuntimeError):
        with view.blob_reader():
            raise RuntimeError("interruption")
    assert len(children) == 2
    assert all(
        child.poll() is not None and child.stdin.closed and child.stdout.closed
        for child in children
    )


def test_batch_protocol_no_prefetch_and_missing_frame(source, monkeypatch):
    import io
    from types import SimpleNamespace

    args, bodies = source
    view = snapshot.open_snapshot(args["repository"], args["commit"], args["receipt_path"])
    first, second, _ = view.iter_entries()
    requests = []

    class Input(io.BytesIO):
        def write(self, value):
            requests.append(value)
            return super().write(value)

    response = (
        f"{first.oid} missing\n{second.oid} blob {second.size}\n".encode() + bodies[1] + b"\n"
    )

    @contextmanager
    def child(*args):
        yield SimpleNamespace(stdin=Input(), stdout=io.BytesIO(response))

    monkeypatch.setattr(snapshot, "_git", child)
    with view.blob_reader() as reader:
        assert requests == []
        with pytest.raises(snapshot.SnapshotError, match="git_object_unavailable"):
            reader.read_blob(first, max_bytes=2_000_000)
        assert reader.read_blob(second, max_bytes=2_000_000) == bodies[1]
    assert requests == [(first.oid + "\n").encode(), (second.oid + "\n").encode()]


@pytest.mark.parametrize("kind", ["unsupported", "invalid", "oversized"])
def test_explicit_unresolved_terminal_outcomes(source, monkeypatch, kind):
    scan, state = modules()
    args, bodies = source
    first_path = args["repository"] / "cves/2026/1xxx/CVE-2026-1234.json"
    if kind == "unsupported":
        first_path.write_bytes(bodies[0].replace(b'"5.1"', b'"99.0"'))
    elif kind == "invalid":
        first_path.write_bytes(b"{")
    else:
        first_path.write_bytes(b" " * 2_000_001)
    git(args["repository"], "add", ".")
    git(args["repository"], "commit", "-qm", "synthetic edge")
    # New synthetic official verification, then restore a strict network trap.
    args["commit"], _, _, _ = official(monkeypatch, snapshot, args["repository"])
    args["receipt_path"] = args["receipt_path"].with_name("second-receipt.json")
    snapshot.verify_snapshot(args["repository"], args["commit"], args["receipt_path"])

    def no_network(*args, **kwargs):
        raise AssertionError("network")

    monkeypatch.setattr(snapshot.http.client, "HTTPSConnection", no_network)
    result = scan.scan_snapshot(**args)
    assert result[kind] == 1 and result["parsed"] == 2
    assert result["scan_complete"] and result["unresolved"] == 1
    assert result["candidate_findings"] == 2


def test_sqlite_growth_limit_rolls_back_record_and_capture(source, monkeypatch):
    scan, state = modules()
    args, _ = source
    original = scan.select_record

    def large(*a, **kw):
        result = original(*a, **kw)
        result["findings"][0] = result["findings"][0] | {"literal": "x" * 40_000}
        return result

    monkeypatch.setattr(scan, "select_record", large)
    monkeypatch.setattr(state, "MAX_WORKSPACE_BYTES", 180_000)
    result = scan.scan_snapshot(**args)
    assert result["stop_reason"] == "workspace_limit"
    assert result["attempted"] == 0
    assert not list((args["workspace"] / "captures").iterdir())
    assert result["retained_bytes"] <= 180_000
    with state.open_workspace(args["workspace"]) as reader:
        assert list(reader.iter_findings()) == []


def test_resumed_workspace_counts_existing_report_and_staging_bytes(source, monkeypatch):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args, record_limit=1)
    (args["workspace"] / "report.txt").write_bytes(b"x" * 90_000)
    monkeypatch.setattr(state, "MAX_WORKSPACE_BYTES", 200_000)
    result = scan.scan_snapshot(**args)
    assert result["attempted"] == 1 and result["stop_reason"] == "workspace_limit"
    assert result["retained_bytes"] <= 200_000


def test_capture_and_database_hardlinks_are_rejected(source):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args, record_limit=1)
    os.link(args["workspace"] / "state.sqlite3", args["workspace"].parent / "alias.sqlite3")
    with pytest.raises(state.StateError, match="unsafe_workspace"):
        scan.scan_snapshot(**args)


def test_cumulative_byte_budget_stops_before_third_record(source):
    scan, _ = modules()
    args, bodies = source
    result = scan.scan_snapshot(**args, byte_limit=len(bodies[0]) + len(bodies[1]))
    assert result["attempted"] == 2 and result["remaining"] == 1
    assert result["consumed_bytes"] == result["invocation_consumed_bytes"] == 576
    assert result["stop_reason"] == "byte_limit"
    assert scan.scan_snapshot(**args)["attempted"] == 3


def test_global_finding_ceiling_stops_before_serialization(source, monkeypatch):
    scan, _ = modules()
    args, _ = source
    original = scan.select_record

    def too_many(*a, **kw):
        result = original(*a, **kw)
        result["findings"] *= 100_001
        return result

    monkeypatch.setattr(scan, "select_record", too_many)
    result = scan.scan_snapshot(**args)
    assert result["stop_reason"] == "candidate_limit"
    assert result["attempted"] == 0
    assert not list((args["workspace"] / "captures").iterdir())


def test_global_workspace_ceiling_includes_existing_files(source):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args, record_limit=0)
    # Sparse file charges logical retained bytes without allocating a gigabyte.
    with (args["workspace"] / "report").open("wb") as handle:
        handle.truncate(1_000_000_001)
    before = (args["workspace"] / "state.sqlite3").read_bytes()
    with pytest.raises(state.StorageLimit, match="workspace_limit"):
        scan.scan_snapshot(**args)
    assert (args["workspace"] / "state.sqlite3").read_bytes() == before


def test_output_alias_through_symlink_parent_is_rejected(source):
    scan, state = modules()
    args, _ = source
    real = args["workspace"].parent / "real"
    real.mkdir()
    alias = args["workspace"].parent / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(state.StateError, match="unsafe_workspace"):
        scan.scan_snapshot(**(args | {"workspace": alias / "child"}))


def test_outcome_codec_preserves_literal_metadata_with_compact_storage():
    _, state = modules()
    row = {
        "position": 0,
        "metadata": {"literal": "\u2603" * 20_000, "dates": {"datePublished": None}},
    }
    encoded, length, sha = state._encode_outcome(row)
    assert len(encoded) < length // 10
    assert state._decode_outcome(encoded, length, sha) == row


@pytest.mark.parametrize(
    "damage", ["truncated", "trailing", "overlong", "hash", "declared_length", "invalid_size"]
)
def test_outcome_decompression_bounds_and_integrity(damage):
    import zlib

    _, state = modules()
    encoded = zlib.compress(b'{"position":0}')
    length = 14
    sha = hashlib.sha256(b'{"position":0}').hexdigest()
    if damage == "truncated":
        encoded = encoded[:-1]
    elif damage == "trailing":
        encoded += b"extra"
    elif damage == "overlong":
        encoded = zlib.compress(b"x" * 2_016_385)
    elif damage == "hash":
        sha = "a" * 64
    elif damage == "declared_length":
        length = 15
    else:
        length = 48_016_385
    with pytest.raises(state.StateError, match="state_integrity"):
        state._decode_outcome(encoded, length, sha)


def test_compact_outcome_digests_preserve_canonical_hashes(source):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args, record_limit=1)
    with state.open_workspace(args["workspace"]) as reader:
        row = next(reader.iter_outcomes())
        finding = next(reader.iter_findings())["finding"]

    def canonical(value):
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()

    expected = hashlib.sha256(canonical(row))
    combined = expected.copy()
    combined.update(hashlib.sha256(canonical(finding)).hexdigest().encode())
    with sqlite3.connect(args["workspace"] / "state.sqlite3") as db:
        raw_sha, retained_sha = db.execute("SELECT raw_sha256,sha256 FROM outcomes").fetchone()
    assert raw_sha == expected.digest()
    assert retained_sha == combined.digest()


def test_interrupted_initialization_reserves_existing_files_before_creation(source, monkeypatch):
    scan, state = modules()
    args, _ = source
    scan.scan_snapshot(**args, record_limit=0)
    # A matching identity can survive a crash before the staged DB is published.
    (args["workspace"] / "state.sqlite3").unlink()
    (args["workspace"] / "report.txt").write_bytes(b"x" * 190_000)
    monkeypatch.setattr(state, "MAX_WORKSPACE_BYTES", 200_000)
    before = sum(path.stat().st_size for path in args["workspace"].rglob("*") if path.is_file())
    with pytest.raises(state.StorageLimit, match="workspace_limit"):
        scan.scan_snapshot(**args)
    after = sum(path.stat().st_size for path in args["workspace"].rglob("*") if path.is_file())
    assert after == before <= 200_000
    assert not (args["workspace"] / "state.sqlite3").exists()
    assert not (args["workspace"] / "pending.sqlite3").exists()


@pytest.mark.parametrize("token,count", [(b"1e9", 160_000), (b"1e15", 390_000)])
def test_canonical_numeric_metadata_expansion_is_retained_without_false_quota_stop(
    source, monkeypatch, token, count
):
    scan, state = modules()
    args, bodies = source
    dates = b"[" + b",".join([token] * count) + b"]"
    raw = bodies[0].replace(b'"2026-02-03T00:00:00Z"', dates)
    assert len(raw) < 2_000_000
    path = args["repository"] / "cves/2026/1xxx/CVE-2026-1234.json"
    path.write_bytes(raw)
    git(args["repository"], "add", ".")
    git(args["repository"], "commit", "-qm", "synthetic expanded date metadata")
    args["commit"], _, _, _ = official(monkeypatch, snapshot, args["repository"])
    args["receipt_path"] = args["receipt_path"].with_name("expanded-metadata-receipt.json")
    snapshot.verify_snapshot(args["repository"], args["commit"], args["receipt_path"])

    def no_network(*args, **kwargs):
        raise AssertionError("network")

    monkeypatch.setattr(snapshot.http.client, "HTTPSConnection", no_network)
    result = scan.scan_snapshot(**args)
    assert result["scan_complete"] and result["parsed"] == 3
    assert result["candidate_findings"] == 3 and result["stop_reason"] == "complete"
    with state.open_workspace(args["workspace"]) as reader:
        row = next(reader.iter_outcomes())
        assert row["metadata"]["date_window_state"] == "unknown"
        assert row["metadata"]["dates"]["datePublished"] == [float(token)] * count
        assert reader.read_capture(row["capture_sha256"]) == raw
    resumed = scan.scan_snapshot(**args)
    assert resumed["scan_complete"] and resumed["invocation_attempted"] == 0


def test_initialization_counts_existing_lock_before_identity_write(source, monkeypatch):
    scan, state = modules()
    args, _ = source
    args["workspace"].mkdir()
    (args["workspace"] / ".lock").write_bytes(b"x" * 190_000)
    monkeypatch.setattr(state, "MAX_WORKSPACE_BYTES", 200_000)
    with pytest.raises(state.StorageLimit, match="workspace_limit"):
        scan.scan_snapshot(**args)
    assert not (args["workspace"] / "identity.json").exists()
    assert (
        sum(path.stat().st_size for path in args["workspace"].rglob("*") if path.is_file())
        == 190_000
    )


def test_internal_encoding_guard_is_not_a_resumable_workspace_quota(monkeypatch):
    _, state = modules()
    monkeypatch.setattr(state, "_MAX_OUTCOME_BYTES", 100)
    with pytest.raises(state.StateError, match="outcome_encoding_limit") as failure:
        state._encode_outcome({"literal": "x" * 101})
    assert not isinstance(failure.value, state.StorageLimit)


def test_expanded_codec_declared_ceiling_is_checked_before_decompression(monkeypatch):
    import zlib

    _, state = modules()
    encoded = zlib.compress(b"{}")

    def forbidden():
        raise AssertionError("decoder allocated before declared-size validation")

    monkeypatch.setattr(state.zlib, "decompressobj", forbidden)
    with pytest.raises(state.StateError, match="state_integrity"):
        state._decode_outcome(encoded, 48_016_385, hashlib.sha256(b"{}").hexdigest())


def test_capture_codec_roundtrip_beneficial_and_legacy_bytes():
    _, state = modules()
    raw = b'{"literal":"' + b"x" * 10_000 + b'"}'
    sha = hashlib.sha256(raw).hexdigest()
    stored = state._encode_capture(raw)
    assert stored.startswith(b"\x89CVEcap\n\x01")
    assert len(stored) < len(raw)
    assert state._decode_capture(stored, sha) == raw
    assert state._decode_capture(raw, sha) == raw
    incompressible = bytes(range(256))
    assert state._encode_capture(incompressible) == incompressible


def test_new_capture_storage_and_legacy_reader_preserve_exact_source(source):
    scan, state = modules()
    args, bodies = source
    scan.scan_snapshot(**args)
    before = (args["workspace"] / "state.sqlite3").read_bytes()
    with state.open_workspace(args["workspace"]) as reader:
        for raw in bodies:
            sha = hashlib.sha256(raw).hexdigest()
            stored = (args["workspace"] / "captures" / (sha + ".json")).read_bytes()
            assert stored.startswith(b"\x89CVEcap\n\x01") and len(stored) < len(raw)
            assert reader.read_capture(sha) == raw
    # Legacy representation remains supported without changing committed state.
    for raw in bodies:
        (args["workspace"] / "captures" / (hashlib.sha256(raw).hexdigest() + ".json")).write_bytes(
            raw
        )
    with state.open_workspace(args["workspace"]) as reader:
        assert reader.read_capture(hashlib.sha256(bodies[0]).hexdigest()) == bodies[0]
    assert (args["workspace"] / "state.sqlite3").read_bytes() == before


@pytest.mark.parametrize(
    "damage", ["truncated", "trailing", "corrupt", "version", "hash", "length", "bomb"]
)
def test_capture_frame_integrity_and_raw_ceiling(damage, monkeypatch):
    import zlib

    _, state = modules()
    raw = b"x" * 10_000
    sha = hashlib.sha256(raw).hexdigest()
    stored = state._encode_capture(raw)
    if damage == "truncated":
        stored = stored[:-1]
    elif damage == "trailing":
        stored += b"x"
    elif damage == "corrupt":
        stored = stored[:-1] + bytes([stored[-1] ^ 1])
    elif damage == "version":
        stored = stored[:8] + b"\x02" + stored[9:]
    elif damage == "hash":
        stored = stored[:13] + b"\x00" * 32 + stored[45:]
    elif damage == "length":
        stored = stored[:9] + (2_000_001).to_bytes(4, "big") + stored[13:]

        def forbidden():
            raise AssertionError("capture decoder allocated before size check")

        monkeypatch.setattr(state.zlib, "decompressobj", forbidden)
    else:
        stored = (
            stored[:9] + (1).to_bytes(4, "big") + stored[13:45] + zlib.compress(b"x" * 2_000_001)
        )
    with pytest.raises(state.StateError, match="capture_integrity"):
        state._decode_capture(stored, sha)


def legacy_workspace(source):
    scan, state = modules()
    args, bodies = source
    scan.scan_snapshot(**args)
    for raw in bodies:
        (args["workspace"] / "captures" / (hashlib.sha256(raw).hexdigest() + ".json")).write_bytes(
            raw
        )
    return args, bodies, state


def test_compaction_roundtrip_limits_and_committed_state_unchanged(source):
    args, bodies, state = legacy_workspace(source)
    files = {
        name: (args["workspace"] / name).read_bytes() for name in ("state.sqlite3", "identity.json")
    }
    result = state.compact_workspace_captures(args["workspace"], byte_limit=287)
    assert result["attempted"] == result["converted"] == 0
    assert result["remaining"] == 3 and result["stop_reason"] == "byte_limit"
    result = state.compact_workspace_captures(args["workspace"], record_limit=1, byte_limit=288)
    assert result["attempted"] == result["converted"] == 1
    assert result["decoded_bytes"] == 288 and result["remaining"] == 2
    assert result["stop_reason"] == "record_limit" and result["bytes_saved"] > 0
    result = state.compact_workspace_captures(args["workspace"], record_limit=1)
    assert result["converted"] == 1 and result["skipped"] == 1 and result["remaining"] == 1
    result = state.compact_workspace_captures(args["workspace"])
    assert result["converted"] == 1 and result["skipped"] == 2 and result["remaining"] == 0
    repeated = state.compact_workspace_captures(args["workspace"])
    assert repeated["attempted"] == repeated["converted"] == 0
    assert repeated["skipped"] == 3 and repeated["stop_reason"] == "complete"
    assert repeated["bytes_before"] == repeated["bytes_after"]
    for name, original in files.items():
        assert (args["workspace"] / name).read_bytes() == original
    with state.open_workspace(args["workspace"]) as reader:
        for raw in bodies:
            assert reader.read_capture(hashlib.sha256(raw).hexdigest()) == raw


@pytest.mark.parametrize("keyword,value", [("record_limit", 0), ("byte_limit", 0)])
def test_compaction_zero_limits_do_not_convert(source, keyword, value):
    args, _, state = legacy_workspace(source)
    before = {p.name: p.read_bytes() for p in (args["workspace"] / "captures").iterdir()}
    result = state.compact_workspace_captures(args["workspace"], **{keyword: value})
    assert result["attempted"] == result["converted"] == 0 and result["remaining"] == 3
    assert {p.name: p.read_bytes() for p in (args["workspace"] / "captures").iterdir()} == before


@pytest.mark.parametrize(
    "keyword,value",
    [("record_limit", 5001), ("byte_limit", 250000001), ("record_limit", True), ("byte_limit", -1)],
)
def test_compaction_rejects_invalid_limits_without_writes(source, keyword, value):
    args, _, state = legacy_workspace(source)
    with pytest.raises(ValueError, match="invalid_compaction_limit"):
        state.compact_workspace_captures(args["workspace"], **{keyword: value})


def test_compaction_quota_rejects_before_replacement(source, monkeypatch):
    args, _, state = legacy_workspace(source)
    before = {p.name: p.read_bytes() for p in (args["workspace"] / "captures").iterdir()}
    total = sum(p.stat().st_size for p in args["workspace"].rglob("*") if p.is_file())
    monkeypatch.setattr(state, "MAX_WORKSPACE_BYTES", total)
    result = state.compact_workspace_captures(args["workspace"])
    assert result["attempted"] == 1 and result["converted"] == 0
    assert result["remaining"] == 3 and result["stop_reason"] == "workspace_limit"
    assert result["bytes_before"] == result["bytes_after"] == total
    assert {p.name: p.read_bytes() for p in (args["workspace"] / "captures").iterdir()} == before
    assert not list(args["workspace"].glob("pending.compact-*"))


@pytest.mark.parametrize("holder", ["report", "writer"])
def test_compaction_excludes_other_workspace_readers_and_writers(source, holder):
    args, _, state = legacy_workspace(source)
    if holder == "report":
        context = state.open_workspace(args["workspace"])
    else:
        context = state._lock(args["workspace"], write=True)
    with context:
        with pytest.raises(state.StateError, match="workspace_locked"):
            state.compact_workspace_captures(args["workspace"])


@pytest.mark.parametrize("when", ["before", "after"])
def test_compaction_process_exit_before_and_after_rename_is_idempotent(source, when):
    import subprocess
    import sys

    args, bodies, state = legacy_workspace(source)
    before = (args["workspace"] / "state.sqlite3").read_bytes()
    script = """
import os
from pathlib import Path
from infrastructure_impact.reconciliation import state
original = os.replace
def interrupt(src, dst):
    if Path(dst).parent.name == 'captures':
        if WHEN == 'after':
            original(src, dst)
        os._exit(91)
    return original(src, dst)
state.os.replace = interrupt
state.compact_workspace_captures(Path(WORKSPACE))
""".replace("WHEN", repr(when)).replace("WORKSPACE", repr(str(args["workspace"])))
    process = subprocess.run([sys.executable, "-c", script], check=False)
    assert process.returncode == 91
    result = state.compact_workspace_captures(args["workspace"])
    assert result["remaining"] == 0
    assert (args["workspace"] / "state.sqlite3").read_bytes() == before
    with state.open_workspace(args["workspace"]) as reader:
        for raw in bodies:
            assert reader.read_capture(hashlib.sha256(raw).hexdigest()) == raw
    assert not list(args["workspace"].glob("pending.compact-*"))


def test_compaction_rejects_corrupt_already_framed_and_foreign_files(source):
    args, _, state = legacy_workspace(source)
    state.compact_workspace_captures(args["workspace"], record_limit=1)
    framed = next(
        p
        for p in (args["workspace"] / "captures").iterdir()
        if p.read_bytes().startswith(b"\x89CVEcap\n")
    )
    original = framed.read_bytes()
    framed.write_bytes(original[:-1])
    with pytest.raises(state.StateError, match="integrity"):
        state.compact_workspace_captures(args["workspace"])
    framed.write_bytes(original)
    foreign = args["workspace"] / "captures" / ("a" * 64 + ".json")
    foreign.write_bytes(b"foreign")
    with pytest.raises(state.StateError, match="capture_integrity"):
        state.compact_workspace_captures(args["workspace"])


def test_compaction_forced_framing_keeps_nonbeneficial_source_bytes():
    _, state = modules()
    raw = bytes(range(256))
    framed = state._encode_capture(raw, force=True)
    assert len(framed) > len(raw)
    assert state._decode_capture(framed, hashlib.sha256(raw).hexdigest()) == raw


def test_nonbeneficial_compaction_advances_with_limit_one_and_reports_growth(source, monkeypatch):
    args, _, state = legacy_workspace(source)
    original = state.zlib.compress
    # Valid stored DEFLATE blocks deliberately provide no compression benefit.
    monkeypatch.setattr(state.zlib, "compress", lambda raw: original(raw, level=0))
    for remaining in (2, 1, 0):
        result = state.compact_workspace_captures(args["workspace"], record_limit=1)
        assert result["converted"] == 1 and result["remaining"] == remaining
        assert result["bytes_saved"] < 0
    assert state.compact_workspace_captures(args["workspace"])["attempted"] == 0


def test_capture_frame_allows_storage_overhead_but_never_overlarge_source():
    _, state = modules()
    raw = os.urandom(2_000_000)
    frame = state._encode_capture(raw, force=True)
    assert len(frame) > 2_000_000
    assert state._decode_capture(frame, hashlib.sha256(raw).hexdigest()) == raw
    with pytest.raises(state.StateError, match="capture_integrity"):
        state._encode_capture(raw + b"x", force=True)


def test_compaction_recovers_only_owned_partial_staging(source):
    args, bodies, state = legacy_workspace(source)
    stage = args["workspace"] / (
        "pending.compact-" + hashlib.sha256(bodies[0]).hexdigest() + ".capture"
    )
    stage.write_bytes(b"partial frame")
    result = state.compact_workspace_captures(args["workspace"], record_limit=0)
    assert result["converted"] == 0 and not stage.exists()
    foreign = args["workspace"] / ("pending.compact-" + "a" * 64 + ".capture")
    foreign.write_bytes(b"foreign")
    with pytest.raises(state.StateError, match="unsafe_compaction_staging"):
        state.compact_workspace_captures(args["workspace"])
    assert foreign.read_bytes() == b"foreign"


def test_active_compaction_excludes_scan_and_report(source, monkeypatch):
    args, _, state = legacy_workspace(source)
    scan, _ = modules()
    original = state._write_new
    checked = []

    def while_locked(path, raw):
        if path.name.startswith("pending.compact-"):
            with pytest.raises(state.StateError, match="workspace_locked"):
                scan.scan_snapshot(**args)
            with pytest.raises(state.StateError, match="workspace_locked"):
                with state.open_workspace(args["workspace"]):
                    pass
            checked.append(True)
        return original(path, raw)

    monkeypatch.setattr(state, "_write_new", while_locked)
    assert state.compact_workspace_captures(args["workspace"], record_limit=1)["converted"] == 1
    assert checked == [True]


def test_compaction_rejects_capture_alias_and_zero_limit_corruption(source):
    args, _, state = legacy_workspace(source)
    state.compact_workspace_captures(args["workspace"], record_limit=1)
    framed = next(
        p
        for p in (args["workspace"] / "captures").iterdir()
        if p.read_bytes().startswith(b"\x89CVEcap\n")
    )
    original = framed.read_bytes()
    framed.write_bytes(original + b"trailing")
    with pytest.raises(state.StateError, match="integrity"):
        state.compact_workspace_captures(args["workspace"], record_limit=0)
    framed.write_bytes(original)
    os.link(framed, args["workspace"].parent / "capture-alias")
    with pytest.raises(state.StateError, match="unsafe_workspace"):
        state.compact_workspace_captures(args["workspace"])


def test_capture_file_reader_rejects_aliases_and_oversized_storage(tmp_path):
    _, state = modules()
    raw = b'{"literal":"x"}'
    sha = hashlib.sha256(raw).hexdigest()
    original = tmp_path / "source"
    original.write_bytes(raw)
    alias = tmp_path / "alias"
    alias.symlink_to(original)
    with pytest.raises(state.StateError, match="unsafe_workspace"):
        state._read_capture_file(alias, sha)
    oversized = tmp_path / "oversized"
    with oversized.open("wb") as handle:
        handle.truncate(2_020_110)
    with pytest.raises(state.StateError, match="capture_integrity"):
        state._read_capture_file(oversized, sha)


def test_capture_file_read_request_remains_bounded(tmp_path, monkeypatch):
    from pathlib import Path

    _, state = modules()
    raw = b'{"literal":"x"}'
    path = tmp_path / "capture"
    path.write_bytes(raw)
    original = Path.open

    @contextmanager
    def bounded_open(self, *args, **kwargs):
        with original(self, *args, **kwargs) as handle:

            class Reader:
                def read(self, size=-1):
                    assert 0 <= size <= 2_020_110, "unbounded capture read"
                    return handle.read(size)

            yield Reader()

    monkeypatch.setattr(Path, "open", bounded_open)
    assert state._read_capture_file(path, hashlib.sha256(raw).hexdigest()) == raw
