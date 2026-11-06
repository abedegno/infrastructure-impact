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
        length = 2_016_385
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
