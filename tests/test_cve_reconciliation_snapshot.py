"""Synthetic snapshot trust boundaries; no network or real CVE captures."""

import hashlib
import importlib
import io
import json
import os
import subprocess
from dataclasses import FrozenInstanceError

import pytest

PATH = "cves/2026/1xxx/CVE-2026-1234.json"
BODY = b'{"cveMetadata":{"cveId":"CVE-2026-1234"}}\n'


def git(repo, *args, input=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_AUTHOR_NAME="Synthetic",
        GIT_AUTHOR_EMAIL="synthetic@example.invalid",
        GIT_COMMITTER_NAME="Synthetic",
        GIT_COMMITTER_EMAIL="synthetic@example.invalid",
    )
    return (
        subprocess.check_output(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args], input=input, env=env
        )
        .strip()
        .decode()
    )


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "input"
    path.mkdir()
    git(path, "init", "-q")
    file = path / PATH
    file.parent.mkdir(parents=True)
    file.write_bytes(BODY)
    (path / "README.md").write_text("Authored fixture\n")
    git(path, "add", ".")
    git(path, "commit", "-qm", "synthetic fixture")
    return path


@pytest.fixture
def snapshot():
    return importlib.import_module("infrastructure_impact.reconciliation.snapshot")


class Response(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(body)
        self.status = status


def official(monkeypatch, snapshot, repo, *, payload=None, status=200, raw=None):
    commit = git(repo, "rev-parse", "HEAD")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    payload = payload or {
        "sha": commit,
        "url": f"https://api.github.com/repos/CVEProject/cvelistV5/commits/{commit}",
        "commit": {
            "tree": {
                "sha": tree,
                "url": f"https://api.github.com/repos/CVEProject/cvelistV5/git/trees/{tree}",
            }
        },
    }
    raw = raw if raw is not None else json.dumps(payload).encode()
    calls = []

    class Connection:
        def __init__(self, host, *, timeout):
            assert host == "api.github.com"
            assert timeout == 25

        def request(self, method, route, headers):
            calls.append((method, route, headers))
            assert method == "GET"
            assert route == f"/repos/CVEProject/cvelistV5/commits/{commit}"
            assert not any(key.lower() == "authorization" for key in headers)

        def getresponse(self):
            return Response(raw, status)

        def close(self):
            pass

    monkeypatch.setattr(snapshot.http.client, "HTTPSConnection", Connection)
    return commit, tree, raw, calls


def verified(monkeypatch, snapshot, repo, tmp_path):
    commit, tree, raw, calls = official(monkeypatch, snapshot, repo)
    receipt = tmp_path / "output" / "receipt.json"
    receipt.parent.mkdir(exist_ok=True)
    result = snapshot.verify_snapshot(repo, commit, receipt)
    return commit, tree, raw, calls, receipt, result


def test_receipt_binds_official_commit_tree_and_raw_hash(monkeypatch, snapshot, repo, tmp_path):
    commit, tree, raw, calls, receipt, result = verified(monkeypatch, snapshot, repo, tmp_path)
    assert result == json.loads(receipt.read_bytes())
    assert result["format_version"] == 1
    assert result["commit"] == commit
    assert result["tree"] == tree
    assert result["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt.with_name(receipt.name + ".raw.json").read_bytes() == raw
    assert len(calls) == 1
    view = snapshot.open_snapshot(repo, commit, receipt)
    assert (view.commit, view.tree) == (commit, tree)
    assert view.receipt_sha256 == hashlib.sha256(receipt.read_bytes()).hexdigest()
    (entry,) = view.iter_entries()
    assert (entry.path, entry.cve_id, entry.size) == (PATH, "CVE-2026-1234", len(BODY))
    assert (
        entry.source_url(commit)
        == f"https://raw.githubusercontent.com/CVEProject/cvelistV5/{commit}/{PATH}"
    )
    assert view.read_blob(entry, max_bytes=len(BODY)) == BODY
    assert view.inventory_entries == 5
    assert view.inventory_bytes > len(PATH)
    with pytest.raises(FrozenInstanceError):
        entry.size = 0
    with pytest.raises(FrozenInstanceError):
        view.commit = "a" * 40
    receipt.with_name(receipt.name + ".raw.json").write_bytes(raw + b" ")
    with pytest.raises(snapshot.SnapshotError, match="raw_hash_mismatch"):
        snapshot.open_snapshot(repo, commit, receipt)


@pytest.mark.parametrize(
    "change",
    [
        "redirect",
        "host",
        "sha",
        "tree",
        "size",
        "bad_time",
        "future_time",
        "wrong_receipt_commit",
        "ref",
        "short_sha",
    ],
)
def test_verification_rejects_redirect_host_sha_tree_size_and_bad_time(
    monkeypatch, snapshot, repo, tmp_path, change
):
    commit, tree, raw, _ = official(monkeypatch, snapshot, repo)
    payload = json.loads(raw)
    receipt = tmp_path / "receipt.json"
    if change in {"bad_time", "future_time", "wrong_receipt_commit"}:
        result = snapshot.verify_snapshot(repo, commit, receipt)
        if change == "wrong_receipt_commit":
            result["commit"] = "a" * 40
        else:
            result["retrieved_at"] = "tomorrow" if change == "bad_time" else "2999-01-01T00:00:00Z"
        receipt.write_text(json.dumps(result))
        with pytest.raises(snapshot.SnapshotError):
            snapshot.open_snapshot(repo, commit, receipt)
        return
    if change == "host":
        payload["url"] = f"https://evil.invalid/commits/{commit}"
    if change == "sha":
        payload["sha"] = "a" * 40
    if change == "tree":
        payload["commit"]["tree"]["sha"] = "b" * 40
    official(
        monkeypatch,
        snapshot,
        repo,
        payload=payload,
        status=302 if change == "redirect" else 200,
        raw=b" " * 1_000_001 if change == "size" else None,
    )
    supplied = "HEAD" if change == "ref" else commit[:39] if change == "short_sha" else commit
    with pytest.raises(snapshot.SnapshotError):
        snapshot.verify_snapshot(repo, supplied, receipt)
    assert not receipt.exists()


def test_tree_and_blob_reads_ignore_dirty_worktree(monkeypatch, snapshot, repo, tmp_path):
    commit, _, _, _, receipt, _ = verified(monkeypatch, snapshot, repo, tmp_path)
    (repo / PATH).write_bytes(b"dirty content")
    extra = repo / "cves/2026/9xxx/CVE-2026-9999.json"
    extra.parent.mkdir(parents=True)
    extra.write_text("{}")
    view = snapshot.open_snapshot(repo, commit, receipt)
    (entry,) = view.iter_entries()
    assert entry.path == PATH
    assert view.read_blob(entry, max_bytes=len(BODY)) == BODY
    with pytest.raises(snapshot.SnapshotError, match="blob_byte_limit"):
        view.read_blob(entry, max_bytes=len(BODY) - 1)
    with pytest.raises(snapshot.SnapshotError):
        view.read_blob(entry, max_bytes=2_000_001)


def test_missing_blob_never_fetches(monkeypatch, snapshot, repo, tmp_path):
    commit, _, _, _, receipt, _ = verified(monkeypatch, snapshot, repo, tmp_path)
    view = snapshot.open_snapshot(repo, commit, receipt)
    (entry,) = view.iter_entries()
    (repo / ".git/objects" / entry.oid[:2] / entry.oid[2:]).unlink()
    git(repo, "config", "remote.origin.url", "https://must-not-fetch.invalid/repo")
    git(repo, "config", "remote.origin.promisor", "true")
    observed = []
    original = subprocess.Popen

    def observe(*args, **kwargs):
        observed.append(kwargs["env"])
        return original(*args, **kwargs)

    monkeypatch.setattr(snapshot.subprocess, "Popen", observe)
    with pytest.raises(snapshot.SnapshotError) as caught:
        view.read_blob(entry, max_bytes=len(BODY))
    assert str(caught.value) == "git_object_unavailable"
    assert observed
    assert all(
        env["GIT_NO_LAZY_FETCH"] == "1"
        and env["GIT_NO_REPLACE_OBJECTS"] == "1"
        and env["GIT_OPTIONAL_LOCKS"] == "0"
        for env in observed
    )


def test_real_replacement_objects_are_ignored(monkeypatch, snapshot, repo, tmp_path):
    commit, _, _, _, receipt, _ = verified(monkeypatch, snapshot, repo, tmp_path)
    blob = git(repo, "rev-parse", f"HEAD:{PATH}")
    replacement = git(repo, "hash-object", "-w", "--stdin", input=b"replaced")
    git(repo, "replace", blob, replacement)
    (repo / PATH).write_bytes(b"changed tree")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "second synthetic tree")
    second = git(repo, "rev-parse", "HEAD")
    git(repo, "replace", commit, second)
    view = snapshot.open_snapshot(repo, commit, receipt)
    (entry,) = view.iter_entries()
    assert entry.oid == blob
    assert view.read_blob(entry, max_bytes=len(BODY)) == BODY


@pytest.mark.parametrize(
    "change",
    [
        "symlink",
        "executable",
        "bucket",
        "year",
        "duplicate",
        "newline",
        "unicode",
        "entry_limit",
        "inventory_limit",
    ],
)
def test_tree_limits_paths_modes_and_duplicate_ids(monkeypatch, snapshot, repo, tmp_path, change):
    if change in {"entry_limit", "inventory_limit"}:
        commit, _, _, _, receipt, _ = verified(monkeypatch, snapshot, repo, tmp_path)
        key = "MAX_TREE_ENTRIES" if change == "entry_limit" else "MAX_INVENTORY_BYTES"
        monkeypatch.setattr(snapshot, key, 1)
    else:
        original = repo / PATH
        if change == "symlink":
            original.unlink()
            original.symlink_to("/synthetic/never-read")
        elif change == "executable":
            original.chmod(0o755)
        else:
            bad = {
                "bucket": "cves/2026/2xxx/CVE-2026-1234.json",
                "year": "cves/2025/1xxx/CVE-2026-1234.json",
                "duplicate": "cves/2026/2xxx/CVE-2026-1234.json",
                "newline": "cves/2026/1xxx/CVE-2026-1234\n.json",
                "unicode": "cves/２０２６/1xxx/CVE-２０２６-1234.json",
            }[change]
            target = repo / bad
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(BODY)
            if change != "duplicate":
                original.unlink()
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "malformed synthetic record")
        commit, _, _, _ = official(monkeypatch, snapshot, repo)
        receipt = tmp_path / "receipt.json"
        snapshot.verify_snapshot(repo, commit, receipt)
    with pytest.raises(snapshot.SnapshotError):
        snapshot.open_snapshot(repo, commit, receipt)


def test_output_cannot_alias_repository_or_existing_inputs(monkeypatch, snapshot, repo, tmp_path):
    commit, _, _, _ = official(monkeypatch, snapshot, repo)
    with pytest.raises(snapshot.SnapshotError):
        snapshot.verify_snapshot(repo, commit, repo / "receipt.json")
    receipt = tmp_path / "receipt.json"
    receipt.symlink_to(repo / PATH)
    with pytest.raises(snapshot.SnapshotError):
        snapshot.verify_snapshot(repo, commit, receipt)
    assert (repo / PATH).read_bytes() == BODY


def test_exact_inventory_bounds_and_sorted_historical_entries(
    monkeypatch, snapshot, repo, tmp_path
):
    old = repo / "cves/1999/0xxx/CVE-1999-0001.json"
    old.parent.mkdir(parents=True)
    old.write_bytes(b"{}")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "historical synthetic record")
    commit, _, _, calls, receipt, _ = verified(monkeypatch, snapshot, repo, tmp_path)
    view = snapshot.open_snapshot(repo, commit, receipt)
    assert [entry.cve_id for entry in view.iter_entries()] == ["CVE-1999-0001", "CVE-2026-1234"]
    assert view.inventory_entries == 8
    monkeypatch.setattr(snapshot, "MAX_TREE_ENTRIES", 8)
    monkeypatch.setattr(snapshot, "MAX_INVENTORY_BYTES", view.inventory_bytes)
    assert list(snapshot.open_snapshot(repo, commit, receipt).iter_entries()) == list(
        view.iter_entries()
    )
    assert len(calls) == 1  # All opening and inventory validation stayed offline.
    monkeypatch.setattr(snapshot, "MAX_INVENTORY_BYTES", view.inventory_bytes - 1)
    with pytest.raises(snapshot.SnapshotError, match="inventory_byte_limit"):
        snapshot.open_snapshot(repo, commit, receipt)


def test_foreign_entry_and_invalid_limits_are_rejected(monkeypatch, snapshot, repo, tmp_path):
    from dataclasses import replace

    commit, _, _, _, receipt, _ = verified(monkeypatch, snapshot, repo, tmp_path)
    view = snapshot.open_snapshot(repo, commit, receipt)
    (entry,) = view.iter_entries()
    with pytest.raises(snapshot.SnapshotError, match="entry_not_in_snapshot"):
        view.read_blob(replace(entry, oid="a" * 40), max_bytes=2_000_000)
    for limit in (True, -1, 2_000_001, 1.5):
        with pytest.raises(snapshot.SnapshotError, match="invalid_blob_limit"):
            view.read_blob(entry, max_bytes=limit)


def test_git_failures_do_not_disclose_input_paths(monkeypatch, snapshot, tmp_path):
    secret_path = tmp_path / "source-name-must-not-leak"
    with pytest.raises(snapshot.SnapshotError) as caught:
        snapshot.verify_snapshot(secret_path, "a" * 40, tmp_path / "receipt.json")
    assert str(caught.value) == "unsafe_receipt_path"
    assert "source-name" not in str(caught.value)


def test_receipt_aliases_and_overwrites_are_rejected(monkeypatch, snapshot, repo, tmp_path):
    commit, _, raw, calls, receipt, _ = verified(monkeypatch, snapshot, repo, tmp_path)
    original = receipt.read_bytes()
    with pytest.raises(snapshot.SnapshotError, match="receipt_already_exists"):
        snapshot.verify_snapshot(repo, commit, receipt)
    assert receipt.read_bytes() == original
    assert len(calls) == 1
    sidecar = receipt.with_name(receipt.name + ".raw.json")
    sidecar.unlink()
    sidecar.symlink_to(repo / PATH)
    with pytest.raises(snapshot.SnapshotError, match="unsafe_receipt_path"):
        snapshot.open_snapshot(repo, commit, receipt)
    sidecar.unlink()
    sidecar.write_bytes(raw)
    alias = tmp_path / "receipt-alias.json"
    alias.hardlink_to(receipt)
    with pytest.raises(snapshot.SnapshotError, match="unsafe_receipt_path"):
        snapshot.open_snapshot(repo, commit, receipt)


def test_noncanonical_large_identifier_fails_with_safe_code(monkeypatch, snapshot, repo, tmp_path):
    # Construct malformed tree bytes without creating an impossible filesystem filename.
    tree = b"100644 blob " + b"a" * 40 + b" 2\tcves/2026/1xxx/CVE-2026-" + b"1" * 5000 + b".json\0"
    from contextlib import contextmanager

    @contextmanager
    def fake_git(*args):
        class Process:
            stdin = io.BytesIO()
            stdout = io.BytesIO(tree)

        yield Process()

    monkeypatch.setattr(snapshot, "_git", fake_git)
    with pytest.raises(snapshot.SnapshotError, match="invalid_record_path"):
        snapshot._inventory(repo, "a" * 40)


def test_exact_http_and_record_byte_ceilings(monkeypatch, snapshot, repo, tmp_path):
    (repo / PATH).write_bytes(b"{}" + b" " * 1_999_998)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "exact synthetic record ceiling")
    commit, _, raw, _ = official(monkeypatch, snapshot, repo)
    bounded = raw + b" " * (1_000_000 - len(raw))
    official(monkeypatch, snapshot, repo, raw=bounded)
    receipt = tmp_path / "receipt.json"
    snapshot.verify_snapshot(repo, commit, receipt)
    assert receipt.with_name(receipt.name + ".raw.json").stat().st_size == 1_000_000
    view = snapshot.open_snapshot(repo, commit, receipt)
    (entry,) = view.iter_entries()
    assert len(view.read_blob(entry, max_bytes=2_000_000)) == 2_000_000


def test_oversize_record_rejects_before_starting_reader(monkeypatch, snapshot, repo, tmp_path):
    (repo / PATH).write_bytes(b" " * 2_000_001)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "oversize synthetic record")
    commit, _, _, _, receipt, _ = verified(monkeypatch, snapshot, repo, tmp_path)
    view = snapshot.open_snapshot(repo, commit, receipt)
    (entry,) = view.iter_entries()

    def forbidden(*args, **kwargs):
        pytest.fail("oversize record launched Git before rejecting its declared size")

    monkeypatch.setattr(snapshot.subprocess, "Popen", forbidden)
    with pytest.raises(snapshot.SnapshotError, match="blob_byte_limit"):
        view.read_blob(entry, max_bytes=2_000_000)
