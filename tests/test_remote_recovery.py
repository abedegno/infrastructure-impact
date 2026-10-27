"""Synthetic network/storage failures cannot advance an unverified checkpoint."""

import copy
import hashlib
import io
import json
import sqlite3
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

import pytest
from cryptography.fernet import Fernet

from infrastructure_impact.storage.remote_recovery import (
    BACKEND,
    AssetRedirects,
    GitHubDraftStore,
)
from ops import hosted_job as hosted


def vault(path):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE evidence(value TEXT)")
        db.execute("INSERT INTO evidence VALUES('SYNTHETIC PRIVATE RECOVERY DATA')")


class FakeAPI:
    def __init__(self):
        self.releases = []
        self.assets = {}
        self.requests = []
        self.fail_upload = False
        self.corrupt_download = False
        self.extra_download = False
        self.bad_digest = False

    def open(self, request, timeout):
        self.requests.append(request)
        url = urlsplit(request.full_url)
        method = request.get_method()
        assert url.hostname in {"api.github.com", "uploads.github.com"}
        assert request.get_header("Authorization") == "Bearer SYNTHETIC_TOKEN"
        assert timeout <= 60
        tail = url.path.removeprefix("/repos/example/recovery/")
        if tail == "releases" and method == "GET":
            value = self.releases
        elif tail == "releases" and method == "POST":
            value = {**json.loads(request.data), "id": len(self.releases) + 1}
            assert value["draft"] is True and value["make_latest"] == "false"
            self.releases.append(value)
        elif url.hostname == "uploads.github.com" and method == "POST":
            if self.fail_upload:
                raise HTTPError(request.full_url, 503, "PRIVATE RESPONSE BODY", {}, None)
            name = parse_qs(url.query)["name"][0]
            assert request.data.startswith(b"gAAAA")
            identifier = len(self.assets) + 1
            value = {
                "id": identifier,
                "name": name,
                "state": "uploaded",
                "size": len(request.data),
                "digest": "sha256:" + hashlib.sha256(request.data).hexdigest(),
            }
            if self.bad_digest:
                value["digest"] = "sha256:" + "0" * 64
            self.assets[identifier] = (value, request.data, int(tail.split("/")[1]))
        elif tail.startswith("releases/assets/"):
            payload = self.assets[int(tail.split("/")[-1])][1]
            if self.corrupt_download:
                payload = payload[:-1] + b"X"
            if self.extra_download:
                payload += b"X"
            return io.BytesIO(payload)
        elif tail.endswith("/assets"):
            identifier = int(tail.split("/")[1])
            value = [a for a, _, release in self.assets.values() if release == identifier]
        elif tail.startswith("releases/"):
            value = next(r for r in self.releases if r["id"] == int(tail.split("/")[1]))
        else:
            raise AssertionError(tail)
        return io.BytesIO(json.dumps(value).encode())


def setup(tmp_path):
    database = tmp_path / "source.sqlite3"
    vault(database)
    key = Fernet.generate_key()
    api = FakeAPI()
    store = GitHubDraftStore("example/recovery", "SYNTHETIC_TOKEN", opener=api)
    return database, key, api, store


@pytest.mark.parametrize("compression", ["gzip", "xz"])
def test_remote_checkpoint_preserves_legacy_files_and_recovers_all_rows(tmp_path, compression):
    database, key, api, store = setup(tmp_path)
    state = tmp_path / "tracked-state"
    hosted.backup(state, database, key)
    old_archives = {p.name: p.read_bytes() for p in state.glob("*.fernet")}
    manifest = hosted.backup_remote(state, database, key, store=store, compression=compression)
    assert manifest["storage_backend"] == BACKEND and manifest["remote_readback_verified_at"]
    assert {p.name: p.read_bytes() for p in state.glob("*.fernet")} == old_archives
    assert set(p.name for p in state.iterdir()) == set(old_archives) | {"current.json"}
    target = tmp_path / "restored.sqlite3"
    assert hosted.restore_current(state, target, key, store=store)
    with sqlite3.connect(target) as db:
        assert (
            db.execute("SELECT value FROM evidence").fetchone()[0]
            == "SYNTHETIC PRIVATE RECOVERY DATA"
        )
    assert hosted.validate_current(state, key, store=store)
    assert api.releases[0]["draft"] is True
    assert not any(r.get_method() in {"PATCH", "DELETE"} for r in api.requests)


@pytest.mark.parametrize(
    "failure", ["fail_upload", "corrupt_download", "extra_download", "bad_digest"]
)
def test_failed_upload_or_readback_preserves_pointer_and_all_legacy_bytes(tmp_path, failure):
    database, key, api, store = setup(tmp_path)
    state = tmp_path / "tracked-state"
    hosted.backup(state, database, key)
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    setattr(api, failure, True)
    with pytest.raises(ValueError):
        hosted.backup_remote(state, database, key, store=store)
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before
    assert all(not path.name.startswith(".") for path in state.iterdir())


def test_repeated_checkpoints_are_append_only_and_use_one_daily_draft(tmp_path):
    database, key, api, store = setup(tmp_path)
    state = tmp_path / "tracked-state"
    for _ in range(3):
        hosted.backup_remote(state, database, key, store=store)
    assert len(api.releases) == 1 and len(api.assets) == 3
    assert [p.name for p in state.iterdir()] == ["current.json"]
    assert hosted.validate_current(state, key, store=store)


def test_plaintext_is_rejected_before_any_network_request(tmp_path):
    database, _, api, store = setup(tmp_path)
    with pytest.raises(ValueError, match="encryption"):
        hosted.backup_remote(tmp_path / "state", database, None, store=store)
    local = tmp_path / "plaintext"
    manifest = hosted.backup(local, database)
    with pytest.raises(ValueError, match="encrypted archive"):
        store.publish(local / manifest["archive"], manifest)
    assert not api.requests


def test_published_or_unmanaged_draft_cannot_receive_a_new_archive(tmp_path):
    database, key, api, store = setup(tmp_path)
    state = tmp_path / "state"
    hosted.backup_remote(state, database, key, store=store)
    before = (state / "current.json").read_bytes()
    for field, value in [("draft", False), ("body", "Unmanaged release")]:
        old = api.releases[0][field]
        api.releases[0][field] = value
        with pytest.raises(ValueError, match="managed unpublished"):
            hosted.backup_remote(state, database, key, store=store)
        api.releases[0][field] = old
        assert (state / "current.json").read_bytes() == before
    assert len(api.assets) == 1


def test_wrong_key_and_missing_store_do_not_restore_a_database(tmp_path):
    database, key, api, store = setup(tmp_path)
    state = tmp_path / "state"
    hosted.backup_remote(state, database, key, store=store)
    target = tmp_path / "restored.sqlite3"
    with pytest.raises(ValueError, match="authenticated repository store"):
        hosted.restore_current(state, target, key)
    from cryptography.fernet import InvalidToken

    with pytest.raises(InvalidToken):
        hosted.restore_current(state, target, Fernet.generate_key(), store=store)
    assert not target.exists()


@pytest.mark.parametrize(
    "mutation", ["repository", "asset_id", "tag", "archive", "size", "extra_url"]
)
def test_untrusted_pointer_cannot_choose_another_destination(tmp_path, mutation):
    database, key, api, store = setup(tmp_path)
    manifest = hosted.backup_remote(tmp_path / "state", database, key, store=store)
    bad = copy.deepcopy(manifest)
    if mutation == "repository":
        bad["remote"]["repository"] = "another/repository"
    if mutation == "asset_id":
        bad["remote"]["asset_id"] = True
    if mutation == "tag":
        bad["remote"]["tag"] = "v1.0"
    if mutation == "archive":
        bad["archive"] = "../private.sqlite3"
    if mutation == "size":
        bad["archive_bytes"] = 51 * 1024 * 1024
    if mutation == "extra_url":
        bad["remote"]["url"] = "https://untrusted.example/download"
    count = len(api.requests)
    with pytest.raises(ValueError, match="pointer"):
        store.download(bad, tmp_path / "download")
    assert len(api.requests) == count


def test_download_refuses_to_replace_a_file_and_cleans_failed_staging(tmp_path):
    database, key, api, store = setup(tmp_path)
    manifest = hosted.backup_remote(tmp_path / "state", database, key, store=store)
    target = tmp_path / "download"
    target.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        store.download(manifest, target)
    assert target.read_bytes() == b"existing"
    api.corrupt_download = True
    with pytest.raises(ValueError):
        store.download(manifest, tmp_path / "bad-download")
    assert not (tmp_path / "bad-download").exists() and not list(tmp_path.glob(".recovery-asset-*"))


def test_download_asset_must_belong_to_the_recorded_managed_draft(tmp_path):
    database, key, api, store = setup(tmp_path)
    manifest = hosted.backup_remote(tmp_path / "state", database, key, store=store)
    asset = api.assets[manifest["remote"]["asset_id"]]
    api.assets[manifest["remote"]["asset_id"]] = (asset[0], asset[1], 99)
    with pytest.raises(ValueError, match="missing"):
        store.download(manifest, tmp_path / "download")


@pytest.mark.parametrize(
    "target",
    [
        "http://release-assets.githubusercontent.com/file",
        "https://evil.example/file",
        "https://release-assets.githubusercontent.com:444/file",
        "https://user:pass@objects.githubusercontent.com/file",
    ],
)
def test_asset_redirects_cannot_send_credentials_to_unapproved_targets(target):
    request = Request(
        "https://api.github.com/repos/example/recovery/releases/assets/1",
        headers={"Authorization": "Bearer SYNTHETIC_TOKEN", "Accept": "application/octet-stream"},
    )
    with pytest.raises(ValueError, match="redirect"):
        AssetRedirects().redirect_request(request, None, 302, "", {}, target)


def test_approved_download_redirect_has_no_authorization_header():
    request = Request(
        "https://api.github.com/repos/example/recovery/releases/assets/1",
        headers={"Authorization": "Bearer SYNTHETIC_TOKEN", "Accept": "application/octet-stream"},
    )
    redirected = AssetRedirects().redirect_request(
        request,
        None,
        302,
        "",
        {},
        "https://release-assets.githubusercontent.com/file?signature=synthetic",
    )
    assert redirected.get_header("Authorization") is None
    assert redirected.get_header("Accept") == "application/octet-stream"
    with pytest.raises(ValueError, match="redirect"):
        AssetRedirects().redirect_request(
            Request("https://api.github.com/repos/example/recovery/releases"),
            None,
            302,
            "",
            {},
            redirected.full_url,
        )


def test_api_failure_message_does_not_expose_server_text_or_token(tmp_path):
    database, key, api, store = setup(tmp_path)
    api.fail_upload = True
    with pytest.raises(ValueError, match="HTTP 503") as error:
        hosted.backup_remote(tmp_path / "state", database, key, store=store)
    assert "SYNTHETIC_TOKEN" not in str(error.value) and "PRIVATE RESPONSE" not in str(error.value)


def test_remote_monitor_reports_legacy_git_copies_and_writer_receipt(tmp_path):
    from checks.backup_storage import summarize

    database, key, api, store = setup(tmp_path)
    state = tmp_path / "state"
    hosted.backup(state, database, key)
    legacy = [
        {"path": "state/" + p.name, "sha": "a" * 40, "size": p.stat().st_size, "type": "blob"}
        for p in state.glob("*.fernet")
    ]
    manifest = hosted.backup_remote(state, database, key, store=store)
    report = summarize([legacy], 100, manifest, repository="example/recovery")
    assert report["storage_backend"] == BACKEND
    assert report["latest_archive_bytes"] == manifest["archive_bytes"]
    assert report["remaining_runs_scenario"] is None
    assert report["retention"]["current_tree_copies_are_legacy"] is True
    assert report["recovery_verification_source"] == "writer_remote_readback_receipt"
    assert not report["storage_review_required"]
    for bad in [
        {**manifest, "remote_readback_verified_at": None},
        {**manifest, "archive_bytes": True},
    ]:
        with pytest.raises(ValueError):
            summarize([legacy], 100, bad)
    with pytest.raises(ValueError):
        summarize([legacy], 100, manifest, repository="wrong/repository")


def test_remote_validation_still_authenticates_every_retained_legacy_copy(tmp_path):
    database, key, api, store = setup(tmp_path)
    state = tmp_path / "state"
    old = hosted.backup(state, database, key)
    hosted.backup_remote(state, database, key, store=store)
    (state / old["archive"]).write_bytes(b"damaged legacy copy")
    from cryptography.fernet import InvalidToken

    with pytest.raises(InvalidToken):
        hosted.validate_current(state, key, store=store)


def test_hosted_cli_remote_write_restore_and_validation_use_same_backend(
    tmp_path, monkeypatch, capsys
):
    import infrastructure_impact.storage.remote_recovery as remote
    import infrastructure_impact.worker as worker
    from infrastructure_impact.storage.repository import connect

    _, key, api, store = setup(tmp_path)
    monkeypatch.setattr(remote, "GitHubDraftStore", lambda repository: store)

    def collect():
        with connect() as db:
            db.execute(
                "INSERT INTO evidence(source_url,sha256,observed_at,raw,media_type) VALUES(?,?,?,?,?)",
                (
                    "https://example.test/source",
                    hashlib.sha256(b"SYNTHETIC JOB EVIDENCE").hexdigest(),
                    "2026-10-27T00:00:00Z",
                    b"SYNTHETIC JOB EVIDENCE",
                    "application/json",
                ),
            )
        return {"outcome": "partial", "failures": 1}

    monkeypatch.setattr(worker, "collect_once", collect)
    monkeypatch.setenv("IMPACT_STATE_KEY", key.decode())
    for name in (
        "IMPACT_HOME",
        "IMPACT_DATABASE",
        "IMPACT_SNAPSHOT",
        "IMPACT_BASE_PATH",
        "IMPACT_DELIVERY_MODE",
    ):
        monkeypatch.setenv(name, "")
    state = tmp_path / "state"
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
            "--recovery-storage",
            "github-draft",
            "--recovery-repository",
            "example/recovery",
        ],
    )
    hosted.main()
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["private_recovery"] == "verified" and receipt["recovery_storage"] == BACKEND
    assert set(p.name for p in state.iterdir()) == {"current.json"}
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hosted_job.py",
            "--state-dir",
            str(state),
            "--encrypted-state",
            "--validate-encrypted-state",
            "--recovery-repository",
            "example/recovery",
        ],
    )
    hosted.main()
    assert json.loads(capsys.readouterr().out) == {"encrypted_state": "authenticated"}


def test_remote_cli_cannot_enable_uploads_without_encryption(tmp_path, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hosted_job.py",
            "--state-dir",
            str(tmp_path / "state"),
            "--output",
            str(tmp_path / "public"),
            "--recovery-storage",
            "github-draft",
        ],
    )
    with pytest.raises(SystemExit) as error:
        hosted.main()
    assert error.value.code == 2


def test_metadata_download_budget_is_enforced_before_json_parsing():
    class LargeMetadata:
        def open(self, request, timeout):
            return io.BytesIO(b" " * 2_000_001)

    store = GitHubDraftStore("example/recovery", "SYNTHETIC_TOKEN", opener=LargeMetadata())
    with pytest.raises(ValueError, match="metadata exceeds"):
        store._release("collector-recovery-2026-10-27")


def test_reusable_public_workflow_has_the_same_recovery_authentication_gate():
    root = Path(__file__).resolve().parent.parent
    assert (root / ".github/workflows/collect.yaml").read_bytes() == (
        root / "deploy/github-public-service.yaml"
    ).read_bytes()


@pytest.mark.parametrize("failed_check", [1, 2])
def test_missing_local_or_remote_readback_cannot_advance_pointer(
    tmp_path, monkeypatch, failed_check
):
    database, key, api, store = setup(tmp_path)
    state = tmp_path / "state"
    hosted.backup(state, database, key)
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    original = hosted.restore
    calls = []

    def incomplete(*args, **kwargs):
        calls.append(True)
        return False if len(calls) == failed_check else original(*args, **kwargs)

    monkeypatch.setattr(hosted, "restore", incomplete)
    with pytest.raises(RuntimeError, match="not available for recovery verification"):
        hosted.backup_remote(state, database, key, store=store)
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before


def test_restore_only_cli_writes_only_an_explicit_new_private_database(
    tmp_path, monkeypatch, capsys
):
    import infrastructure_impact.storage.remote_recovery as remote

    database, key, api, store = setup(tmp_path)
    state = tmp_path / "state"
    hosted.backup_remote(state, database, key, store=store)
    monkeypatch.setattr(remote, "GitHubDraftStore", lambda repository: store)
    monkeypatch.setenv("IMPACT_STATE_KEY", key.decode())
    target = tmp_path / "recovered.sqlite3"
    base = [
        "hosted_job.py",
        "--state-dir",
        str(state),
        "--encrypted-state",
        "--recovery-repository",
        "example/recovery",
        "--restore-only",
    ]
    monkeypatch.setattr(sys, "argv", base + [str(target)])
    hosted.main()
    assert json.loads(capsys.readouterr().out) == {"restored": True, "storage_backend": BACKEND}
    with sqlite3.connect(target) as db:
        assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1
    with pytest.raises(FileExistsError):
        hosted.main()
    monkeypatch.setattr(sys, "argv", base + [str(state / "plaintext.sqlite3")])
    with pytest.raises(SystemExit):
        hosted.main()
    assert not (state / "plaintext.sqlite3").exists()
    dangling = tmp_path / "dangling.sqlite3"
    dangling.symlink_to(tmp_path / "unintended.sqlite3")
    monkeypatch.setattr(sys, "argv", base + [str(dangling)])
    with pytest.raises(SystemExit):
        hosted.main()
    assert not (tmp_path / "unintended.sqlite3").exists()
