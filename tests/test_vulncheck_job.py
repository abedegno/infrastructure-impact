"""Synthetic scheduled collection and encrypted restart; no live feed or credentials."""

import json

from cryptography.fernet import Fernet
from test_remote_recovery import FakeAPI
from test_vulncheck_kev import NOW, TOKEN, Session

from infrastructure_impact.collection import vulncheck_kev as vc
from infrastructure_impact.storage.remote_recovery import GitHubDraftStore
from ops import vulncheck_job as job


def test_hosted_helper_is_in_the_public_source_release():
    from checks import release

    assert "ops/vulncheck_job.py" in release.FILES


def context(tmp_path):
    checkout = tmp_path / "service"
    checkout.mkdir()
    api = FakeAPI()
    store = GitHubDraftStore("example/recovery", token="SYNTHETIC_TOKEN", opener=api)
    env = {
        "IMPACT_STATE_KEY": Fernet.generate_key().decode(),
        "IMPACT_SOURCE_COMMIT": "a" * 40,
        "GITHUB_REPOSITORY": "example/recovery",
        "VULNCHECK_API_TOKEN": TOKEN,
    }
    return checkout, store, env, api


def test_first_run_and_restart_reuse_retained_backup(tmp_path):
    checkout, store, env, api = context(tmp_path)
    session = Session()
    commits = []
    forces = []

    def collect(path, **kwargs):
        forces.append(kwargs["force"])
        return vc.collect(path, token=env["VULNCHECK_API_TOKEN"], session=session, at=NOW, **kwargs)

    kwargs = dict(environ=env, store=store, collector=collect, commit=lambda p: commits.append(p))
    first = job.execute(checkout, **kwargs)
    assert first["collection_outcome"] == "ok"
    assert first["checkpoint_persisted"] and first["private_recovery_verified"]
    assert len(session.calls) == 2 and len(commits) == 1
    assert job.execute(checkout, **kwargs)["collection_outcome"] == "ok"
    assert len(session.calls) == 3, (
        "daily verification reuses matching ZIP rather than downloading again"
    )
    assert forces == [True, True], "daily jitter must not defer verification for another whole day"
    assert list((checkout / "vulncheck-state").iterdir()) == [
        checkout / "vulncheck-state/current.json"
    ]
    pointer = (checkout / "vulncheck-state/current.json").read_bytes()
    assert TOKEN.encode() not in pointer and b"SQLite format" not in pointer
    assert all(value[1].startswith(b"gAAAA") for value in api.assets.values())


def test_collection_failure_retains_failed_attempt_without_claiming_success(tmp_path):
    checkout, store, env, api = context(tmp_path)

    def failure(path, **kwargs):
        return vc.collect(path, token="", at=NOW)

    result = job.execute(
        checkout, environ=env, store=store, collector=failure, commit=lambda _: None
    )
    assert result["collection_outcome"] == "failed"
    assert result["error_code"] == "credentials_missing"
    assert result["checkpoint_persisted"] and result["private_recovery_verified"]


def test_upload_failure_keeps_previous_pointer_and_hides_exception(tmp_path):
    checkout, store, env, api = context(tmp_path)

    def collector(path, **kw):
        return vc.collect(path, token=TOKEN, session=Session(), at=NOW, **kw)

    job.execute(checkout, environ=env, store=store, collector=collector, commit=lambda _: None)
    pointer = (checkout / "vulncheck-state/current.json").read_bytes()
    api.fail_upload = True
    result = job.execute(
        checkout, environ=env, store=store, collector=collector, commit=lambda _: None
    )
    assert result["error_code"] == "recovery_failed"
    assert not result["checkpoint_persisted"]
    assert (checkout / "vulncheck-state/current.json").read_bytes() == pointer
    assert "PRIVATE RESPONSE" not in json.dumps(result)


def test_invalid_configuration_and_symlinks_never_collect(tmp_path):
    checkout, store, env, _ = context(tmp_path)
    env["IMPACT_STATE_KEY"] = ""

    def forbidden(*args, **kwargs):
        raise AssertionError("must not collect")

    result = job.execute(checkout, environ=env, store=store, collector=forbidden)
    assert result["error_code"] == "configuration_invalid"
    assert not (checkout / "vulncheck-state").exists()
    env["IMPACT_STATE_KEY"] = Fernet.generate_key().decode()
    (checkout / "vulncheck-state").symlink_to(tmp_path, target_is_directory=True)
    assert (
        job.execute(checkout, environ=env, store=store, collector=forbidden)["error_code"]
        == "configuration_invalid"
    )


def test_private_database_is_temporary_and_main_vault_untouched(tmp_path):
    checkout, store, env, _ = context(tmp_path)
    main = checkout / "state"
    main.mkdir()
    (main / "current.json").write_text("SYNTHETIC MAIN POINTER")
    paths = []

    def collect(path, **kw):
        paths.append(path)
        return vc.collect(path, token=TOKEN, session=Session(), at=NOW, **kw)

    job.execute(checkout, environ=env, store=store, collector=collect, commit=lambda _: None)
    assert all(not p.exists() and not p.is_relative_to(checkout) for p in paths)
    assert (main / "current.json").read_text() == "SYNTHETIC MAIN POINTER"


def test_commit_only_tracks_fixed_pointer(tmp_path):
    import subprocess

    checkout = tmp_path / "repository"
    checkout.mkdir()

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(checkout), *args], check=True, capture_output=True, text=True
        )

    git("init", "-b", "publication-state")
    pointer = checkout / "vulncheck-state/current.json"
    pointer.parent.mkdir()
    pointer.write_text("{}")
    (checkout / "plaintext.sqlite").write_text("MUST NOT TRACK")
    pushes = []
    job.commit_pointer(checkout, push=lambda repo: pushes.append(repo))
    assert git("ls-files").stdout.splitlines() == ["vulncheck-state/current.json"]
    assert pushes == [checkout]
