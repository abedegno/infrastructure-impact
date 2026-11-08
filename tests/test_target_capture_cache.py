"""Durable byte captures survive rejected candidates without changing the baseline."""

import sqlite3
from contextlib import closing

import pytest
from test_target_import_stage import implementation, passing_verifier, receipt, serve, snapshot
from test_target_import_stage import setup as setup


def test_restart_after_rejection_replays_original_capture_without_http(setup, monkeypatch):
    database, selected, raws, output, home = setup
    module = implementation()
    accepted = receipt(database, selected)
    before = snapshot(database)
    serve(monkeypatch, selected, raws)
    monkeypatch.setattr(module, "verify", lambda *_: {"candidate_validated": False})
    first = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert first["failure_code"] == "candidate_validation"
    cache = home / "captures" / (selected.fingerprint + ".sqlite3")
    assert cache.is_file()
    with closing(sqlite3.connect(cache)) as db:
        captures = db.execute(
            "SELECT url,sha256,observed_at,raw FROM captures ORDER BY url"
        ).fetchall()
    assert len(captures) == 2
    monkeypatch.setattr(module.transport, "build_opener", lambda *_: pytest.fail("replay HTTP"))
    monkeypatch.setattr(module, "verify", passing_verifier)
    retried = output.with_name("retry")
    second = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        retried,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert second["outcome"] == "completed"
    assert second["counters"]["http_attempts"] == second["counters"]["received_bytes"] == 0
    with closing(sqlite3.connect(retried / second["staged_database"])) as db:
        actual = db.execute(
            "SELECT source_url,sha256,observed_at,raw FROM evidence WHERE id>1 ORDER BY source_url"
        ).fetchall()
        assert actual == captures
        assert db.execute("SELECT count(*) FROM source_observations").fetchone()[0] == 0
    assert snapshot(database) == before


def test_exact_baseline_capture_reuses_bytes_before_http(setup, monkeypatch):
    from infrastructure_impact.storage.repository import connect, evidence

    database, selected, raws, output, home = setup
    with closing(connect(database)) as db, db:
        for t in selected.targets:
            evidence(db, raws[t.vendor], t.fetch_url)
    monkeypatch.setattr(
        implementation().transport, "build_opener", lambda *_: pytest.fail("baseline HTTP")
    )
    monkeypatch.setattr(implementation(), "verify", passing_verifier)
    accepted = receipt(database, selected)
    result = implementation().stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert result["outcome"] == "completed"
    assert result["counters"]["http_attempts"] == 0


@pytest.mark.parametrize("kind", ["wrong_url", "wrong_hash", "corrupt", "oversize", "timestamp"])
def test_cache_identity_integrity_and_document_limit(setup, monkeypatch, kind):
    from infrastructure_impact.storage import capture_cache

    database, selected, raws, output, home = setup
    cache = home / "captures" / (selected.fingerprint + ".sqlite3")
    target = selected.targets[0]
    raw = raws[target.vendor]
    url, digest = target.fetch_url, target.source_sha256
    if kind == "wrong_url":
        url += "?different"
    elif kind == "wrong_hash":
        digest = "0" * 64
    elif kind == "corrupt":
        raw = b"corrupt payload"
    elif kind == "oversize":
        raw = b"x" * (selected.max_document_bytes + 1)
        # Metadata claims the pinned digest; actual bytes must still be checked.
    with closing(capture_cache.connect(cache)) as db:
        capture_cache.save(
            db,
            dict(
                url=url,
                sha256=digest,
                observed_at="2020-01-01" if kind == "timestamp" else "2020-01-01T00:00:00Z",
                raw=raw,
                media_type="text/plain",
                etag=None,
                modified=None,
            ),
        )
    calls = serve(monkeypatch, selected, raws)
    monkeypatch.setattr(implementation(), "verify", passing_verifier)
    accepted = receipt(database, selected)
    result = implementation().stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    if kind in ("wrong_url", "wrong_hash"):
        assert result["outcome"] == "completed" and len(calls) == 2
    else:
        assert result["failure_code"] == ("source_access" if kind == "oversize" else "storage")
        assert calls == []


@pytest.mark.parametrize(
    "kind", ["source", "source_sidecar", "output", "parent", "symlink", "sidecar_link"]
)
def test_explicit_cache_separation_and_symlink_refusal(setup, monkeypatch, kind):
    database, selected, _, output, home = setup
    cache = home / "capture.sqlite3"
    if kind == "source":
        cache = database
    elif kind == "source_sidecar":
        cache = database.with_name("intel.sqlite3-wal")
    elif kind == "output":
        cache = output / "capture.sqlite3"
    elif kind == "parent":
        cache = output.parent
    elif kind == "symlink":
        cache.symlink_to(home / "absent")
    else:
        from pathlib import Path

        Path(str(cache) + "-journal").symlink_to(home / "absent")
    before = snapshot(database)
    monkeypatch.setattr(
        implementation().transport, "build_opener", lambda *_: pytest.fail("unsafe HTTP")
    )
    accepted = receipt(database, selected)
    result = implementation().stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
        capture_cache=cache,
    )
    assert result["failure_code"] == "storage"
    assert not output.exists()
    assert snapshot(database) == before


def test_interrupted_cache_transaction_keeps_earlier_commit(tmp_path):
    from hashlib import sha256

    from infrastructure_impact.storage import capture_cache

    cache = tmp_path / "captures.sqlite3"
    capture = dict(
        url="https://example.com/a",
        sha256=sha256(b"a").hexdigest(),
        observed_at="2020-01-01T00:00:00Z",
        raw=b"a",
        media_type="text/plain",
        etag="original",
        modified=None,
    )
    with closing(capture_cache.connect(cache)) as db:
        capture_cache.save(db, capture)
        db.execute("BEGIN")
        db.execute("UPDATE captures SET raw=?", (b"uncommitted",))
    with closing(capture_cache.connect(cache)) as db:
        recovered = capture_cache.lookup(db, capture["url"], capture["sha256"], 1)
        assert recovered["raw"] == b"a"
        assert recovered["observed_at"] == "2020-01-01T00:00:00Z"
        with pytest.raises(capture_cache.CaptureError):
            capture_cache.lookup(db, capture["url"], capture["sha256"], 0)


def test_stage_transfers_checkpoint_inode_and_keeps_real_integrity(setup, monkeypatch):
    module = implementation()
    database, selected, raws, output, home = setup
    actual_move = module.shutil.move
    transferred = []

    def move(source, destination):
        before = source.stat()
        result = actual_move(source, destination)
        after = destination.stat()
        assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
        with closing(sqlite3.connect(destination)) as db:
            assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        transferred.append(True)
        return result

    monkeypatch.setattr(module.shutil, "move", move)
    serve(monkeypatch, selected, raws)
    monkeypatch.setattr(module, "verify", passing_verifier)
    accepted = receipt(database, selected)
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert result["outcome"] == "completed" and transferred == [True]


def test_partial_preflight_commits_and_checkpoints_first_capture(setup, monkeypatch):
    import io
    from urllib.error import HTTPError

    from test_target_import_stage import Response

    database, selected, raws, output, home = setup
    module = implementation()
    first, second = selected.targets

    class Opener:
        def open(self, request, timeout):
            if request.full_url == second.fetch_url:
                raise HTTPError(request.full_url, 403, "blocked", {}, io.BytesIO())
            return Response(raws[first.vendor])

    monkeypatch.setattr(module.transport, "build_opener", lambda *_: Opener())
    monkeypatch.setattr(module, "verify", lambda *_: pytest.fail("partial candidate verification"))
    checkpoints = []

    def checkpoint(path):
        with closing(sqlite3.connect(path)) as db:
            checkpoints.append(db.execute("SELECT url,raw FROM captures").fetchall())

    accepted = receipt(database, selected)
    first_result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
        acquisition_checkpoint=checkpoint,
    )
    assert first_result["failure_code"] == "source_access"
    assert checkpoints == [[(first.fetch_url, raws[first.vendor])]]
    monkeypatch.setattr(module, "verify", passing_verifier)
    calls = serve(monkeypatch, selected, raws)
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output.with_name("retry"),
        lock_home=home,
        accepted_preview=accepted,
    )
    assert result["outcome"] == "completed"
    assert len(calls) == result["counters"]["http_attempts"] == 1


def test_failed_acquisition_checkpoint_prevents_verification(setup, monkeypatch):
    database, selected, raws, output, home = setup
    module = implementation()
    serve(monkeypatch, selected, raws)
    monkeypatch.setattr(module, "verify", lambda *_: pytest.fail("uncheckpointed candidate"))

    def reject(_):
        raise ValueError("private checkpoint detail")

    accepted = receipt(database, selected)
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
        acquisition_checkpoint=reject,
    )
    assert result["failure_code"] == "storage"
    assert result["counters"]["http_attempts"] == 2


def test_valid_oversize_capture_cannot_bypass_stage_document_limit(setup, monkeypatch):
    from hashlib import sha256

    from infrastructure_impact.collection.target_import_profiles import from_manifest
    from infrastructure_impact.storage import capture_cache

    database, selected, raws, output, home = setup
    raw = raws["aruba"].ljust(selected.max_document_bytes + 1, b" ")
    value = selected.metadata()
    value["targets"][0]["source_sha256"] = sha256(raw).hexdigest()
    selected = from_manifest(value)
    monkeypatch.setattr(implementation().target_import, "registered_profile", lambda _: selected)
    target = selected.targets[0]
    cache = home / "captures" / (selected.fingerprint + ".sqlite3")
    with closing(capture_cache.connect(cache)) as db:
        capture_cache.save(
            db,
            dict(
                url=target.fetch_url,
                sha256=target.source_sha256,
                observed_at="2020-01-01T00:00:00Z",
                raw=raw,
                media_type="text/plain",
                etag=None,
                modified=None,
            ),
        )
    monkeypatch.setattr(
        implementation().transport, "build_opener", lambda *_: pytest.fail("oversize HTTP")
    )
    accepted = receipt(database, selected)
    result = implementation().stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
    )
    assert result["failure_code"] == "source_access"
    assert result["counters"]["http_attempts"] == 0


def test_cli_explicit_capture_cache_stays_outside_output(setup, monkeypatch, capsys):
    from infrastructure_impact.application.target_import_contracts import preview_bytes
    from infrastructure_impact.cli import main
    from infrastructure_impact.collection import target_import_profiles

    database, selected, raws, output, home = setup
    cache = home / "explicit-captures.sqlite3"
    accepted = receipt(database, selected)
    preview = home / "preview.json"
    preview.write_bytes(preview_bytes(accepted, selected=selected))
    monkeypatch.setattr(target_import_profiles, "profile", lambda _: selected)
    monkeypatch.setattr(implementation(), "verify", passing_verifier)
    serve(monkeypatch, selected, raws)
    assert (
        main(
            [
                "target-import",
                "stage",
                "--database",
                str(database),
                "--profile",
                selected.profile_id,
                "--output",
                str(output),
                "--home",
                str(home),
                "--preview",
                str(preview),
                "--capture-cache",
                str(cache),
            ]
        )
        == 0
    )
    assert cache.is_file()
    assert cache.stat().st_mode & 0o777 == 0o600
    assert not (home / "captures").exists()
    assert "explicit-captures" not in capsys.readouterr().out


@pytest.mark.parametrize("cache_suffix", ["", "-wal", "-shm", "-journal"])
@pytest.mark.parametrize("source_suffix", ["", "-wal", "-shm", "-journal"])
def test_cache_family_hardlink_aliases_refused_before_sqlite_write(
    setup, monkeypatch, cache_suffix, source_suffix
):
    from pathlib import Path

    database, selected, _, output, home = setup
    cache = home / "separate" / "cache.sqlite3"
    cache.parent.mkdir()
    source = Path(str(database) + source_suffix)
    if not source.exists():
        source.touch()
    Path(str(cache) + cache_suffix).hardlink_to(source)
    accepted = receipt(database, selected)
    before = snapshot(database)
    module = implementation()
    monkeypatch.setattr(module.captures, "connect", lambda *_: pytest.fail("cache SQLite opened"))
    monkeypatch.setattr(module.transport, "build_opener", lambda *_: pytest.fail("alias HTTP"))
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
        capture_cache=cache,
    )
    assert result["failure_code"] == "storage"
    assert not output.exists()
    assert snapshot(database) == before


@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
def test_nonregular_cache_family_path_refused_before_sqlite(setup, monkeypatch, suffix):
    from pathlib import Path

    database, selected, _, output, home = setup
    cache = home / "nonregular.sqlite3"
    Path(str(cache) + suffix).mkdir()
    module = implementation()
    monkeypatch.setattr(module.captures, "connect", lambda *_: pytest.fail("nonregular SQLite"))
    accepted = receipt(database, selected)
    before = snapshot(database)
    result = module.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
        capture_cache=cache,
    )
    assert result["failure_code"] == "storage"
    assert not output.exists()
    assert snapshot(database) == before
