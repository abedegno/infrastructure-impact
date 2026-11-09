"""Synthetic-only tests for the closed runner activation boundary."""

import importlib
import importlib.util
import json
from contextlib import closing
from hashlib import sha256

import pytest

from infrastructure_impact.storage.repository import connect, ingest


def implementation():
    name = "infrastructure_impact.application.switching_activation"
    assert importlib.util.find_spec(name), "closed activation helper is absent"
    return importlib.import_module(name)


@pytest.fixture
def baseline(tmp_path, monkeypatch):
    monkeypatch.setenv("IMPACT_SOURCE_COMMIT", "a" * 40)
    home = tmp_path / "home"
    database = home / "data/intel.sqlite3"
    with closing(connect(database)):
        pass
    state = tmp_path / "state"
    state.mkdir()
    (state / "current.json").write_text(
        '{"storage_backend":"github-draft-release-v1","synthetic":true}'
    )
    return home, database, state


def test_preview_is_read_only_finite_and_binds_manifest_and_all_normalizers(baseline, monkeypatch):
    m = implementation()
    home, database, state = baseline
    before = database.read_bytes()
    # Expected Arista absence must fail closed, not silently skip maintenance.
    with pytest.raises(ValueError):
        m.preview(database, state)
    assert database.read_bytes() == before


def test_custom_profile_keeps_stock_manifest_validation():
    m = implementation()
    selected = m.selected_profile()
    from infrastructure_impact.collection.target_import_profiles import from_manifest

    assert from_manifest(selected.metadata()) == selected
    assert len(selected.targets) == 2
    assert m.ARUBA_URL in selected.allowed_urls
    assert len(selected.allowed_urls) == 2


@pytest.mark.parametrize(
    "flags",
    [
        ["--maintenance-profile", "switching-readiness-2026-11-09-v1", "--maintenance-profile=x"],
        ["--maintenance-profile=switching-readiness-2026-11-09-v1", "--unknown=SECRET"],
        ["--maintenance-profile=switching-readiness-2026-11-09-v1", "--maintenance-mode=other"],
    ],
)
def test_invalid_controls_fail_closed_before_restore(flags, monkeypatch, capsys):
    m = implementation()
    from ops import hosted_job

    monkeypatch.setattr(hosted_job, "restore_current", lambda *a, **k: pytest.fail("restore"))
    assert m.main(flags) == 1
    output = capsys.readouterr()
    assert "SECRET" not in output.out + output.err
    assert json.loads(output.out)["stage"] == "controls"


def authored_arista(database, m, monkeypatch):
    from infrastructure_impact.plugins.registry import default_registry

    registry = default_registry()
    with closing(connect(database)) as db:
        for identity, url, cves in m.ARISTA:
            raw = (
                f"<html><title>Synthetic advisory</title><body><h1>Security Advisory {identity}</h1>"
                f"<p>{cves[0]}</p><h2>Affected Software</h2><div>EOS Versions:</div><ul><li>4.30.1</li></ul><h2>History</h2>"
                "</body></html>"
            ).encode()
            document = registry.normalize(raw, url, "arista")
            assert document["advisory_id"] == identity
            document["adapter_version"] = "synthetic-old-parser"
            ingest(db, raw, url, lambda *a, document=document: document, "arista")

    # Author an exact existing Cisco bundle member; never substitute live bytes.
    from dataclasses import replace
    from types import SimpleNamespace

    from test_cisco_platform_scope import document

    from infrastructure_impact.collection import target_import_profiles as profiles

    stock = profiles.profile(profiles.PROFILE_ID)
    anchor = next(t for t in stock.targets if t.advisory_id == m.ANCHOR_ID)
    data = document()
    data["document"]["tracking"]["id"] = m.ANCHOR_ID
    data["vulnerabilities"] = [data["vulnerabilities"][0]]
    data["vulnerabilities"][0]["cve"] = "CVE-2024-20259"
    raw = json.dumps(data).encode()
    anchor = replace(anchor, source_sha256=sha256(raw).hexdigest())
    monkeypatch.setattr(m, "ANCHOR_SHA256", anchor.source_sha256)
    monkeypatch.setattr(profiles, "profile", lambda name: SimpleNamespace(targets=(anchor,)))
    with closing(connect(database)) as db:
        ingest(db, raw, anchor.fetch_url, registry.normalize, "cisco")


def test_preview_stock_inventory_no_raw_keys_and_stale_binding(baseline, monkeypatch):
    m = implementation()
    home, database, state = baseline
    authored_arista(database, m, monkeypatch)
    before = database.read_bytes()
    first = m.preview(database, state)
    encoded = m.encoded(first)
    assert len(encoded) <= 2_000_000
    assert first["format"] == "impact-switching-activation-preview"
    assert set(first["normalizer_fingerprints"]) == {"arista", "aruba", "cisco"}
    assert "Synthetic advisory" not in encoded.decode()
    assert "before_keys" not in encoded.decode()
    assert database.read_bytes() == before
    assert m.preview(database, state)["fingerprint"] == first["fingerprint"]
    (state / "current.json").write_text('{"synthetic":false}')
    assert m.preview(database, state)["fingerprint"] != first["fingerprint"]
    monkeypatch.setenv("IMPACT_SOURCE_COMMIT", "b" * 40)
    assert m.preview(database, state)["fingerprint"] != first["fingerprint"]


def test_reparse_preserves_old_evidence_and_exact_identities(baseline, monkeypatch):
    m = implementation()
    home, database, state = baseline
    authored_arista(database, m, monkeypatch)
    with closing(connect(database)) as db:
        before = [tuple(r) for r in db.execute("SELECT * FROM evidence ORDER BY id")]
        revisions = [tuple(r) for r in db.execute("SELECT * FROM revisions ORDER BY id")]
    m.reparse(database)
    with closing(connect(database)) as db:
        assert [tuple(r) for r in db.execute("SELECT * FROM evidence ORDER BY id")] == before
        assert [
            tuple(r) for r in db.execute("SELECT * FROM revisions WHERE id<=3 ORDER BY id")
        ] == revisions
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 5
        assert db.execute("SELECT COUNT(*) FROM source_observations").fetchone()[0] == 0


@pytest.mark.parametrize("mutation", ["wrong_cve", "missing", "wrong_url", "wrong_raw"])
def test_retained_arista_drift_blocks_before_any_reparse(baseline, mutation, monkeypatch):
    m = implementation()
    home, database, state = baseline
    authored_arista(database, m, monkeypatch)
    with closing(connect(database)) as db, db:
        if mutation == "missing":
            db.execute("DELETE FROM revisions WHERE id=2")
        elif mutation == "wrong_cve":
            row = json.loads(
                db.execute("SELECT normalized FROM revisions WHERE id=2").fetchone()[0]
            )
            row["cves"] = ["CVE-2026-99999"]
            db.execute("UPDATE revisions SET normalized=? WHERE id=2", (json.dumps(row),))
        elif mutation == "wrong_url":
            db.execute("UPDATE revisions SET source_url='https://www.arista.com/wrong' WHERE id=2")
        else:
            db.execute("UPDATE evidence SET raw=? WHERE id=2", (b"wrong",))
        count = db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0]
    with pytest.raises(ValueError):
        m.reparse(database)
    with closing(connect(database)) as db:
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == count


def synthetic_erp(monkeypatch, m):
    from infrastructure_impact.adapters import switching

    raw = b"<html>Synthetic explicit bundle members; no advisory normalization.</html>"
    entry = next(
        e for e in switching.bindings_resource()["entries"] if e["source_url"] == m.ERP_URL
    )
    entry = json.loads(json.dumps(entry))
    entry["source_sha256"] = sha256(raw).hexdigest()
    monkeypatch.setattr(m, "ERP_SHA256", entry["source_sha256"])
    monkeypatch.setattr(m, "ERP_SIZE", len(raw))
    monkeypatch.setattr(
        switching, "bindings_resource", lambda: {"schema_version": 1, "entries": [entry]}
    )
    return raw


def serve_one(monkeypatch, url, raw, *, retry=False):
    import io
    from urllib.error import HTTPError

    from infrastructure_impact.collection import transport

    calls = []

    class Response(io.BytesIO):
        status = 200
        headers = {"Content-Type": "text/html"}

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == url
            calls.append(request.full_url)
            if retry:
                raise HTTPError(url, 503, "PRIVATE_EXCEPTION_SENTINEL", {}, io.BytesIO(b"private"))
            return Response(raw)

    monkeypatch.setattr(transport, "build_opener", lambda *a: Opener())
    monkeypatch.setattr(transport.time, "sleep", lambda *a: None)
    return calls


def test_erp_uses_stock_transport_source_only_and_true_observation(baseline, monkeypatch):
    m = implementation()
    home, database, state = baseline
    raw = synthetic_erp(monkeypatch, m)
    calls = serve_one(monkeypatch, m.ERP_URL, raw)
    assert m.capture_erp(database) == 1
    assert calls == [m.ERP_URL]
    with closing(connect(database)) as db:
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 0
        row = db.execute(
            "SELECT e.raw,o.http_status,e.observed_at,o.checked_at FROM evidence e JOIN source_observations o ON o.evidence_id=e.id"
        ).fetchone()
        assert row[0] == raw and row[1] == 200
        assert row[2] != m.PRIOR_CAPTURE and row[3] != m.PRIOR_CAPTURE


def test_erp_retry_is_bounded_and_hash_drift_is_rejected(baseline, monkeypatch):
    m = implementation()
    home, database, state = baseline
    raw = synthetic_erp(monkeypatch, m)
    calls = serve_one(monkeypatch, m.ERP_URL, raw, retry=True)
    with pytest.raises(Exception):
        m.capture_erp(database)
    assert calls == [m.ERP_URL, m.ERP_URL]
    serve_one(monkeypatch, m.ERP_URL, raw + b"drift")
    with pytest.raises(ValueError):
        m.capture_erp(database)
    with closing(connect(database)) as db:
        assert db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 0


def invocation(state, output, mode="preview", fingerprint=""):
    return [
        "--state-dir",
        str(state),
        "--output",
        str(output),
        "--encrypted-state",
        "--recovery-storage=github-draft",
        "--publication-format=v2",
        "--maintenance-profile=switching-readiness-2026-11-09-v1",
        "--maintenance-mode=" + mode,
        *(["--maintenance-preview-fingerprint=" + fingerprint] if fingerprint else []),
    ]


def install_restore(monkeypatch, database):
    import shutil

    from infrastructure_impact.storage import remote_recovery
    from ops import hosted_job

    monkeypatch.setenv("IMPACT_STATE_KEY", "synthetic-key")
    monkeypatch.setattr(remote_recovery, "GitHubDraftStore", lambda *a: object())

    def restore(state, destination, *a, **k):
        destination.parent.mkdir(parents=True)
        shutil.copyfile(database, destination)
        return True

    monkeypatch.setattr(hosted_job, "restore_current", restore)


def test_main_preview_has_only_preview_effects_and_no_retrieval(baseline, monkeypatch, capsys):
    m = implementation()
    home, database, state = baseline
    authored_arista(database, m, monkeypatch)
    install_restore(monkeypatch, database)
    from infrastructure_impact.collection import transport
    from ops import hosted_job

    monkeypatch.setattr(transport, "fetch", lambda *a, **k: pytest.fail("vendor request"))
    monkeypatch.setattr(hosted_job, "backup_verified", lambda *a, **k: pytest.fail("backup"))
    effects = home.parent / "effects"
    monkeypatch.setenv("GITHUB_OUTPUT", str(effects))
    output = home.parent / "public"
    manifest = (state / "current.json").read_bytes()
    assert m.main(invocation(state, output)) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "preview"
    assert effects.read_text() == "mode=preview\npreview_ready=true\n"
    assert (state / "current.json").read_bytes() == manifest
    assert json.loads((output / "maintenance-preview.json").read_bytes())["target_count"] == 2


def test_main_stale_preview_blocks_preparation_and_sanitizes_errors(baseline, monkeypatch, capsys):
    m = implementation()
    home, database, state = baseline
    authored_arista(database, m, monkeypatch)
    install_restore(monkeypatch, database)
    monkeypatch.setattr(m, "reparse", lambda *a: pytest.fail("preparation before fingerprint"))
    output = home.parent / "public"
    assert m.main(invocation(state, output, "apply", "f" * 64)) == 1
    assert json.loads(capsys.readouterr().out)["stage"] == "preview"
    assert not output.exists()


@pytest.mark.parametrize("spaced", [True, False])
def test_entry_dispatch_accepts_both_profile_forms(spaced, monkeypatch):
    m = implementation()
    from ops import hosted_job

    values = (
        ["--maintenance-profile", m.PROFILE_ID]
        if spaced
        else ["--maintenance-profile=" + m.PROFILE_ID]
    )
    monkeypatch.setattr("sys.argv", ["hosted_job", *values])
    monkeypatch.setattr(m, "main", lambda argv: 37 if argv == values else 1)
    with pytest.raises(SystemExit) as exit:
        hosted_job.entrypoint()
    assert exit.value.code == 37


def test_stock_validation_entry_stays_stock(monkeypatch):
    implementation()
    from ops import hosted_job

    monkeypatch.setattr("sys.argv", ["hosted_job", "--validate-encrypted-state"])
    called = []
    monkeypatch.setattr(hosted_job, "main", lambda: called.append("stock"))
    hosted_job.entrypoint()
    assert called == ["stock"]


@pytest.mark.parametrize("mutation", ["missing", "facts", "bytes"])
def test_cached_anchor_is_required_and_cannot_change_facts(baseline, monkeypatch, mutation):
    m = implementation()
    home, database, state = baseline
    authored_arista(database, m, monkeypatch)
    with closing(connect(database)) as db, db:
        if mutation == "missing":
            db.execute("DELETE FROM revisions WHERE vendor='cisco'")
        elif mutation == "bytes":
            db.execute("UPDATE evidence SET raw=? WHERE id=3", (b"changed",))
        else:
            record = json.loads(
                db.execute("SELECT normalized FROM revisions WHERE vendor='cisco'").fetchone()[0]
            )
            record["title"] = "Unreviewed factual change"
            db.execute(
                "UPDATE revisions SET normalized=? WHERE vendor='cisco'", (json.dumps(record),)
            )
    with pytest.raises(ValueError):
        m.preview(database, state)


def authored_aruba(monkeypatch, m):
    from test_aruba_text_coverage import signed_text

    text = signed_text(excluded=True).decode().replace("ARUBA-PSA-2021-013", "ARUBA-PSA-2021-019")
    for old, new in zip([f"CVE-2021-9000{i}" for i in range(1, 5)], m.ARUBA_CVES[:4]):
        text = text.replace(old, new)
    text = text.replace(
        "CVE-2021-45046\nPublication Date:", "CVE-2021-45046, CVE-2021-45105\nPublication Date:"
    )
    raw = text.encode()
    monkeypatch.setattr(m, "ARUBA_SHA256", sha256(raw).hexdigest())
    return raw


def test_stock_preview_stage_and_fresh_worker_accept_authored_two_target_profile(
    baseline, monkeypatch
):
    m = implementation()
    home, database, state = baseline
    authored_arista(database, m, monkeypatch)
    from infrastructure_impact.adapters.common import assessment, base

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
    raw = authored_aruba(monkeypatch, m)
    calls = serve_one(monkeypatch, m.ARUBA_URL, raw)
    from infrastructure_impact.application import target_import, target_import_stage
    from infrastructure_impact.application.target_import_contracts import result_bytes

    selected = m.selected_profile()
    with m.profile_lookup(selected):
        accepted = target_import.preview(database, m.PROFILE_ID)
    output = home.parent / "stage"
    result = target_import_stage.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
        publication_format="v2",
    )
    assert result["outcome"] == "completed", result["failure_code"]
    result_bytes(result, selected=selected, publication_format="v2")
    assert calls == [m.ARUBA_URL]
    assert result["counters"]["http_attempts"] == 1
    assert result["targets"][1]["status"] == "unchanged"
    assert all(result["checks"].values())


@pytest.mark.parametrize("failure", ["candidate", "backup", "none"])
def test_apply_gates_publication_and_orders_recovery_effects(
    baseline, monkeypatch, capsys, failure
):
    m = implementation()
    home, database, state = baseline
    authored_arista(database, m, monkeypatch)
    raw = authored_aruba(monkeypatch, m)
    erp = synthetic_erp(monkeypatch, m)
    import io

    from test_target_import_stage import passing_verifier

    from infrastructure_impact.application import target_import_stage
    from infrastructure_impact.collection import transport
    from ops import hosted_job

    class Response(io.BytesIO):
        status = 200
        headers = {"Content-Type": "text/plain"}

    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            return Response({m.ERP_URL: erp, m.ARUBA_URL: raw}[request.full_url])

    monkeypatch.setattr(transport, "build_opener", lambda *a: Opener())

    def verify(*a, **k):
        if failure == "candidate":
            return {"audit_passed": False, "capacity_passed": False, "candidate_validated": False}
        result = passing_verifier(*a)
        result.update(schema_version=2, publication_format="v2")
        result["candidate"].update(
            archive_scope="snapshot-v1", representation="publication-v2-physical"
        )
        return result

    monkeypatch.setattr(target_import_stage, "verify", verify)
    install_restore(monkeypatch, database)
    output = home.parent / "public"
    effects = home.parent / "effects"
    monkeypatch.setenv("GITHUB_OUTPUT", str(effects))
    initial = m.preview(database, state)["fingerprint"]
    manifest = (state / "current.json").read_bytes()

    def backup(state, staged, key, **kwargs):
        assert not output.exists()
        if failure == "backup":
            raise ValueError("PRIVATE_EXCEPTION_SENTINEL")
        (state / "current.json").write_text('{"synthetic_promoted":true}')
        hosted_job.workflow_effect("recovery_ready")

    monkeypatch.setattr(hosted_job, "backup_verified", backup)
    assert m.main(invocation(state, output, "apply", initial)) == (0 if failure == "none" else 1)
    public = capsys.readouterr()
    assert "PRIVATE_EXCEPTION_SENTINEL" not in public.out + public.err
    assert calls == [m.ERP_URL, m.ARUBA_URL]
    if failure == "none":
        assert output.is_dir()
        assert effects.read_text() == "mode=apply\nrecovery_ready=true\npublish_ready=true\n"
        assert (state / "current.json").read_bytes() != manifest
    else:
        assert not output.exists()
        assert (state / "current.json").read_bytes() == manifest
        assert not effects.exists() or "publish_ready" not in effects.read_text()


def test_restore_pointer_drift_is_rejected_before_preview(baseline, monkeypatch, capsys):
    m = implementation()
    home, database, state = baseline
    authored_arista(database, m, monkeypatch)
    install_restore(monkeypatch, database)
    from ops import hosted_job

    original = hosted_job.restore_current

    def drift(*a, **k):
        restored = original(*a, **k)
        (state / "current.json").write_text('{"changed_during_restore":true}')
        return restored

    monkeypatch.setattr(hosted_job, "restore_current", drift)
    output = home.parent / "public"
    assert m.main(invocation(state, output)) == 1
    assert not output.exists()
    assert json.loads(capsys.readouterr().out)["stage"] == "restore"


def test_activation_refuses_non_remote_recovery_before_restore(baseline, monkeypatch, capsys):
    m = implementation()
    home, database, state = baseline
    install_restore(monkeypatch, database)
    (state / "current.json").write_text('{"storage_backend":"git"}')
    from ops import hosted_job

    monkeypatch.setattr(hosted_job, "restore_current", lambda *a, **k: pytest.fail("restore"))
    assert m.main(invocation(state, home.parent / "public")) == 1
    assert json.loads(capsys.readouterr().out)["stage"] == "controls"


def annotations(raw):
    return [
        json.loads(line.split("::", 2)[2]) for line in raw.splitlines() if line.startswith("::")
    ]


def test_private_diagnostics_annotations_use_only_existing_closed_projection(capsys):
    m = implementation()
    import sys

    with pytest.raises(ValueError):
        with m.private_diagnostics():
            print("PRIVATE_PATH_SENTINEL ::error::injected")
            print(
                json.dumps(
                    {
                        "event": "monitor_capacity",
                        "mode": "archive",
                        "reason": "part",
                        "resource": "v2_part",
                        "observed_bytes": 1024,
                        "limit_bytes": 512,
                        "path": "PRIVATE_RESOURCE_SENTINEL",
                    }
                )
            )
            print(
                json.dumps(
                    {
                        "event": "phase",
                        "phase": "publication.query",
                        "state": "completed",
                        "elapsed_seconds": 1.25,
                        "private": "PRIVATE_FIELD_SENTINEL",
                    }
                )
            )
            print(
                json.dumps(
                    {
                        "event": "phase",
                        "phase": "PRIVATE_PHASE_SENTINEL",
                        "state": "completed",
                        "elapsed_seconds": 1,
                    }
                )
            )
            print(
                json.dumps(
                    {
                        "event": "candidate_worker",
                        "state": "timeout",
                        "elapsed_seconds": 2400,
                        "returncode": 1,
                        "exception": "PRIVATE_EXCEPTION_SENTINEL",
                    }
                ),
                file=sys.stderr,
            )
            print(
                json.dumps(
                    {
                        "event": "candidate_worker",
                        "state": "PRIVATE_STATE_SENTINEL",
                        "elapsed_seconds": 1,
                    }
                )
            )
            raise ValueError("PRIVATE_EXCEPTION_SENTINEL")
    output = capsys.readouterr()
    assert output.out == ""
    assert "PRIVATE" not in output.err
    assert annotations(output.err) == [
        {
            "event": "monitor_capacity",
            "mode": "archive",
            "reason": "part",
            "resource": "v2_part",
            "observed_bytes": 1024,
            "limit_bytes": 512,
        },
        {
            "event": "phase",
            "phase": "publication.query",
            "state": "completed",
            "elapsed_seconds": 1.25,
        },
        {"event": "candidate_worker", "state": "timeout", "elapsed_seconds": 2400, "returncode": 1},
    ]


def test_diagnostics_input_event_and_numeric_limits_are_preserved(capsys):
    m = implementation()
    with m.private_diagnostics():
        for _ in range(50):
            print(
                json.dumps(
                    {
                        "event": "phase",
                        "phase": "publication.writing",
                        "state": "started",
                        "elapsed_seconds": 0,
                    }
                )
            )
        print(
            '{"event":"phase","phase":"publication.query","state":"started","elapsed_seconds":NaN}'
        )
        print(
            '{"event":"phase","phase":"publication.query","state":"started","elapsed_seconds":Infinity}'
        )
        print("x" * 65_536)
        print(
            json.dumps({"event": "candidate_worker", "state": "timeout", "elapsed_seconds": 2400})
        )
    output = capsys.readouterr()
    projected = annotations(output.err)
    assert len(projected) == 32
    assert len(output.err.encode()) < 16_384
    assert all(event["elapsed_seconds"] == 0 for event in projected)
    assert all(event["event"] == "phase" for event in projected)


def test_controls_error_has_closed_annotation_without_exception_text(monkeypatch, capsys):
    m = implementation()
    assert m.main(["--unknown=PRIVATE_ARGUMENT_SENTINEL"]) == 1
    output = capsys.readouterr()
    assert "PRIVATE" not in output.out + output.err
    assert annotations(output.err) == [
        {"event": "switching_activation", "outcome": "error", "stage": "controls"}
    ]
