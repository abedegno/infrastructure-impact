"""Synthetic-only retained diagnostics: private output must never become metadata."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ops import retained_preview_progress as progress

ROOT = Path(__file__).resolve().parents[1]


def phase(**extra):
    return dict(
        event="phase", phase="retained.sources", state="started", elapsed_seconds=0, **extra
    )


def test_private_logs_unknown_fields_and_forged_events_never_escape():
    projector = progress.Projector()
    lines = [
        b"PRIVATE stdout/stderr/path",
        json.dumps(phase(raw="PRIVATE")).encode(),
        json.dumps({**phase(), "phase": "PRIVATE"}).encode(),
        b'{"event":"phase","event":"sample"}',
        json.dumps(phase()).encode(),
    ]
    projector.feed(b"\n".join(lines) + b"\n", now=0)
    assert json.loads(projector.bytes()) == {"schema_version": 1, "events": [phase()]}
    assert b"PRIVATE" not in projector.bytes()


@pytest.mark.parametrize("mutation", ["unknown", "path", "line", "nan", "overflow", "bool"])
def test_progress_is_fresh_closed_and_numeric_bounded(mutation):
    value = {"schema_version": 1, "events": [phase()]}
    progress.progress_bytes(value)
    if mutation == "unknown":
        value["events"][0]["raw"] = "PRIVATE"
    elif mutation == "path":
        value["events"] = [
            dict(
                event="samples",
                total_samples=1,
                locations=[dict(file="../PRIVATE.py", line=1, count=1)],
            )
        ]
    elif mutation == "line":
        value["events"] = [
            dict(
                event="samples",
                total_samples=1,
                locations=[dict(file="ops/switching_fix_preview.py", line=10**9, count=1)],
            )
        ]
    else:
        value["events"][0]["elapsed_seconds"] = {
            "nan": float("nan"),
            "overflow": 86401,
            "bool": True,
        }[mutation]
    with pytest.raises((ValueError, TypeError)):
        progress.progress_bytes(value)


def test_frame_projection_reads_only_public_code_location():
    class Frame:
        f_code = SimpleNamespace(co_filename=str(ROOT / "ops/switching_fix_preview.py"))
        f_lineno = 1

        def __getattr__(self, name):
            pytest.fail("unexpected frame access: " + name)

    assert progress.frame_location(Frame()) == {"file": "ops/switching_fix_preview.py", "line": 1}
    frame = SimpleNamespace(f_code=SimpleNamespace(co_filename="/PRIVATE/customer.py"), f_lineno=99)
    assert progress.frame_location(frame) == {"file": "external", "line": 0}
    frame.f_code.co_filename = str(ROOT / "tests/test_retained_preview_progress.py")
    assert progress.frame_location(frame) == {"file": "external", "line": 0}
    import jsonschema

    frame.f_code.co_filename = jsonschema.__file__
    frame.f_lineno = 1
    assert progress.frame_location(frame) == {"file": "jsonschema/__init__.py", "line": 1}


def test_dedup_sampling_limit_top_three_and_aggregation_interval():
    projector = progress.Projector()
    projector.feed((json.dumps(phase()) + "\n").encode() * 50, now=0)
    for index in range(100):
        location = {"file": "ops/switching_fix_preview.py", "line": index % 4 + 1}
        projector.feed(json.dumps(dict(event="sample", **location)).encode() + b"\n", now=30)
    assert json.loads(projector.bytes())["events"] == [phase()]
    projector.flush_samples(now=120)
    events = json.loads(projector.bytes())["events"]
    assert events[1] == dict(
        event="samples",
        total_samples=80,
        locations=[dict(file="ops/switching_fix_preview.py", line=n, count=20) for n in (1, 2, 3)],
    )
    projector.flush_samples(now=121)
    assert json.loads(projector.bytes())["events"] == events
    assert len(projector.bytes()) <= 16384
    for index in range(100):
        projector.feed(
            json.dumps({**phase(), "state": "completed", "elapsed_seconds": index}).encode()
            + b"\n",
            now=240,
        )
    assert len(json.loads(projector.bytes())["events"]) <= 32


def test_progress_file_rejects_existing_symlink_ancestor_and_hostile_reads(tmp_path):
    path = tmp_path / "progress.json"
    writer = progress.ProgressFile(path)
    writer.write({"schema_version": 1, "events": [phase()]})
    assert progress.read_progress(path)["events"] == [phase()]
    with pytest.raises(ValueError):
        progress.ProgressFile(path)
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        progress.ProgressFile(link / "new.json")
    path.unlink()
    path.symlink_to(tmp_path / "private")
    with pytest.raises((ValueError, OSError)):
        progress.read_progress(path)
    path.unlink()
    path.write_bytes(b"x" * 16385)
    with pytest.raises(ValueError):
        progress.read_progress(path)


def test_worker_sampling_is_bounded_and_stops_without_frame_values():
    stream = io.StringIO()
    sampler = progress.Sampler(stream)
    for _ in range(100):
        sampler.sample(SimpleNamespace(f_code=SimpleNamespace(co_filename="PRIVATE"), f_lineno=1))
    assert len(stream.getvalue().splitlines()) == 80
    assert set(stream.getvalue().splitlines()) == {'{"event":"sample","file":"external","line":0}'}
    with sampler:
        pass
    assert not sampler.thread.is_alive()


def test_fixed_driver_does_not_offer_caller_command(tmp_path):
    run = subprocess.run(
        [sys.executable, "-m", "ops.retained_preview_progress", "--command", "PRIVATE"],
        capture_output=True,
    )
    assert run.returncode != 0
    output = tmp_path / "result.json"
    path = tmp_path / "progress.json"
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "ops.retained_preview_progress",
            "--database",
            str(tmp_path / "missing.sqlite3"),
            "--public",
            str(tmp_path / "public"),
            "--output",
            str(output),
            "--source-commit",
            "a" * 40,
            "--progress",
            str(path),
        ],
        capture_output=True,
    )
    assert run.returncode == 1
    assert json.loads(output.read_bytes())["failure_code"] == "database_missing"
    assert run.stdout == b""
    assert json.loads(path.read_bytes())["schema_version"] == 1


def test_fixed_child_private_output_and_cancel_cleanup(tmp_path, monkeypatch, capsys):
    original = subprocess.Popen
    children = []

    def synthetic(argv, **kwargs):
        assert argv[0] == sys.executable
        assert Path(argv[1]) == ROOT / "ops/switching_fix_preview.py"
        assert argv[-1] == "--diagnostic-sampling"
        child = original(
            [
                sys.executable,
                "-c",
                "import sys,time; print('PRIVATE stdout',flush=True); print('PRIVATE stderr',file=sys.stderr,flush=True); time.sleep(60)",
            ],
            **kwargs,
        )
        children.append(child)
        return child

    monkeypatch.setattr(progress.subprocess, "Popen", synthetic)
    monkeypatch.setattr(
        progress.time, "sleep", lambda _: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    with pytest.raises(KeyboardInterrupt):
        progress.run(
            tmp_path / "database",
            tmp_path / "public",
            tmp_path / "output",
            "a" * 40,
            tmp_path / "progress.json",
        )
    assert len(children) == 1 and children[0].poll() is not None
    captured = capsys.readouterr()
    assert "PRIVATE" not in captured.out + captured.err
    assert not (tmp_path / "output").exists()


def test_every_progress_boundary_and_poll_read_is_bounded(tmp_path):
    value = {"schema_version": 1, "events": [phase()] * 33}
    with pytest.raises(ValueError):
        progress.progress_bytes(value)
    projector = progress.Projector()
    with pytest.raises(ValueError):
        projector.feed(b"x" * 65537, now=0)
    # Neither a long line nor its suffix may become an event across reads.
    projector.feed(b"x" * 4096, now=0)
    projector.feed(json.dumps(phase()).encode() + b"\n", now=0)
    assert json.loads(projector.bytes())["events"] == []
    projector.feed((json.dumps(phase()) + "\n").encode(), now=0)
    assert json.loads(projector.bytes())["events"] == [phase()]
    path = tmp_path / "stale.json"
    path.write_bytes(projector.bytes())
    os.utime(path, (0, 0))
    with pytest.raises(ValueError):
        progress.read_progress(path)


def test_event_capacity_does_not_hide_later_samples():
    projector = progress.Projector()
    raw = b"".join(
        json.dumps(dict(event="phase", phase=name, state=state, elapsed_seconds=0)).encode() + b"\n"
        for name in sorted(progress.PHASES)
        for state in ("started", "completed", "failed")
    )
    projector.feed(raw, now=0)
    projector.feed(b'{"event":"sample","file":"external","line":0}\n', now=120)
    value = json.loads(projector.bytes())
    assert len(value["events"]) <= 32
    assert value["events"][-1] == dict(
        event="samples", total_samples=1, locations=[dict(file="external", line=0, count=1)]
    )


def test_owned_child_is_killed_if_it_ignores_termination():
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready',flush=True); time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
    )
    try:
        assert child.stdout.readline() == b"ready\n"
        progress._stop(child)
        assert child.poll() is not None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdout.close()


def test_fixed_child_logs_and_fake_events_cannot_be_exported(tmp_path, monkeypatch, capsys):
    original = subprocess.Popen
    payload = 'import sys; print(\'PRIVATE stdout\'); print(\'PRIVATE stderr\',file=sys.stderr); print(\'{"event":"phase","phase":"retained.sources","state":"started","elapsed_seconds":0,"raw":"PRIVATE"}\',file=sys.stderr); sys.exit(7)'
    monkeypatch.setattr(
        progress.subprocess,
        "Popen",
        lambda argv, **kwargs: original([sys.executable, "-c", payload], **kwargs),
    )
    output = tmp_path / "result.json"
    path = tmp_path / "progress.json"
    assert progress.run(tmp_path / "database", tmp_path / "public", output, "a" * 40, path) == 7
    captured = capsys.readouterr()
    assert "PRIVATE" not in captured.out + captured.err + path.read_text()
    assert not output.exists()


def test_driver_never_uses_result_or_database_as_progress_file(tmp_path):
    for name in ("output", "database"):
        protected = tmp_path / name
        with pytest.raises(ValueError):
            progress.run(
                tmp_path / "database", tmp_path / "public", tmp_path / "output", "a" * 40, protected
            )
        assert not protected.exists()


def test_progress_rejects_hardlink_and_replacement(tmp_path):
    path = tmp_path / "progress.json"
    writer = progress.ProgressFile(path)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b'{"schema_version":1,"events":[]}\n')
    path.unlink()
    os.link(replacement, path)
    with pytest.raises(ValueError):
        writer.write({"schema_version": 1, "events": []})
    with pytest.raises(ValueError):
        progress.read_progress(path)
