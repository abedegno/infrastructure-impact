"""Phase receipts contain timing and static labels, including failure boundaries."""

import io
import json
import math
import sys

import pytest
from jsonschema.exceptions import ValidationError

from infrastructure_impact import phase_events
from infrastructure_impact.application import jobs, publication, query
from infrastructure_impact.storage.repository import connect
from ops import hosted_job


class FlushedEvents(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushed = []

    def flush(self):
        self.flushed.append(self.getvalue())


def events(sink):
    result = [json.loads(line) for line in sink.getvalue().splitlines()]
    for event in result:
        expected = {"event", "phase", "state", "elapsed_seconds"}
        if event["state"] == "failed":
            expected.add("failure_code")
        try:
            phase_events.process_time()
        except (NotImplementedError, OSError, ValueError):
            pass
        else:
            expected.add("process_cpu_seconds")
        if phase_events.resource is not None and sys.platform in ("darwin", "linux"):
            expected.add("peak_resident_bytes")
        assert set(event) == expected
        if "process_cpu_seconds" in event:
            assert math.isfinite(event["process_cpu_seconds"])
            assert 0 <= event["process_cpu_seconds"] <= 86_400
        if "peak_resident_bytes" in event:
            assert type(event["peak_resident_bytes"]) is int
            assert 0 <= event["peak_resident_bytes"] <= 2**50
        assert event["event"] == "phase"
        assert event["state"] in {"started", "completed", "failed"}
        assert 0 <= event["elapsed_seconds"] < 60
    return result


@pytest.mark.parametrize(
    "failed_phase", [None, "collection.sync", "collection.benchmark", "report", "publication.build"]
)
def test_job_receipts_flush_and_stop_at_failure(tmp_path, monkeypatch, failed_phase):
    sink = FlushedEvents()
    monkeypatch.setattr(sys, "stderr", sink)
    reached = []

    def run(label, result=None):
        reached.append(label)
        if label == failed_phase:
            raise RuntimeError("PRIVATE SYNTHETIC FAILURE DETAIL")
        return result

    args = [
        lambda: run("collection.sync", (2, 0)),
        lambda: run("collection.benchmark", (3, 0)),
        lambda: run("report"),
        lambda: run("publication.build"),
    ]
    if failed_phase:
        with pytest.raises(RuntimeError, match="PRIVATE SYNTHETIC"):
            jobs.execute(*args, db_path=tmp_path / "vault.sqlite3")
    else:
        assert jobs.execute(*args, db_path=tmp_path / "vault.sqlite3")["imported"] == 5
    receipt = events(sink)
    assert [e["phase"] for e in receipt[::2]] == reached
    assert len(receipt) == 2 * len(reached)
    assert [e["state"] for e in receipt[::2]] == ["started"] * len(reached)
    assert receipt[-1]["state"] == ("failed" if failed_phase else "completed")
    assert len(sink.flushed) == len(receipt)
    assert all(value.endswith("\n") for value in sink.flushed)
    assert "PRIVATE SYNTHETIC" not in sink.getvalue()


def test_query_projection_writer_and_backup_failures_have_bounded_receipts(tmp_path, monkeypatch):
    sink = FlushedEvents()
    monkeypatch.setattr(sys, "stderr", sink)
    db = connect(":memory:")
    data = query.state(db)
    assert data["records"] == []
    with pytest.raises((KeyError, TypeError)):
        publication.public_projection({"PRIVATE SYNTHETIC": "payload"})
    with pytest.raises((KeyError, TypeError)):
        publication.write_bundle(tmp_path / "invalid", {})
    with pytest.raises(Exception):
        hosted_job.backup(tmp_path / "backup", tmp_path / "missing.sqlite3")
    receipt = events(sink)
    assert [(e["phase"], e["state"]) for e in receipt] == [
        ("publication.query", "started"),
        ("publication.query", "completed"),
        ("publication.projection", "started"),
        ("publication.projection", "failed"),
        ("publication.writing", "started"),
        ("publication.writing", "failed"),
        ("backup.local", "started"),
        ("backup.local", "failed"),
    ]
    assert "PRIVATE SYNTHETIC" not in sink.getvalue()
    assert str(tmp_path) not in sink.getvalue()
    db.close()


@pytest.mark.parametrize(
    "platform,rss,expected", [("darwin", 4096, 4096), ("linux", 4096, 4194304)]
)
def test_phase_resources_use_process_cpu_and_platform_rss_units(
    monkeypatch, capsys, platform, rss, expected
):
    from types import SimpleNamespace

    ticks = iter([10.0, 10.25, 11.5])
    monkeypatch.setattr(phase_events, "process_time", lambda: next(ticks), raising=False)
    monkeypatch.setattr(phase_events.sys, "platform", platform)

    def usage(who):
        assert who == 0
        return SimpleNamespace(ru_maxrss=rss)

    monkeypatch.setattr(phase_events, "resource", SimpleNamespace(RUSAGE_SELF=0, getrusage=usage))
    with phase_events.phase("publication.query"):
        pass
    receipt = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert [event["process_cpu_seconds"] for event in receipt] == [0.25, 1.5]
    assert [event["peak_resident_bytes"] for event in receipt] == [expected, expected]


@pytest.mark.parametrize("rss", [True, -1, float("nan"), float("inf"), 10**1000])
def test_phase_omits_invalid_resource_measurements(monkeypatch, capsys, rss):
    from types import SimpleNamespace

    monkeypatch.setattr(
        phase_events,
        "resource",
        SimpleNamespace(RUSAGE_SELF=0, getrusage=lambda who: SimpleNamespace(ru_maxrss=rss)),
    )
    with phase_events.phase("publication.query"):
        pass
    receipt = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert all("peak_resident_bytes" not in event for event in receipt)
    assert receipt[-1]["state"] == "completed"


def test_phase_resource_unavailable_does_not_fail_operation(monkeypatch, capsys):
    monkeypatch.setattr(phase_events, "resource", None, raising=False)
    with phase_events.phase("publication.query"):
        pass
    receipt = events(io.StringIO(capsys.readouterr().err))
    assert all("peak_resident_bytes" not in event for event in receipt)
    assert receipt[-1]["state"] == "completed"


def test_phase_resource_platform_error_does_not_fail_operation(monkeypatch, capsys):
    def unavailable(who):
        raise NotImplementedError("PRIVATE PLATFORM DETAIL")

    from types import SimpleNamespace

    monkeypatch.setattr(
        phase_events, "resource", SimpleNamespace(RUSAGE_SELF=0, getrusage=unavailable)
    )
    with phase_events.phase("publication.query"):
        pass
    receipt = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert all("peak_resident_bytes" not in event for event in receipt)
    assert receipt[-1]["state"] == "completed"


def test_phase_cpu_unavailable_does_not_fail_operation(monkeypatch, capsys):
    def unavailable():
        raise NotImplementedError("PRIVATE PLATFORM DETAIL")

    monkeypatch.setattr(phase_events, "process_time", unavailable)
    with phase_events.phase("publication.query"):
        pass
    receipt = events(io.StringIO(capsys.readouterr().err))
    assert all("process_cpu_seconds" not in event for event in receipt)
    assert receipt[-1]["state"] == "completed"


@pytest.mark.parametrize(
    "error,code",
    [
        (ValueError("stream deadline"), "stream_deadline"),
        (ValueError("decoded byte budget"), "byte_budget"),
        (ValueError("native switching query mismatch"), "query_mismatch"),
        (ValidationError("PRIVATE SCHEMA DETAIL"), "schema"),
        (MemoryError("PRIVATE MEMORY DETAIL"), "memory"),
        (RecursionError("PRIVATE RECURSION DETAIL"), "recursion"),
        (RuntimeError("PRIVATE/path/token"), "unclassified"),
        (ValueError("PRIVATE/path/token stream deadline"), "unclassified"),
    ],
)
def test_failed_phase_has_only_closed_failure_code(error, code, capsys):
    from infrastructure_impact.application.import_candidate import parse_worker_diagnostics

    with pytest.raises(type(error)) as caught:
        with phase_events.phase("publication.native_queries"):
            raise error
    assert caught.value is error
    raw = capsys.readouterr().err
    event = json.loads(raw.splitlines()[-1])
    assert event["failure_code"] == code
    sanitized = parse_worker_diagnostics(raw.encode())
    assert sanitized[-1]["failure_code"] == code
    assert "PRIVATE" not in raw and "PRIVATE" not in json.dumps(sanitized)


def test_diagnostic_parser_drops_untrusted_failure_code():
    from infrastructure_impact.application.import_candidate import parse_worker_diagnostics

    event = dict(
        event="phase",
        phase="publication.native_queries",
        state="failed",
        elapsed_seconds=1,
        failure_code="PRIVATE/token",
    )
    value = parse_worker_diagnostics(json.dumps(event).encode())
    assert len(value) == 1
    assert "failure_code" not in value[0]
    assert "PRIVATE" not in json.dumps(value)


def test_phase_does_not_format_unknown_exception(capsys):
    class PrivateError(Exception):
        def __str__(self):
            raise AssertionError("Exception details must not be formatted")

    with pytest.raises(PrivateError):
        with phase_events.phase("publication.native_queries"):
            raise PrivateError()
    assert json.loads(capsys.readouterr().err.splitlines()[-1])["failure_code"] == "unclassified"


def test_real_decoder_deadline_is_reported_without_traceback(capsys):
    from infrastructure_impact import publication_codec as codec
    from infrastructure_impact.application.import_candidate import parse_worker_diagnostics

    with pytest.raises(ValueError, match="stream deadline"):
        with phase_events.phase("publication.native_queries"):
            list(codec.stream_tokens([-2], ["vendor text"], [], budget=codec.Budget(deadline=0)))
    raw = capsys.readouterr().err
    assert parse_worker_diagnostics(raw.encode())[-1]["failure_code"] == "stream_deadline"
    assert "Traceback" not in raw and "vendor text" not in raw


@pytest.mark.parametrize("label", ["publication.native_expected", "publication.native_reader"])
def test_native_subphase_diagnostics_accept_only_static_numeric_metadata(label, capsys):
    from infrastructure_impact.application.import_candidate import parse_worker_diagnostics

    with phase_events.phase(label):
        pass
    raw = capsys.readouterr().err
    accepted = parse_worker_diagnostics(raw.encode())
    assert [e["state"] for e in accepted] == ["started", "completed"]
    assert all(e["phase"] == label for e in accepted)
    event = json.loads(raw.splitlines()[-1])
    event["private"] = "PRIVATE/CVE-2099-1234/https://example.test"
    assert "PRIVATE" not in json.dumps(parse_worker_diagnostics(json.dumps(event).encode()))
    for field, value in (
        ("phase", label + ".unknown"),
        ("elapsed_seconds", "PRIVATE"),
        ("elapsed_seconds", True),
        ("elapsed_seconds", float("nan")),
    ):
        assert parse_worker_diagnostics(json.dumps({**event, field: value}).encode()) == []
