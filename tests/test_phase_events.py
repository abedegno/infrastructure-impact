"""Phase receipts contain timing and static labels, including failure boundaries."""

import io
import json
import sys

import pytest

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
        assert set(event) == {"event", "phase", "state", "elapsed_seconds"}
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
