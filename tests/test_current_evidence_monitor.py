"""The actual read-only checker rejects incomplete synthetic HTTP publications."""

import functools
import hashlib
import json
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError

import pytest
from test_current_evidence_delivery import (  # noqa: F401
    arista_case,
    delivery_db,
)
from test_current_evidence_delivery import (
    delivery as _delivery,
)

from checks.public_health import check
from infrastructure_impact.application.publication import publish


def publish_monitored(data, root):
    data["benchmark_cohort"] = {"CVE-2024-6858": "Synthetic current monitor selection"}
    return publish(data, root)


delivery = _delivery


@contextmanager
def serving(directory):
    class Handler(SimpleHTTPRequestHandler):
        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=directory))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def rewrite(generation, path, value):
    raw = json.dumps(value).encode()
    (generation / path).write_bytes(raw)
    manifest_path = generation / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["sha256"][path] = hashlib.sha256(raw).hexdigest()
    manifest_path.write_text(json.dumps(manifest))


def rewrite_part(generation, index, descriptor, value):
    raw = json.dumps(value).encode()
    digest = hashlib.sha256(raw).hexdigest()
    path = "data/" + digest + ".json"
    descriptor.update(path=path, sha256=digest, bytes=len(raw))
    rewrite(generation, path, value)
    rewrite(generation, "data/index.json", index)


def test_monitor_rejects_new_capability_without_disposition_asset(delivery, tmp_path):
    # Removing the new asset gate would accept an incomplete candidate.
    accepted = publish_monitored(delivery, tmp_path / "accepted")
    candidate = publish_monitored(delivery, tmp_path / "candidate")
    before = {p.relative_to(accepted): p.read_bytes() for p in accepted.rglob("*") if p.is_file()}
    with serving(accepted) as origin:
        assert check(origin)["status"] == "fresh"
    (candidate / "current-evidence.json").unlink()
    with serving(candidate) as origin, pytest.raises((AssertionError, HTTPError)):
        check(origin)
    assert {
        p.relative_to(accepted): p.read_bytes() for p in accepted.rglob("*") if p.is_file()
    } == before
    with serving(accepted) as origin:
        assert check(origin)["current_evidence_counts"] == {
            "current": 2,
            "excluded": 1,
            "retained_total": 3,
        }


@pytest.mark.parametrize(
    "fault", ["union", "generation", "target", "retained_missing", "membership", "capability"]
)
def test_monitor_rejects_inconsistent_partition(delivery, tmp_path, fault):
    generation = publish_monitored(delivery, tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    capability = index["current_evidence"]
    if fault in ("union", "generation"):
        descriptor = capability["report"]
        value = json.loads((generation / descriptor["path"]).read_text())
        if fault == "union":
            value["data"]["counts"]["retained_total"] = 99
        else:
            value["data"]["publication"]["id"] = "0" * 32
        rewrite(generation, "current-evidence.json", value["data"])
        rewrite_part(generation, index, descriptor, value)
    elif fault == "target":
        descriptor = capability["retained"][0]["part"]
        value = json.loads((generation / descriptor["path"]).read_text())
        value["data"][0]["record"]["revision_id"] = "wrong-revision"
        rewrite_part(generation, index, descriptor, value)
    elif fault == "retained_missing":
        (generation / capability["retained"][0]["part"]["path"]).unlink()
    elif fault == "membership":
        capability["retained"][0]["decision_ids"] = []
        rewrite(generation, "data/index.json", index)
    else:
        del index["current_evidence"]
        rewrite(generation, "data/index.json", index)
    with serving(generation) as origin, pytest.raises((AssertionError, HTTPError)):
        check(origin)


def test_current_monitor_runs_without_installed_application(delivery, tmp_path):
    generation = publish_monitored(delivery, tmp_path)
    script = Path(__file__).resolve().parents[1] / "checks/public_health.py"
    with serving(generation) as origin:
        result = subprocess.run(
            [sys.executable, "-S", str(script), origin], capture_output=True, text=True
        )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["current_evidence_counts"]["excluded"] == 1


@pytest.mark.parametrize(
    ("branches", "value", "accepted"),
    [
        ([{"type": "integer"}, {"type": "string"}], 1, True),
        ([{"type": "integer"}, {"type": "string"}], True, False),
        ([{"type": "integer"}, {"type": "string"}], None, False),
        ([{"type": "integer"}, {"type": "number"}], 1, False),
    ],
)
def test_standalone_schema_requires_exactly_one_typed_alternative(branches, value, accepted):
    from checks.switching_health import validate_schema

    schemas = {"probe": {"oneOf": branches}, "kev-v1.json": {}}
    if accepted:
        validate_schema(value, "probe", schemas)
    else:
        with pytest.raises(AssertionError):
            validate_schema(value, "probe", schemas)


def test_monitor_rejects_missing_manifest_declared_index(delivery, tmp_path):
    generation = publish_monitored(delivery, tmp_path)
    (generation / "data/index.json").unlink()
    with serving(generation) as origin, pytest.raises((AssertionError, HTTPError)):
        check(origin)


@pytest.mark.parametrize("fault", ["current_overlap", "private_retained", "duplicate_retained"])
def test_no_index_snapshot_keeps_strict_partition_checks(delivery, tmp_path, fault):
    generation = publish_monitored(delivery, tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    (generation / "data/index.json").unlink()
    manifest_path = generation / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    del manifest["sha256"]["data/index.json"]
    manifest["sha256"].pop("snapshot.json.gz")
    manifest_path.write_text(json.dumps(manifest))
    data = json.loads((generation / "snapshot.json").read_text())
    if fault == "current_overlap":
        data["records"][0] = data["retained_advisories"][0]["record"]
    elif fault == "private_retained":
        data["retained_advisories"][0]["record"]["notes"] = ["SYNTHETIC PRIVATE SENTINEL"]
    else:
        data["retained_advisories"].append(data["retained_advisories"][0])
    rewrite(generation, "snapshot.json", data)
    assert index["current_evidence"]
    with serving(generation) as origin, pytest.raises(AssertionError):
        check(origin)


def test_no_index_report_cannot_disagree_with_manifest_without_eligibility(delivery, tmp_path):
    generation = publish_monitored(delivery, tmp_path)
    (generation / "data/index.json").unlink()
    manifest_path = generation / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    del manifest["sha256"]["data/index.json"]
    manifest["sha256"].pop("snapshot.json.gz")
    manifest["sha256"].pop("comparison-eligibility-summary.json")
    manifest["generation"] = "0" * 32
    manifest_path.write_text(json.dumps(manifest))
    data = json.loads((generation / "snapshot.json").read_text())
    # No unrelated eligibility summary can provide generation integrity for this fixture.
    data.pop("comparison_eligibility", None)
    data.pop("product_groups", None)
    rewrite(generation, "snapshot.json", data)
    with serving(generation) as origin, pytest.raises(AssertionError):
        check(origin)


def test_monitor_rejects_fresh_payload_with_stale_index_and_part_clocks(delivery, tmp_path):
    generation = publish_monitored(delivery, tmp_path)
    with serving(generation) as origin:
        assert check(origin)["status"] == "fresh"
    index = json.loads((generation / "data/index.json").read_text())
    stale = "2000-01-01T00:00:00+00:00"
    index["generated_at"] = stale
    rewritten = {}

    def stale_envelopes(value):
        if isinstance(value, list):
            for item in value:
                stale_envelopes(item)
        elif isinstance(value, dict):
            if set(value) == {"path", "sha256", "bytes"} and value["path"].startswith("data/"):
                original = value["path"]
                if original in rewritten:
                    value.update(rewritten[original])
                    return
                envelope = json.loads((generation / original).read_text())
                # Only publication envelope clocks change. The internally consistent
                # bootstrap/report payloads and source/publisher dates stay untouched.
                envelope["generated_at"] = stale
                rewrite_part(generation, index, value, envelope)
                rewritten[original] = dict(value)
            else:
                for item in value.values():
                    stale_envelopes(item)

    stale_envelopes(index)
    rewrite(generation, "data/index.json", index)
    with (
        serving(generation) as origin,
        pytest.raises(AssertionError, match="Mixed publication dates"),
    ):
        check(origin)
