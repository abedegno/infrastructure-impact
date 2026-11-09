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
    arista_case as _arista_case,
)
from test_current_evidence_delivery import (
    delivery as _delivery,
)
from test_current_evidence_delivery import (
    delivery_db as _delivery_db,
)

from checks.public_health import check
from infrastructure_impact.application.publication import publish


def publish_monitored(data, root):
    data["benchmark_cohort"] = {"CVE-2024-6858": "Synthetic current monitor selection"}
    return publish(data, root)


delivery = _delivery
arista_case = _arista_case
delivery_db = _delivery_db


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


@pytest.mark.parametrize(
    ("boundary", "version"),
    [
        (boundary, version)
        for boundary in ("index", "bootstrap", "records", "report", "retained")
        for version in (True, "1", 3 if boundary == "index" else 2)
    ],
)
@pytest.mark.parametrize("switching", [True, False])
def test_monitor_browser_reject_same_invalid_transport_versions(
    delivery, tmp_path, version, boundary, switching
):
    """Python equality must not accept a version rejected by the real JS transport."""
    assert_monitor_browser_reject_version(delivery, tmp_path, version, boundary, switching)


@pytest.mark.parametrize("switching", [True, False])
def test_monitor_browser_reject_v1_index_mislabeled_as_v2(delivery, tmp_path, switching):
    # Version 2 is supported, but changing the header cannot supply its required assets.
    assert_monitor_browser_reject_version(
        delivery, tmp_path, 2, "index", switching, expected_error=(AssertionError, HTTPError)
    )


def assert_monitor_browser_reject_version(
    delivery, tmp_path, version, boundary, switching, *, expected_error=AssertionError
):
    from infrastructure_impact.settings import PACKAGE

    generation = publish_monitored(delivery, tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    if not switching:
        index.pop("switching", None)
        rewrite(generation, "data/index.json", index)
    script = r"""
const fs=require('fs'),vm=require('vm'),{webcrypto}=require('crypto');
const [root,web]=process.argv.slice(1),c={window:{},Response,TextEncoder,TextDecoder,Uint8Array,crypto:webcrypto};
vm.createContext(c);for(const f of ['lossless-json.js','publication-v2.js','switching-contracts.js','current-evidence.js','delivery.js'])vm.runInContext(fs.readFileSync(web+'/'+f,'utf8'),c);
(async()=>{try{const load=await c.createStaticDelivery(async p=>new Response(fs.readFileSync(root+p)),'/');await load(['CVE-2024-6858']);await load.retained();console.log('accepted');}catch(e){console.log('rejected');}})();
"""

    def browser():
        return subprocess.check_output(
            ["node", "-e", script, str(generation), str(PACKAGE / "web")], text=True
        ).strip()

    assert browser() == "accepted"
    with serving(generation) as origin:
        assert check(origin)["status"] == "fresh"
    if boundary == "index":
        index["schema_version"] = version
        rewrite(generation, "data/index.json", index)
    else:
        descriptor = {
            "bootstrap": index["bootstrap"],
            "records": index["cohorts"]["CVE-2024-6858"][0],
            "report": index["current_evidence"]["report"],
            "retained": index["current_evidence"]["retained"][0]["part"],
        }[boundary]
        old_path = descriptor["path"]
        envelope = json.loads((generation / old_path).read_text())
        envelope["schema_version"] = version
        rewrite_part(generation, index, descriptor, envelope)
        # Every duplicate descriptor for the same cohort part follows the replacement.
        for descriptors in index["cohorts"].values():
            for item in descriptors:
                if item["path"] == old_path:
                    item.update(descriptor)
        rewrite(generation, "data/index.json", index)
    assert browser() == "rejected"
    with serving(generation) as origin, pytest.raises(expected_error) as rejected:
        check(origin)
    if isinstance(rejected.value, HTTPError):
        assert rejected.value.code == 404
        # The mislabeled index is rejected before its publication catalog is opened.
        assert rejected.value.url == origin + "/schemas/static-index-v2.json"


def test_monitor_validates_root_report_types_before_index_equality(delivery, tmp_path):
    generation = publish_monitored(delivery, tmp_path)
    with serving(generation) as origin:
        assert check(origin)["status"] == "fresh"
    report = json.loads((generation / "current-evidence.json").read_text())
    report["schema_version"] = True
    rewrite(generation, "current-evidence.json", report)
    with serving(generation) as origin, pytest.raises(AssertionError):
        check(origin)


@pytest.fixture
def retained_only_delivery(arista_case):
    from test_arista_current_evidence import CSAF, URL, alternate_bytes, primary_bytes

    from infrastructure_impact.application.query import state
    from infrastructure_impact.collection.service import resolve_document, retain_resolution
    from infrastructure_impact.plugins.shared import structured
    from infrastructure_impact.storage.repository import connect, ingest

    registry = arista_case["registry"]
    primary, alternate = primary_bytes(), alternate_bytes()
    with connect(":memory:") as db:
        legacy = registry.finalize(structured(alternate, CSAF, "arista"), CSAF, "arista")
        ingest(db, alternate, CSAF, lambda *_: legacy, "arista")
        ingest(db, primary, URL, registry.normalize, "arista")
        resolution = resolve_document(
            db,
            URL,
            "arista",
            fetcher=lambda _db, url, _vendor: primary if url == URL else alternate,
        )
        retain_resolution(db, "arista", URL, resolution)
        return state(db, ["CVE-2024-6858"])


@pytest.mark.parametrize("delivery_mode", ["parts", "full"])
def test_monitor_keeps_kev_context_for_retained_only_cve(
    retained_only_delivery, tmp_path, delivery_mode
):
    generation = publish_monitored(retained_only_delivery, tmp_path)
    data = json.loads((generation / "snapshot.json").read_text())
    assert data["all_cves"] == ["CVE-2024-6858"]
    assert set(data["benchmark_cohort"]) == {"CVE-2024-6858"}
    assert data["kev"]["selection"]["requested_cve_ids"] == ["CVE-2023-5501", "CVE-2024-6858"]
    if delivery_mode == "full":
        (generation / "data/index.json").unlink()
        manifest = json.loads((generation / "manifest.json").read_text())
        del manifest["sha256"]["data/index.json"]
        (generation / "manifest.json").write_text(json.dumps(manifest))
    with serving(generation) as origin:
        health = check(origin)
    assert health["status"] == "fresh"
    assert health["current_evidence_counts"] == {"current": 1, "excluded": 1, "retained_total": 2}


@pytest.mark.parametrize("fault", ["missing_retained", "extra_unproven"])
def test_monitor_rejects_kev_scope_not_bound_to_retained_records(
    retained_only_delivery, tmp_path, fault
):
    from infrastructure_impact.application.kev import select_report

    generation = publish_monitored(retained_only_delivery, tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    bootstrap = json.loads((generation / index["bootstrap"]["path"]).read_text())
    scope = (
        ["CVE-2024-6858"]
        if fault == "missing_retained"
        else ["CVE-2023-5501", "CVE-2024-6858", "CVE-2099-99999"]
    )
    report = select_report(bootstrap["data"]["kev"], scope, evaluated_at=bootstrap["generated_at"])
    bootstrap["data"]["kev"] = report
    if fault == "extra_unproven":
        # An unbound metadata claim must not authorize an extra KEV CVE.
        bootstrap["data"]["retained_cves"].append("CVE-2099-99999")
    rewrite(generation, "kev.json", report)
    rewrite_part(generation, index, index["bootstrap"], bootstrap)
    with (
        serving(generation) as origin,
        pytest.raises(AssertionError, match="KEV selection differs from publication scope"),
    ):
        check(origin)
