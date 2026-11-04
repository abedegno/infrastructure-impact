"""Synthetic stdlib monitor checks; full history is never a monitor dependency."""

import copy
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_static_delivery import dataset
from test_switching_delivery import FIXTURE

import checks.public_health as health
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.switching_comparison import summary
from infrastructure_impact.settings import PACKAGE

SCHEMAS = {
    p.name: json.loads(p.read_text()) for p in (PACKAGE / "schemas").glob("switching-*.json")
}
SCHEMAS["kev-v1.json"] = json.loads((PACKAGE / "schemas/kev-v1.json").read_text())


def validate(report):
    assert hasattr(health, "validate_switching_report"), "Missing standalone switching gate"
    health.validate_switching_report(
        report, report["publication"], FIXTURE["comparison_base_report"]["generated_at"], SCHEMAS
    )


def test_valid_incomplete_summary():
    report = summary(copy.deepcopy(FIXTURE["comparison_base_report"]))
    validate(report)
    assert report["rows"][0]["coverage"]["expected_advisories"] is None


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schema_version",), True),
        (("representation",), "full"),
        (("inputs",), {}),
        (("definition", "id"), "other-study"),
        (("definition", "version"), 999),
        (("selection", "definition_sha256"), "0" * 64),
        (("generated_at",), "2026-01-01T00:00:00Z"),
        (("evaluated_at",), "2026-01-01T00:00:00Z"),
        (("rows", 2, "counts", "advisories"), -1),
        (("rows", 2, "counts", "advisories"), True),
        (("rows", 2, "counts", "advisories"), 999),
        (("rows", 2, "coverage", "expected_advisories"), 999),
        (("sources", 0, "source_sha256"), "bad-hash"),
        (("sources", 0, "source_url"), "https://evil.example/source"),
        (("sources", 0, "retrieved_at"), "yesterday"),
        (("rows", 2, "kev", "listed_count"), 999),
    ],
)
def test_rejects_malformed_summary(path, value):
    report = summary(copy.deepcopy(FIXTURE["comparison_base_report"]))
    parent = report
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(AssertionError):
        validate(report)


def serve(monkeypatch, generation):
    requests = []

    class Response(io.BytesIO):
        status = 200

    def fetch(url, timeout=None):
        name = url.removeprefix("https://example.test/") or "index.html"
        requests.append(name)
        return Response((generation / name).read_bytes())

    monkeypatch.setattr(health, "urlopen", fetch)
    return requests


def test_monitor_reads_only_compact_study_and_rejects_tampering(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    requests = serve(monkeypatch, generation)
    result = health.check("https://example.test")
    assert result.get("switching_availability") == "available"
    assert result["checked_default_bytes"] <= 20_000_000
    index = json.loads((generation / "data/index.json").read_text())
    assert index["switching"]["summary"]["path"] in requests
    assert index["switching"]["inputs"]["path"] not in requests
    assert not {
        "snapshot.json",
        "snapshot.json.gz",
        "switching-evidence.json",
        "switching-comparison.json",
    } & set(requests)
    (generation / index["switching"]["summary"]["path"]).write_text("{}")
    with pytest.raises(AssertionError):
        health.check("https://example.test")


def test_legacy_index_without_study_is_healthy(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    index_path = generation / "data/index.json"
    index = json.loads(index_path.read_text())
    del index["switching"]
    index_path.write_text(json.dumps(index))
    manifest_path = generation / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["sha256"]["data/index.json"] = hashlib.sha256(index_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    serve(monkeypatch, generation)
    assert health.check("https://example.test")["switching_availability"] == "unavailable"


def test_gate_runs_without_installed_application():
    script = """
import json,runpy,sys
sys.path.insert(0, __import__('os').path.dirname(sys.argv[1]))
m=runpy.run_path(sys.argv[1]); r,s=json.load(sys.stdin)
assert 'validate_switching_report' in m, 'Missing standalone switching gate'
m['validate_switching_report'](r,r['publication'],r['generated_at'],s)
assert not any(n.startswith(('infrastructure_impact','jsonschema')) for n in sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-S", "-c", script, str(Path(health.__file__).resolve())],
        input=json.dumps([summary(FIXTURE["comparison_base_report"]), SCHEMAS]),
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr


def test_monitor_accepts_allowlisted_scores_but_rejects_private_fields(tmp_path, monkeypatch):
    from test_cvss_enrichment import V3, csaf, extract

    d = dataset()
    record = next(r for r in d["records"] if "CVE-2025-12345" in r["cves"])
    scores = extract(
        csaf(
            [
                {
                    "products": ["p"],
                    "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3},
                }
            ]
        )
    )
    for c in scores["claims"]:
        c["cve_id"] = record["cves"][0]
    d["research"]["score_input"] = {
        "advisories": [
            dict(
                vendor=record["vendor"], advisory_id=record["advisory_id"], claims=scores["claims"]
            )
        ]
    }
    generation = publish(d, tmp_path)
    serve(monkeypatch, generation)
    assert health.check("https://example.test")["status"] == "fresh"
    from checks.switching_health import validate_public_metrics

    public = json.loads((generation / "snapshot.json").read_text())
    retained = next(r for r in public["records"] if r["metrics"])
    retained["metrics"][0]["private"] = "SYNTHETIC PRIVATE SENTINEL"
    with pytest.raises(AssertionError):
        validate_public_metrics(retained)


def test_monitor_rejects_changed_detail_descriptor_without_loading_history(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    path = generation / "data/index.json"
    index = json.loads(path.read_text())
    index["switching"]["inputs"]["sha256"] = "f" * 64
    path.write_text(json.dumps(index))
    manifest_path = generation / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["sha256"]["data/index.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    serve(monkeypatch, generation)
    with pytest.raises(AssertionError):
        health.check("https://example.test")


def test_monitor_rejects_foreign_vendor_coverage_source():
    report = summary(copy.deepcopy(FIXTURE["comparison_base_report"]))
    source = dict(
        vendor="arista",
        source_url="https://www.arista.com/security/synthetic",
        state="partial",
        observed_start="2026-11-04",
        observed_end="2026-11-04",
        total=None,
        issues=["publisher_total_unknown"],
    )
    report["rows"][2]["coverage"]["sources"] = [source]
    validate(report)
    source["source_url"] = "https://www.cisco.com/security/synthetic"
    with pytest.raises(AssertionError):
        validate(report)
