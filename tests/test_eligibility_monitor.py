"""Synthetic bounded monitoring of complete eligibility gates, never case history."""

import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from test_static_delivery import dataset

import checks.public_health as health
from infrastructure_impact.application.publication import publish
from infrastructure_impact.http import Application
from infrastructure_impact.settings import PACKAGE

SUMMARY = "comparison-eligibility-summary.json"
DETAIL = "comparison-eligibility.json"
SCHEMA = "comparison-eligibility-summary-v1.json"


def rewrite(generation, name, value):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    (generation / name).write_bytes(raw)
    manifest = json.loads((generation / "manifest.json").read_text())
    manifest["sha256"][name] = hashlib.sha256(raw).hexdigest()
    (generation / "manifest.json").write_text(json.dumps(manifest))


def serve(monkeypatch, generation):
    reads, requests = [], []

    class Response(io.BytesIO):
        status = 200

        def read(self, size=-1):
            raw = super().read(size)
            reads.append(len(raw))
            return raw

    def fetch(url, timeout=None):
        name = url.removeprefix("https://example.test/") or "index.html"
        requests.append(name)
        if not (generation / name).is_file():
            raise HTTPError(url, 404, "Missing", {}, None)
        return Response((generation / name).read_bytes())

    monkeypatch.setattr(health, "urlopen", fetch)
    return requests, reads


def test_writer_emits_closed_summary_bound_to_exact_detail_and_native_routes(tmp_path):
    generation = publish(dataset(), tmp_path)
    assert (generation / SUMMARY).is_file(), "Writer must emit monitor summary"
    report = json.loads((generation / SUMMARY).read_text())
    detail_raw = (generation / DETAIL).read_bytes()
    detail = json.loads(detail_raw)
    snapshot = json.loads((generation / "snapshot.json").read_text())
    assert report["source_detail"] == {
        "path": DETAIL,
        "sha256": hashlib.sha256(detail_raw).hexdigest(),
    }
    assert detail == {
        **snapshot["comparison_eligibility"],
        "publication": snapshot["publication"],
        "generated_at": snapshot["generated_at"],
    }
    assert report["publication"] == snapshot["publication"] == detail["publication"]
    assert report["generated_at"] == snapshot["generated_at"] == detail["generated_at"]
    assert report["expected_vendor_ids"] == sorted(snapshot["vendors"])
    assert {v["vendor"] for v in report["vendors"]} == set(snapshot["vendors"])
    assert {v["vendor"]: v["eligibility"] for v in report["vendors"]} == {
        v["vendor"]: {
            key: v["eligibility"][key]
            for key in ("rate_comparison", "first_disclosure_comparison", "fix_timing_comparison")
        }
        for v in detail["vendors"]
    }
    assert set(report) == {
        "schema_version",
        "representation",
        "publication",
        "generated_at",
        "source_detail",
        "expected_vendor_ids",
        "vendors",
    }
    assert all(set(v) == {"vendor", "eligibility"} for v in report["vendors"])
    schema = json.loads((generation / "schemas" / SCHEMA).read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
    assert schema == json.loads((PACKAGE / "schemas" / SCHEMA).read_text())
    manifest = json.loads((generation / "manifest.json").read_text())
    app = Application(tmp_path)
    for name in (SUMMARY, DETAIL, "schemas/" + SCHEMA):
        code, _, raw = app.route(dict(REQUEST_METHOD="GET", PATH_INFO="/" + name))
        assert code == 200
        assert hashlib.sha256(raw).hexdigest() == manifest["sha256"][name]
    index = json.loads((generation / "data/index.json").read_text())
    bootstrap = json.loads((generation / index["bootstrap"]["path"]).read_text())["data"]
    assert "comparison_eligibility_summary" not in bootstrap


def test_large_detail_uses_compact_summary_and_counts_every_default_read(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    rewrite(generation, DETAIL, (generation / DETAIL).read_bytes() + b" " * 15_000_001)
    assert (generation / SUMMARY).is_file(), "Compact path missing"
    summary = json.loads((generation / SUMMARY).read_text())
    summary["source_detail"]["sha256"] = hashlib.sha256(
        (generation / DETAIL).read_bytes()
    ).hexdigest()
    rewrite(generation, SUMMARY, summary)
    requests, reads = serve(monkeypatch, generation)
    result = health.check("https://example.test")
    assert result["comparison_eligibility_verification"] == "compact_summary"
    assert DETAIL not in requests
    assert not {
        "snapshot.json",
        "snapshot.json.gz",
        "switching-evidence.json",
        "switching-comparison.json",
    } & set(requests)
    assert result["checked_default_bytes"] == sum(reads) < 20_000_000


def test_default_byte_count_includes_all_network_reads(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    _, reads = serve(monkeypatch, generation)
    result = health.check("https://example.test")
    assert result["checked_default_bytes"] == sum(reads)


def test_cumulative_small_reports_cannot_escape_aggregate_budget(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    for name in ("product-groups.json", "extraction-validation.json", "review-packet.json"):
        rewrite(generation, name, (generation / name).read_bytes() + b" " * 7_000_000)
    _, reads = serve(monkeypatch, generation)
    with pytest.raises(AssertionError, match="Default .*monitor budget"):
        health.check("https://example.test")
    assert sum(reads) <= 20_000_001


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "digest",
        "source_sha",
        "source_path",
        "publication",
        "generated_at",
        "schema_version",
        "extra",
        "private_gate",
        "vendor_extra",
        "vendor_missing",
        "vendor_duplicate",
        "expected_missing",
        "expected_duplicate",
        "expected_empty",
        "coordinated_membership",
        "rate_comparison",
        "first_disclosure_comparison",
        "fix_timing_comparison",
    ],
)
def test_declared_bad_summary_fails_without_detail_fallback(tmp_path, monkeypatch, fault):
    generation = publish(dataset(), tmp_path)
    assert (generation / SUMMARY).is_file(), "Compact path missing"
    report = json.loads((generation / SUMMARY).read_text())
    if fault == "missing":
        (generation / SUMMARY).unlink()
    elif fault == "digest":
        (generation / SUMMARY).write_text("{}")
    else:
        if fault == "source_sha":
            report["source_detail"]["sha256"] = "0" * 64
        elif fault == "source_path":
            report["source_detail"]["path"] = "snapshot.json"
        elif fault == "publication":
            report["publication"]["id"] = "different"
        elif fault == "generated_at":
            report["generated_at"] = "2020-01-01T00:00:00Z"
        elif fault == "schema_version":
            report["schema_version"] = True
        elif fault == "extra":
            report["cases"] = []
        elif fault == "private_gate":
            report["vendors"][0]["eligibility"]["raw_metrics"] = []
        elif fault == "vendor_extra":
            report["vendors"][0]["vendor"] = "unexpected-vendor"
        elif fault == "vendor_missing":
            report["vendors"].pop()
        elif fault == "vendor_duplicate":
            report["vendors"].append(report["vendors"][0])
        elif fault == "expected_missing":
            report["expected_vendor_ids"].pop()
        elif fault == "expected_duplicate":
            report["expected_vendor_ids"].append(report["expected_vendor_ids"][0])
        elif fault == "expected_empty":
            report["expected_vendor_ids"] = []
            report["vendors"] = []
        elif fault == "coordinated_membership":
            vendor = report["vendors"].pop()["vendor"]
            report["expected_vendor_ids"].remove(vendor)
        else:
            report["vendors"][0]["eligibility"][fault] = "allowed"
        rewrite(generation, SUMMARY, report)
    requests, _ = serve(monkeypatch, generation)
    with pytest.raises((AssertionError, HTTPError)):
        health.check("https://example.test")
    assert DETAIL not in requests


@pytest.mark.parametrize("oversized", [False, True])
def test_undeclared_legacy_report_is_checked_with_original_bound(tmp_path, monkeypatch, oversized):
    generation = publish(dataset(), tmp_path)
    manifest = json.loads((generation / "manifest.json").read_text())
    manifest["sha256"].pop(SUMMARY, None)
    (generation / "manifest.json").write_text(json.dumps(manifest))
    if oversized:
        rewrite(generation, DETAIL, (generation / DETAIL).read_bytes() + b" " * 15_000_001)
    requests, reads = serve(monkeypatch, generation)
    if oversized:
        with pytest.raises(AssertionError, match="monitor budget"):
            health.check("https://example.test")
    else:
        result = health.check("https://example.test")
        assert result["comparison_eligibility_verification"] == "legacy_full_report"
        assert result["checked_default_bytes"] == sum(reads)
    assert DETAIL in requests and SUMMARY not in requests


def test_explicit_archive_read_is_separate_from_default_accounting(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    requests, reads = serve(monkeypatch, generation)
    result = health.check("https://example.test", verify_archive=True)
    assert requests[-1] == "snapshot.json.gz"
    assert result["checked_compressed_archive_bytes"] == reads[-1]
    assert result["checked_default_bytes"] == sum(reads[:-1])
    assert result["compressed_archive_verified"] is True


def test_summary_gate_runs_without_installed_application(tmp_path):
    generation = publish(dataset(), tmp_path)
    script = """
import json, runpy, sys
sys.path.insert(0, __import__('os').path.dirname(sys.argv[1]))
m = runpy.run_path(sys.argv[1]); r, d, h = json.load(sys.stdin)
assert 'validate_eligibility_summary' in m, 'Missing standalone eligibility gate'
m['validate_eligibility_summary'](r, d['publication'], d['generated_at'], d['vendors'], h)
assert not any(n.startswith(('infrastructure_impact', 'jsonschema')) for n in sys.modules)
"""
    assert (generation / SUMMARY).is_file(), "Compact path missing"
    result = subprocess.run(
        [sys.executable, "-S", "-c", script, str(Path(health.__file__).resolve())],
        input=json.dumps(
            [
                json.loads((generation / SUMMARY).read_text()),
                json.loads((generation / "snapshot.json").read_text()),
                hashlib.sha256((generation / DETAIL).read_bytes()).hexdigest(),
            ]
        ),
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("fault", ["missing_vendor", "duplicate_vendor", "gate", "case_gate"])
def test_invalid_full_report_cannot_replace_current_generation(tmp_path, monkeypatch, fault):
    import infrastructure_impact.application.publication as publication

    previous = publish(dataset(), tmp_path)
    original = publication.eligibility

    def invalid(*args, **kwargs):
        report = original(*args, **kwargs)
        if fault == "missing_vendor":
            report["vendors"].pop()
        elif fault == "duplicate_vendor":
            report["vendors"].append(report["vendors"][0])
        elif fault == "gate":
            report["vendors"][0]["eligibility"]["rate_comparison"] = "allowed"
        else:
            report["vendors"][0]["cases"][0]["verified_fix_delay_days"] = 0
        return report

    monkeypatch.setattr(publication, "eligibility", invalid)
    with pytest.raises((ValueError, ValidationError)):
        publish(dataset(), tmp_path)
    assert (tmp_path / "current").resolve() == previous
    assert not list((tmp_path / "generations").glob(".staging-*"))


def test_legacy_snapshot_counts_implicit_archive_in_default_budget(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    (generation / "data/index.json").unlink()
    # A genuine no-index generation does not declare a missing index asset.
    manifest_path = generation / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    del manifest["sha256"]["data/index.json"]
    manifest_path.write_text(json.dumps(manifest))
    requests, reads = serve(monkeypatch, generation)
    result = health.check("https://example.test")
    assert result["delivery"] == "legacy_snapshot"
    assert "snapshot.json" in requests and "snapshot.json.gz" in requests
    assert result["checked_default_bytes"] == sum(reads)
    assert result["compressed_archive_verified"] is True
