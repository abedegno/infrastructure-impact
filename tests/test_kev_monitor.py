"""Standard-library KEV health gates over synthetic public reports."""

import copy
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_kev import BASE
from test_static_delivery import dataset

import checks.public_health as health
from infrastructure_impact.application.publication import publish

CID = "CVE-2024-6387"
OUTSIDE = "CVE-2099-99999"


def validate(report):
    # Removing this monitor gate must reject malformed publications in integration too.
    assert hasattr(health, "validate_kev_report"), "Missing standalone KEV report gate"
    health.validate_kev_report(report, BASE["publication"], BASE["generated_at"], [CID])


def test_valid_retained_report():
    validate(copy.deepcopy(BASE))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schema_version",), True),
        (("extra",), "unreviewed"),
        (("publication", "id"), "wrong-generation"),
        (("generated_at",), "2026-11-01T12:00:00Z"),
        (("evaluated_at",), "2026-11-03T12:00:00Z"),
        (("source", "id"), "other-source"),
        (("source", "retrieval_url"), "https://example.test/other.json"),
        (("source", "configured"), 1),
        (("source", "availability"), "stale"),
        (("source", "checked_at"), "2026-02-30T12:00:00Z"),
        (("source", "latest_attempt", "error_code"), {}),
        (("catalogue", "sha256"), "wrong-hash"),
        (("catalogue", "count"), 1),
        (("catalogue", "parser_version"), True),
        (("policy", "max_entries"), 20001),
        (("listed_cve_ids",), [OUTSIDE, CID]),
        (("listed_cve_ids",), [CID, CID]),
        (("listed_cve_ids",), [CID, "cve-2099-99999"]),
        (("entries", CID, "cveID"), OUTSIDE),
        (("entries", CID, "dateAdded"), "2026-02-30"),
        (("entries", CID, "cwes"), "CWE-362"),
        (("entries", CID, "extra"), "unreviewed"),
        (("selection", "membership", CID), "not_listed"),
        (("selection", "membership", OUTSIDE), "listed"),
        (("selection", "requested_cve_ids"), [CID, CID]),
        (("selection", "effective_cve_ids"), []),
    ],
)
def test_rejects_malformed_report(path, value):
    report = copy.deepcopy(BASE)
    parent = report
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(AssertionError):
        validate(report)


@pytest.mark.parametrize("field", list(BASE))
def test_rejects_missing_required_field(field):
    report = copy.deepcopy(BASE)
    del report[field]
    with pytest.raises(AssertionError):
        validate(report)


def test_rejects_out_of_scope_details_even_when_indexed():
    report = copy.deepcopy(BASE)
    report["entries"][OUTSIDE] = dict(report["entries"][CID], cveID=OUTSIDE)
    with pytest.raises(AssertionError):
        validate(report)


@pytest.mark.parametrize(
    "availability", ["failed", "stale", "future", "disabled", "not_configured", "missing"]
)
def test_unknown_membership_is_healthy(availability):
    report = copy.deepcopy(BASE)
    source = report["source"]
    source["availability"] = availability
    if availability == "failed":
        source["latest_attempt"]["outcome"] = "error"
    elif availability == "stale":
        source["checked_at"] = "2026-10-30T12:00:00Z"
    elif availability == "future":
        source["checked_at"] = "2026-11-02T12:05:01Z"
    elif availability == "disabled":
        source["enabled"] = False
    elif availability == "not_configured":
        source["configured"] = False
    else:
        source.update(configured=None, enabled=None, checked_at=None, latest_attempt=None)
        report.update(catalogue=None, listed_cve_ids=[], entries={})
    report["selection"]["membership"][CID] = "unknown"
    validate(report)


def serve(monkeypatch, generation):
    class Response(io.BytesIO):
        status = 200

    monkeypatch.setattr(
        health,
        "urlopen",
        lambda url, timeout=None: Response(
            (generation / (url.removeprefix("https://example.test/") or "index.html")).read_bytes()
        ),
    )


def test_monitor_checks_report_and_manifest_fingerprint(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    serve(monkeypatch, generation)
    result = health.check("https://example.test")
    assert result.get("kev_availability") == "missing"
    (generation / "kev.json").write_text("{}")
    with pytest.raises(AssertionError, match="Fingerprint"):
        health.check("https://example.test")


def test_monitor_rejects_fingerprinted_but_malformed_report(tmp_path, monkeypatch):
    generation = publish(dataset(), tmp_path)
    serve(monkeypatch, generation)
    raw = b"{}"
    (generation / "kev.json").write_bytes(raw)
    manifest = json.loads((generation / "manifest.json").read_text())
    manifest["sha256"]["kev.json"] = hashlib.sha256(raw).hexdigest()
    (generation / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(AssertionError):
        health.check("https://example.test")


def test_kev_gate_runs_without_site_packages(tmp_path):
    script = Path(health.__file__).resolve()
    probe = """
import json, runpy, sys
module = runpy.run_path(sys.argv[1])
assert 'validate_kev_report' in module, 'Missing standalone KEV report gate'
r = json.loads(sys.stdin.read())
module['validate_kev_report'](r, r['publication'], r['generated_at'], ['CVE-2024-6387'])
assert not any(n.startswith(('infrastructure_impact', 'jsonschema')) for n in sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-S", "-c", probe, str(script)],
        input=json.dumps(BASE),
        text=True,
        capture_output=True,
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr


def test_rejects_selection_that_silently_drops_publication_scope():
    report = copy.deepcopy(BASE)
    report["selection"] = dict(
        requested_cve_ids=[], effective_cve_ids=[], kev_only=False, membership={}
    )
    with pytest.raises(AssertionError):
        validate(report)


def test_rejects_selection_that_adds_out_of_scope_identity():
    report = copy.deepcopy(BASE)
    report["selection"] = dict(
        requested_cve_ids=[CID, OUTSIDE],
        effective_cve_ids=[CID, OUTSIDE],
        kev_only=False,
        membership={CID: "listed", OUTSIDE: "listed"},
    )
    with pytest.raises(AssertionError):
        validate(report)


def test_delivery_budget_contract_is_preserved():
    from infrastructure_impact.application.static_delivery import (
        MAX_INDEX_BYTES,
        MAX_PART_BYTES,
        TARGET_BYTES,
    )

    assert (TARGET_BYTES, MAX_PART_BYTES, MAX_INDEX_BYTES) == (512_000, 8_000_000, 2_000_000)


@pytest.mark.parametrize("fault", ["index", "part", "default_cohort"])
def test_monitor_keeps_existing_delivery_bounds(tmp_path, monkeypatch, fault):
    generation = publish(dataset(), tmp_path)
    manifest_path = generation / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    index_path = generation / "data/index.json"
    index = json.loads(index_path.read_text())
    if fault == "index":
        index_path.write_bytes(b" " * 2_000_001)
        message = "Publication part exceeds monitor budget"
    elif fault == "part":
        index["bootstrap"]["bytes"] = 8_000_001
        index_path.write_text(json.dumps(index))
        message = "Oversized part"
    else:
        descriptors = []
        for padding in range(3):
            value = dict(
                schema_version=1,
                publication=index["publication"],
                generated_at=index["generated_at"],
                data=[],
            )
            raw = json.dumps(value).encode() + b" " * (7_000_000 + padding)
            digest = hashlib.sha256(raw).hexdigest()
            path = "data/" + digest + ".json"
            (generation / path).write_bytes(raw)
            manifest["sha256"][path] = digest
            descriptors.append(dict(path=path, sha256=digest, bytes=len(raw)))
        index["cohorts"] = {"CVE-2025-12345": descriptors}
        index_path.write_text(json.dumps(index))
        message = "Default publication exceeds monitor budget"
    manifest["sha256"]["data/index.json"] = hashlib.sha256(index_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    serve(monkeypatch, generation)
    with pytest.raises(AssertionError, match=message):
        health.check("https://example.test")
