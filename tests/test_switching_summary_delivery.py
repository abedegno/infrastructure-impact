"""Authored lossless summary transport, including the actual 8 MB boundary."""

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_static_delivery import dataset
from test_switching_delivery import DELIVERY, delivery
from test_switching_monitor import serve

import checks.public_health as health
from infrastructure_impact.application import static_delivery as transport
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.switching_comparison import summary
from infrastructure_impact.exports import switching_csv
from infrastructure_impact.settings import PACKAGE


def refresh_manifest(root, index):
    (root / "data/index.json").write_bytes(transport.encode(index))
    path = root / "manifest.json"
    manifest = json.loads(path.read_text())
    for file in (root / "data").glob("*.json"):
        manifest["sha256"][str(file.relative_to(root))] = hashlib.sha256(
            file.read_bytes()
        ).hexdigest()
    path.write_text(json.dumps(manifest))


def prepared(tmp_path, monkeypatch, *, large=False):
    root = publish(dataset(), tmp_path)
    data = json.loads((root / "snapshot.json").read_text())
    report = json.loads((root / "switching-comparison.json").read_text())
    # Repeated Unicode and JSON escapes exercise UTF-8 and envelope expansion.
    report["method"] = "Authored transport fixture: " + 'é🦊"\\\n' * (800_000 if large else 120_000)
    data["switching_comparison"] = report
    if not large:
        monkeypatch.setattr(transport, "MAX_PART_BYTES", 512_000)
    index = transport.write_static_delivery(root, data)
    refresh_manifest(root, index)
    return root, index, report


def test_actual_oversized_summary_round_trips_without_semantic_change(tmp_path, monkeypatch):
    root, index, report = prepared(tmp_path, monkeypatch, large=True)
    expected = transport.encode(summary(report))
    assert len(expected) > 8_000_000
    capability = index["switching"]["summary_fragments"]
    assert "summary" not in index["switching"]
    assert capability["bytes"] == len(expected)
    assert capability["sha256"] == hashlib.sha256(expected).hexdigest()
    assert all(p["bytes"] <= 8_000_000 for p in capability["parts"])
    browser = delivery(root)
    assert browser.get("value") == report, browser.get("error")
    assert switching_csv(browser["value"]) == switching_csv(report)
    serve(monkeypatch, root)
    result = health.check("https://example.test")
    assert result["switching_availability"] == "available"
    assert 8_000_000 < result["checked_default_bytes"] <= 20_000_000


def test_fragments_preserve_repeated_positions_and_legacy_form(tmp_path, monkeypatch):
    root = publish(dataset(), tmp_path)
    legacy = json.loads((root / "data/index.json").read_text())
    assert "summary" in legacy["switching"] and "summary_fragments" not in legacy["switching"]
    assert "value" in delivery(root, mode="summary")
    root, index, report = prepared(tmp_path, monkeypatch)
    parts = index["switching"]["summary_fragments"]["parts"]
    assert len(parts) > len({p["path"] for p in parts}), "Fixture must exercise repeated fragments"
    assert delivery(root, mode="summary").get("value") == summary(report)
    serve(monkeypatch, root)
    assert health.check("https://example.test")["switching_availability"] == "available"


@pytest.mark.parametrize(
    "fault",
    [
        "reorder",
        "missing",
        "type",
        "generation",
        "hash",
        "size",
        "tamper",
        "both",
        "neither",
        "negative",
        "boolean",
        "huge",
        "accumulated",
        "repeated_descriptor_size",
        "advisory_version",
    ],
)
def test_fragment_faults_fail_closed_in_browser_and_monitor(tmp_path, monkeypatch, fault):
    root, index, report = prepared(tmp_path, monkeypatch)
    switching = index["switching"]
    fragment = switching["summary_fragments"]
    parts = fragment["parts"]
    if fault == "repeated_descriptor_size":
        seen = set()
        for part in parts:
            if part["path"] in seen:
                part["bytes"] += 1
                break
            seen.add(part["path"])
        else:
            pytest.fail("Fixture must contain repeated fragment descriptors")
    elif fault == "reorder":
        parts.reverse()
    elif fault == "missing":
        parts.pop()
    elif fault in ("type", "generation", "advisory_version"):
        envelope = json.loads((root / parts[0]["path"]).read_text())
        if fault == "type":
            envelope["data"] = {"unexpected": "object"}
        elif fault == "generation":
            envelope["publication"]["id"] = "f" * 32
        else:
            envelope["publication"]["advisory_schema_version"] = 999
        raw = transport.encode(envelope)
        digest = hashlib.sha256(raw).hexdigest()
        parts[0] = dict(path="data/" + digest + ".json", sha256=digest, bytes=len(raw))
        (root / parts[0]["path"]).write_bytes(raw)
    elif fault == "hash":
        fragment["sha256"] = "0" * 64
    elif fault == "size":
        fragment["bytes"] += 1
    elif fault == "tamper":
        path = root / parts[0]["path"]
        path.write_bytes(path.read_bytes().replace(b"Authored", b"Changed", 1))
    elif fault == "both":
        switching["summary"] = copy.deepcopy(switching["inputs"])
    elif fault == "neither":
        del switching["summary_fragments"]
    elif fault == "negative":
        fragment["bytes"] = -1
    elif fault == "boolean":
        fragment["bytes"] = True
    elif fault == "huge":
        fragment["bytes"] = 128_000_001
    elif fault == "accumulated":
        fragment["bytes"] = 1
    refresh_manifest(root, index)
    assert "error" in delivery(root, mode="summary"), fault
    serve(monkeypatch, root)
    with pytest.raises(AssertionError):
        health.check("https://example.test")


def test_repeated_parts_still_spend_actual_monitor_read_budget(tmp_path, monkeypatch):
    root, index, _ = prepared(tmp_path, monkeypatch)
    fragment = index["switching"]["summary_fragments"]
    # Syntactically valid descriptor, bounded reconstructed declaration; actual
    # repeated responses must consume the unchanged default network budget.
    fragment["parts"] *= 100
    fragment["bytes"] = 128_000_000
    refresh_manifest(root, index)
    requests = serve(monkeypatch, root)
    with pytest.raises(AssertionError, match="Default publication exceeds monitor budget"):
        health.check("https://example.test")
    assert len(requests) < len(fragment["parts"])


@pytest.mark.parametrize("catalog", [False, True])
def test_fragment_monitor_runs_as_standalone_stdlib_script(tmp_path, monkeypatch, catalog):
    root, _, _ = (
        catalog_generation(tmp_path, monkeypatch, fragments=True)
        if catalog
        else prepared(tmp_path, monkeypatch)
    )
    script = """
import io,json,pathlib,runpy,sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
m=runpy.run_path(sys.argv[1])
class Response(io.BytesIO):
    status=200
root=pathlib.Path(sys.argv[2])
def fetch(url,timeout=None):
    return Response((root/(url.removeprefix('https://example.test/') or 'index.html')).read_bytes())
m['check'].__globals__['urlopen']=fetch
print(json.dumps(m['check']('https://example.test')))
assert not any(n.startswith(('infrastructure_impact','jsonschema')) for n in sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-S", "-c", script, str(Path(health.__file__).resolve()), str(root)],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["switching_availability"] == "available"


def catalog_generation(tmp_path, monkeypatch, *, fragments=False, real=False):
    root = publish(dataset(), tmp_path)
    data = json.loads((root / "snapshot.json").read_text())
    report = json.loads((root / "switching-comparison.json").read_text())
    data["switching_comparison"] = report
    if real:
        from test_switching_delivery import FIXTURE

        claim = FIXTURE["comparison_base_report"]["inputs"]["evidence"]["claims"][0]
        report["inputs"]["evidence"]["claims"] = [
            dict(claim, claim_id=hashlib.sha256(str(i).encode()).hexdigest()) for i in range(35_000)
        ]
    else:
        # Lower only the existing index cap to exercise the same branch cheaply.
        from test_switching_delivery import FIXTURE

        report = copy.deepcopy(FIXTURE["comparison_base_report"])
        for key in ("publication", "generated_at", "evaluated_at"):
            report[key] = data[key] if key != "evaluated_at" else data["generated_at"]
        for name in ("evidence", "kev"):
            report["inputs"][name]["publication"] = data["publication"]
            report["inputs"][name]["generated_at"] = data["generated_at"]
        data["switching_comparison"] = report
        if fragments:
            monkeypatch.setattr(transport, "MAX_PART_BYTES", 512_000)
            report["method"] += "é🦊" * 120_000
    if not real:
        inline = transport.write_static_delivery(root, data)
        monkeypatch.setattr(transport, "MAX_INDEX_BYTES", len(transport.encode(inline)) - 1)
    index = transport.write_static_delivery(root, data)
    refresh_manifest(root, index)
    return root, index, report


def test_real_claim_catalog_exceeds_two_mb_but_index_remains_bounded(tmp_path, monkeypatch):
    root, index, report = catalog_generation(tmp_path, monkeypatch, real=True)
    assert "claims" not in index["switching"]
    catalog = index["switching"]["claim_catalog"]
    assert len(catalog) > 1
    assert (root / "data/index.json").stat().st_size <= 2_000_000
    claims = report["inputs"]["evidence"]["claims"]
    selected = measured_delivery(root, mode="claims", ids=[claims[0]["claim_id"]])
    assert selected.get("value") == claims[:1], selected.get("error")
    assert 2 <= selected["peak"] <= 6
    assert "/switching-comparison.json" not in selected["requests"]
    requests = serve(monkeypatch, root)
    assert health.check("https://example.test")["switching_availability"] == "available"
    assert all(p["path"] in requests for p in catalog)


@pytest.mark.parametrize("fragments", [False, True])
def test_catalog_hydrates_report_exactly_and_summary_loading_stays_lazy(
    tmp_path, monkeypatch, fragments
):
    root, index, report = catalog_generation(tmp_path, monkeypatch, fragments=fragments)
    assert "claim_catalog" in index["switching"]
    assert ("summary_fragments" in index["switching"]) is fragments
    selected = delivery(root, mode="summary")
    assert selected.get("value") == summary(report), selected.get("error")
    assert not {"/" + p["path"] for p in index["switching"]["claim_catalog"]} & set(
        selected["requests"]
    )
    hydrated = delivery(root)
    assert hydrated.get("value") == report, hydrated.get("error")


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "tamper",
        "type",
        "duplicate",
        "cross_part_duplicate",
        "descriptor",
        "descriptor_identity",
        "generation",
        "both",
        "neither",
    ],
)
def test_catalog_faults_fail_closed(tmp_path, monkeypatch, fault):
    root, index, report = catalog_generation(tmp_path, monkeypatch)
    switching = index["switching"]
    catalog = switching["claim_catalog"]
    if fault == "missing":
        (root / catalog[0]["path"]).unlink()
    elif fault == "tamper":
        (root / catalog[0]["path"]).write_bytes(b"{}")
    elif fault == "cross_part_duplicate":
        catalog.append(copy.deepcopy(catalog[0]))
    elif fault in ("type", "duplicate", "descriptor", "descriptor_identity", "generation"):
        envelope = json.loads((root / catalog[0]["path"]).read_text())
        if fault == "type":
            envelope["data"] = "wrong type"
        elif fault == "duplicate":
            envelope["data"] *= 2
        elif fault == "descriptor":
            envelope["data"][0]["part"]["bytes"] = 8_000_001
        elif fault == "descriptor_identity":
            envelope["data"][0]["part"]["path"] = "data/" + "0" * 64 + ".json"
        else:
            envelope["publication"]["id"] = "e" * 32
        raw = transport.encode(envelope)
        digest = hashlib.sha256(raw).hexdigest()
        catalog[0] = dict(path="data/" + digest + ".json", sha256=digest, bytes=len(raw))
        (root / catalog[0]["path"]).write_bytes(raw)
    elif fault == "both":
        switching["claims"] = []
    else:
        del switching["claim_catalog"]
    refresh_manifest(root, index)
    assert "error" in delivery(root, mode="claims", ids=[])
    serve(monkeypatch, root)
    with pytest.raises((AssertionError, FileNotFoundError)):
        health.check("https://example.test")


def measured_delivery(root, **options):
    script = (
        DELIVERY.replace("const x=", "let active=0,peak=0;const x=")
        .replace(
            "requests.push(path);let raw=",
            "requests.push(path);active++;peak=Math.max(peak,active);"
            "await new Promise(r=>setTimeout(r,1));active--;let raw=",
        )
        .replace("{value,requests,cacheReuse}", "{value,requests,cacheReuse,peak}")
    )
    return json.loads(
        subprocess.check_output(
            ["node", "-e", script],
            input=json.dumps(dict(root=str(root), web=str(PACKAGE / "web"), **options)).encode(),
        )
    )


def test_fragment_fetches_use_six_workers(tmp_path, monkeypatch):
    root, _, report = prepared(tmp_path, monkeypatch)
    result = measured_delivery(root, mode="summary")
    assert result.get("value") == summary(report), result.get("error")
    assert result["peak"] == 6
