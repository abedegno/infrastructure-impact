"""Actual standalone monitor checks over synthetic published table transports."""

import gzip
import hashlib
import io
import json
import shutil

import pytest
from test_static_delivery import dataset

import checks.public_health as health
from infrastructure_impact.application.publication import publish


def descriptor(raw, suffix=".json"):
    digest = hashlib.sha256(raw).hexdigest()
    return {"path": f"data/v2/{digest}{suffix}", "sha256": digest, "bytes": len(raw)}


def save_catalog(root, catalog, manifest=None):
    """Rebind modified synthetic metadata so tests reach the intended inner gate."""
    path = root / "publication-v2.json"
    raw = (json.dumps(catalog, separators=(",", ":")) + "\n").encode()
    path.write_bytes(raw)
    index_path = root / "data/index.json"
    index = json.loads(index_path.read_bytes())
    index["publication_v2"].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    index_path.write_text(json.dumps(index))
    if manifest is None:
        manifest = json.loads((root / "manifest.json").read_bytes())
    for name in ("publication-v2.json", "data/index.json"):
        manifest["sha256"][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    (root / "manifest.json").write_text(json.dumps(manifest))


def sidecar(root, catalog, raw_desc, encoded):
    desc = descriptor(encoded, ".json.gz")
    (root / desc["path"]).write_bytes(encoded)
    catalog.setdefault("table_transports", {})[raw_desc["path"]] = desc
    manifest = json.loads((root / "manifest.json").read_bytes())
    manifest["sha256"][desc["path"]] = desc["sha256"]
    save_catalog(root, catalog, manifest)
    return desc


@pytest.fixture(scope="module")
def publication(tmp_path_factory):
    root = publish(dataset(), tmp_path_factory.mktemp("transport-monitor"), publication_format="v2")
    catalog = json.loads((root / "publication-v2.json").read_bytes())
    # Construct independently so the monitor test also works before producer support exists.
    catalog["table_transports"] = {}
    for name in ("strings", "shapes"):
        for item in catalog[name]:
            raw = (root / item["part"]["path"]).read_bytes()
            encoded = gzip.compress(raw, mtime=0)
            if len(encoded) < len(raw):
                sidecar(root, catalog, item["part"], encoded)
    save_catalog(root, catalog)
    return root


@pytest.fixture
def site(publication, tmp_path):
    root = tmp_path / "site"
    shutil.copytree(publication, root)
    return root


def serve(monkeypatch, root):
    """Replace only HTTP, retaining real bounded reads, fingerprints and monitor."""
    requests, reads = [], []

    class Response(io.BytesIO):
        status = 200

        def read(self, size=-1):
            raw = super().read(size)
            reads.append(len(raw))
            return raw

    def fetch(url, timeout=None):
        name = url.removeprefix("https://example.test/") or "index.html"
        requests.append(name)
        return Response((root / name).read_bytes())

    monkeypatch.setattr(health, "urlopen", fetch)
    return requests, reads


def test_monitor_uses_compressed_tables_and_counts_actual_wire_bytes(site, monkeypatch):
    catalog = json.loads((site / "publication-v2.json").read_bytes())
    transports = catalog["table_transports"]
    assert transports
    requests, reads = serve(monkeypatch, site)
    compressed = health.check("https://example.test")
    assert compressed["status"] == "fresh"
    assert compressed["checked_default_bytes"] == sum(reads)
    assert {d["path"] for d in transports.values()} <= set(requests)
    assert not set(transports) & set(requests)

    del catalog["table_transports"]
    save_catalog(site, catalog)
    requests, reads = serve(monkeypatch, site)
    legacy = health.check("https://example.test")
    assert legacy["checked_default_bytes"] == sum(reads)
    assert set(transports) <= set(requests)
    assert not {d["path"] for d in transports.values()} & set(requests)
    assert compressed["checked_default_bytes"] < legacy["checked_default_bytes"]


@pytest.mark.parametrize("representation", ["raw", "gzip"])
@pytest.mark.parametrize("binding", ["missing", "wrong"])
def test_monitor_requires_manifest_binding_for_both_table_representations(
    site, monkeypatch, representation, binding
):
    catalog = json.loads((site / "publication-v2.json").read_bytes())
    raw_path, encoded = next(iter(catalog["table_transports"].items()))
    path = raw_path if representation == "raw" else encoded["path"]
    manifest_path = site / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    if binding == "missing":
        del manifest["sha256"][path]
    else:
        manifest["sha256"][path] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    requests, _ = serve(monkeypatch, site)
    with pytest.raises(AssertionError, match="Unbound v2"):
        health.check("https://example.test")
    assert raw_path not in requests


@pytest.mark.parametrize(
    "fault",
    [
        "corrupt",
        "truncated",
        "overflow",
        "decoded_length",
        "decoded_hash",
        "wire_hash",
        "wire_length",
    ],
)
def test_monitor_rejects_declared_broken_sidecar_without_raw_fallback(site, monkeypatch, fault):
    catalog = json.loads((site / "publication-v2.json").read_bytes())
    raw_desc = catalog["strings"][0]["part"]
    raw = (site / raw_desc["path"]).read_bytes()
    encoded = gzip.compress(raw, mtime=0)
    if fault == "corrupt":
        encoded = b"invalid gzip"
    elif fault == "truncated":
        encoded = encoded[:-4]
    elif fault == "overflow":
        encoded = gzip.compress(raw + b"x", mtime=0)
    elif fault == "decoded_length":
        encoded = gzip.compress(raw[:-1], mtime=0)
    elif fault == "decoded_hash":
        encoded = gzip.compress(raw[:-1] + b" ", mtime=0)
    desc = sidecar(site, catalog, raw_desc, encoded)
    if fault == "wire_hash":
        # Keep descriptor and manifest intact; damage only bytes returned on the wire.
        (site / desc["path"]).write_bytes(encoded[:-1] + bytes([encoded[-1] ^ 1]))
    elif fault == "wire_length":
        (site / desc["path"]).write_bytes(encoded + b"x")
    requests, _ = serve(monkeypatch, site)
    with pytest.raises((AssertionError, ValueError)):
        health.check("https://example.test")
    assert desc["path"] in requests
    assert raw_desc["path"] not in requests


def test_monitor_rejects_oversized_transport_descriptor_before_fetch(site, monkeypatch):
    catalog = json.loads((site / "publication-v2.json").read_bytes())
    raw_path, desc = next(iter(catalog["table_transports"].items()))
    desc["bytes"] = 8_000_001
    save_catalog(site, catalog)
    requests, _ = serve(monkeypatch, site)
    with pytest.raises((AssertionError, ValueError)):
        health.check("https://example.test")
    assert desc["path"] not in requests
    assert raw_path not in requests


@pytest.mark.parametrize(
    "fault,message",
    [
        ("generation", "Mixed v2 generation"),
        ("envelope", "V2 envelope"),
        ("json", "duplicate JSON key"),
        ("count", "literal table count"),
        ("duplicates", "duplicate layout key/definition"),
    ],
)
def test_monitor_retains_decoded_table_validation(site, monkeypatch, fault, message):
    catalog = json.loads((site / "publication-v2.json").read_bytes())
    item = catalog["shapes" if fault == "duplicates" else "strings"][0]
    previous = item["part"]["path"]
    value = json.loads((site / previous).read_bytes())
    if fault == "generation":
        value["publication"]["id"] = "f" * 32
    elif fault == "envelope":
        value["kind"] = "shapes"
    elif fault == "count":
        value["data"].pop()
    elif fault == "duplicates":
        value["data"][1] = value["data"][0]
    raw = json.dumps(value, separators=(",", ":")).encode()
    if fault == "json":
        raw = b'{"schema_version":2,' + raw[1:]
    item["part"] = descriptor(raw)
    (site / item["part"]["path"]).write_bytes(raw)
    del catalog["table_transports"][previous]
    manifest = json.loads((site / "manifest.json").read_bytes())
    manifest["sha256"][item["part"]["path"]] = item["part"]["sha256"]
    save_catalog(site, catalog, manifest)
    encoded = sidecar(site, catalog, item["part"], gzip.compress(raw, mtime=0))
    requests, _ = serve(monkeypatch, site)
    with pytest.raises((AssertionError, ValueError), match=message):
        health.check("https://example.test")
    assert encoded["path"] in requests
    assert item["part"]["path"] not in requests


def test_monitor_stops_at_wire_budget_sentinel_during_declared_gzip_read(site, monkeypatch, capsys):
    catalog = json.loads((site / "publication-v2.json").read_bytes())
    index_path = site / "data/index.json"
    index = json.loads(index_path.read_bytes())
    manifest = json.loads((site / "manifest.json").read_bytes())
    cohort = index["cohorts"][next(iter(index["cohorts"]))]
    envelope = json.dumps(
        {
            "schema_version": 1,
            "publication": index["publication"],
            "generated_at": index["generated_at"],
            "data": [],
        },
        separators=(",", ":"),
    ).encode()
    for i in range(5):
        # Distinct, valid JSON parts consume 30 MB before the monitor opens v2 tables.
        raw = envelope + b"\t" * i + b" " * (6_000_000 - len(envelope) - i)
        digest = hashlib.sha256(raw).hexdigest()
        desc = {"path": f"data/{digest}.json", "sha256": digest, "bytes": len(raw)}
        (site / desc["path"]).write_bytes(raw)
        manifest["sha256"][desc["path"]] = digest
        cohort.append(desc)
    index_path.write_text(json.dumps(index))
    save_catalog(site, catalog, manifest)

    raw_desc = catalog["strings"][0]["part"]
    raw = (site / raw_desc["path"]).read_bytes()
    buffer = io.BytesIO()
    # A legal large filename makes wire bytes exceed the remaining budget while
    # preserving the original small decoded table and the 8 MB encoded part bound.
    with gzip.GzipFile(filename="x" * 3_000_000, fileobj=buffer, mode="wb", mtime=0) as stream:
        stream.write(raw)
    encoded = buffer.getvalue()
    assert gzip.decompress(encoded) == raw
    assert 3_000_000 < len(encoded) <= 8_000_000
    compressed = sidecar(site, catalog, raw_desc, encoded)

    requests, reads = serve(monkeypatch, site)
    with pytest.raises(AssertionError, match="Default publication exceeds monitor budget"):
        health.check("https://example.test")
    assert requests[-1] == compressed["path"]
    assert raw_desc["path"] not in requests
    assert sum(reads) == 32_000_001
    assert 30_000_000 < sum(reads[:-1]) < 32_000_000
    assert reads[-1] == 32_000_000 - sum(reads[:-1]) + 1
    assert reads[-1] < compressed["bytes"]
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert events == [
        {
            "event": "monitor_capacity",
            "mode": "default",
            "reason": "default_transfer",
            "resource": "other",
            "observed_bytes": 32_000_001,
            "limit_bytes": 32_000_000,
        }
    ]
