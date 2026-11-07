"""Direct encoding of the validated public projection, independent of legacy files."""

import gzip
import json
from hashlib import sha256

import pytest
from test_static_delivery import dataset

from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.publication_reader import PublicationReader


def test_v1_default_ignores_ambient_format(tmp_path, monkeypatch):
    monkeypatch.setenv("IMPACT_PUBLICATION_FORMAT", "v2")
    out = publish(dataset(), tmp_path)
    assert json.loads((out / "data/index.json").read_text())["schema_version"] == 1


def test_v2_direct_complete_archive_and_roots(tmp_path):
    data = dataset()
    legacy = publish(data, tmp_path / "v1")
    out = publish(data, tmp_path / "v2", publication_format="v2")
    assert not (out / "snapshot.json").exists()
    assert not (out / "switching-evidence.json").exists()
    reader = PublicationReader(out)
    full = json.loads(b"".join(reader.stream_root("snapshot.json")))
    old = json.loads((legacy / "snapshot.json").read_bytes())

    # Different generation identities are intentionally rebound by publish.
    def normalize(value):
        if isinstance(value, dict):
            return {k: normalize(v) for k, v in value.items() if k != "publication"}
        return [normalize(v) for v in value] if isinstance(value, list) else value

    assert normalize(full) == normalize(old)
    assert (out / "impact.csv").read_bytes() == (legacy / "impact.csv").read_bytes().replace(
        legacy.name.encode(), out.name.encode()
    )
    archive = json.loads(gzip.decompress((out / "snapshot-v2.json.gz").read_bytes()))
    assert archive["representation"] == "snapshot-archive"
    members = {a["path"]: a for a in archive["assets"]}
    scope = members[reader.catalog["archive"]["manifest"]["path"]]["data"]["data"]
    assert scope["scope"] == "snapshot-v1"
    assert {d["path"] for d in scope["members"]} == set(members) - {
        reader.catalog["archive"]["manifest"]["path"]
    }
    raw = b"".join(reader.stream_root("snapshot.json", serialization="ascii")) + b"\n"
    assert scope["legacy_snapshot"] == {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    for desc in scope["members"]:
        assert desc["path"] in members
    assert {
        "snapshot.json",
        "runtime-snapshot",
        "switching-evidence.json",
        "switching-comparison.json",
    } <= set(reader.catalog["roots"])
    assert reader.metadata()["publication"] == full["publication"]


def test_v2_monitors_default_and_exact_archive(tmp_path, monkeypatch):
    from test_switching_monitor import serve

    import checks.public_health as health

    out = publish(dataset(), tmp_path, publication_format="v2")
    requests = serve(monkeypatch, out)
    result = health.check("https://example.test", verify_archive=True)
    assert result["delivery"] == "publication_v2"
    assert result["compressed_archive_verified"] is True
    assert result["checked_default_bytes"] <= 20_000_000
    assert "snapshot.json" not in requests


def test_v2_worker_result_requires_trusted_expected_format():
    import pytest

    from infrastructure_impact.application.import_candidate import _empty, validate_result

    value = _empty(publication_format="v2")
    assert validate_result(value, publication_format="v2") == value
    with pytest.raises(ValueError):
        validate_result(value)
    with pytest.raises(ValueError):
        validate_result(_empty(), publication_format="v2")


def test_local_stream_export_never_overwrites(tmp_path):
    import pytest

    from infrastructure_impact.application.publication_reader import export_root

    out = publish(dataset(), tmp_path / "site", publication_format="v2")
    target = tmp_path / "export.json"
    export_root(out, "snapshot.json", target)
    assert json.loads(target.read_bytes())["records"]
    with pytest.raises(FileExistsError):
        export_root(out, "snapshot.json", target)
    with pytest.raises(ValueError):
        export_root(out, "snapshot.json", out / "new-export.json")


def test_archive_binds_compressed_descriptor(tmp_path):
    import copy

    import pytest

    from checks.switching_health import verify_publication_v2_archive

    out = publish(dataset(), tmp_path, publication_format="v2")
    reader = PublicationReader(out)
    catalog = copy.deepcopy(reader.catalog)
    catalog["archive"]["gzip"]["sha256"] = "0" * 64
    with pytest.raises(AssertionError, match="Compressed archive"):
        verify_publication_v2_archive(
            (out / "snapshot-v2.json.gz").read_bytes(), catalog, reader.identity
        )


def test_archive_binds_every_scope_member_descriptor(tmp_path):
    import copy

    import pytest

    from checks.switching_health import verify_publication_v2_archive

    out = publish(dataset(), tmp_path, publication_format="v2")
    reader = PublicationReader(out)
    catalog = copy.deepcopy(reader.catalog)
    archive = json.loads((out / "snapshot-v2.json").read_bytes())
    scope = next(
        a for a in archive["assets"] if a["path"] == catalog["archive"]["manifest"]["path"]
    )
    scope["data"]["data"]["members"][0]["bytes"] += 1
    encoded = (json.dumps(scope["data"], ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    scope.update(
        bytes=len(encoded),
        sha256=sha256(encoded).hexdigest(),
        path="data/v2/" + sha256(encoded).hexdigest() + ".json",
    )
    catalog["archive"]["manifest"] = {k: scope[k] for k in ("path", "sha256", "bytes")}
    raw = (json.dumps(archive, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    compressed = gzip.compress(raw, mtime=0)
    catalog["archive"]["expanded"].update(bytes=len(raw), sha256=sha256(raw).hexdigest())
    catalog["archive"]["gzip"].update(bytes=len(compressed), sha256=sha256(compressed).hexdigest())
    with pytest.raises(AssertionError, match="member descriptor"):
        verify_publication_v2_archive(compressed, catalog, reader.identity)


@pytest.mark.parametrize("fault", ["kind", "missing", "index", "interval", "size", "float", "site"])
def test_archive_record_route_authority(tmp_path, fault):
    import copy

    from checks.switching_health import verify_publication_v2_archive

    out = publish(dataset(), tmp_path, publication_format="v2")
    reader = PublicationReader(out)
    catalog = copy.deepcopy(reader.catalog)
    archive = json.loads((out / "snapshot-v2.json").read_bytes())
    assets = {a["path"]: a for a in archive["assets"]}
    scope_asset = assets[catalog["archive"]["manifest"]["path"]]
    scope = scope_asset["data"]["data"]
    original = scope["record_routes"][0]
    route_asset = assets[original["path"]]

    def rehash(asset):
        encoded = (
            json.dumps(asset["data"], ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode()
        asset.update(
            bytes=len(encoded),
            sha256=sha256(encoded).hexdigest(),
            path="data/v2/" + sha256(encoded).hexdigest() + ".json",
        )
        return {k: asset[k] for k in ("path", "sha256", "bytes")}

    if fault in ("kind", "missing"):
        scope["record_routes"] = [scope["root"]] if fault == "kind" else []
        scope["members"] = [d for d in scope["members"] if d != original]
        archive["assets"].remove(route_asset)
    elif fault == "site":
        catalog["routes"]["records"] = []
    else:
        row = route_asset["data"]["data"][0]
        field = {
            "index": "record_index",
            "interval": "first_token",
            "size": "logical_bytes",
            "float": "record_index",
        }[fault]
        row[field] = float(row[field]) if fault == "float" else row[field] + 1
        descriptor = rehash(route_asset)
        scope["record_routes"][0] = descriptor
        scope["members"] = [descriptor if d == original else d for d in scope["members"]]
        # Keep site bindings consistent: independently validate snapshot membership.
        catalog["routes"]["records"][0] = descriptor
    catalog["archive"]["manifest"] = rehash(scope_asset)
    raw = (json.dumps(archive, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    compressed = gzip.compress(raw, mtime=0)
    catalog["archive"]["expanded"].update(bytes=len(raw), sha256=sha256(raw).hexdigest())
    catalog["archive"]["gzip"].update(bytes=len(compressed), sha256=sha256(compressed).hexdigest())
    with pytest.raises((AssertionError, ValueError)):
        verify_publication_v2_archive(compressed, catalog, reader.identity)
