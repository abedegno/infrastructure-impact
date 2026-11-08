"""Optional table transports retain raw identities and fail closed under bounds."""

import copy
import gzip
import io
import json
from hashlib import sha256

import pytest
from test_static_delivery import dataset

from infrastructure_impact import publication_codec as codec
from infrastructure_impact.application import publication_v2 as publication
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.publication_reader import PublicationReader


def descriptor(raw, *, compressed=False):
    digest = sha256(raw).hexdigest()
    return dict(
        path=f"data/v2/{digest}.json" + (".gz" if compressed else ""), sha256=digest, bytes=len(raw)
    )


def transport_fixture():
    raw = b'{"data":["' + b"literal" * 500 + b'"]}\n'
    encoded = gzip.compress(raw, mtime=0)
    decoded, compressed = descriptor(raw), descriptor(encoded, compressed=True)
    catalog = dict(
        strings=[dict(part=decoded, first=0, count=1)],
        shapes=[],
        table_transports={decoded["path"]: compressed},
    )
    return raw, encoded, decoded, compressed, catalog


def helper(name):
    result = getattr(codec, name, None)
    assert callable(result), f"missing codec helper {name}"
    return result


def test_map_accepts_legacy_empty_and_valid_table_subset():
    validate = helper("validate_table_transports")
    _, _, decoded, compressed, catalog = transport_fixture()
    assert validate({"strings": [], "shapes": []}) == {}
    assert validate({**catalog, "table_transports": {}}) == {}
    assert validate(catalog) == {decoded["path"]: compressed}
    catalog["shapes"], catalog["strings"] = catalog["strings"], []
    assert validate(catalog) == {decoded["path"]: compressed}


@pytest.mark.parametrize(
    "fault",
    [
        "null",
        "array",
        "unknown",
        "root",
        "raw-path",
        "path-hash",
        "hash-type",
        "closed",
        "zero",
        "bool",
        "float",
        "oversize",
        "decoded-oversize",
        "duplicate",
    ],
)
def test_map_rejects_unbound_paths_and_invalid_descriptors(fault):
    validate = helper("validate_table_transports")
    _, _, decoded, compressed, catalog = transport_fixture()
    if fault in ("null", "array"):
        catalog["table_transports"] = None if fault == "null" else []
    elif fault in ("unknown", "root"):
        other = descriptor(b"root")
        catalog["table_transports"] = {other["path"]: compressed}
        if fault == "root":
            catalog["roots"] = {"snapshot.json": other}
    elif fault == "raw-path":
        compressed["path"] = decoded["path"]
    elif fault == "path-hash":
        compressed["sha256"] = "0" * 64
    elif fault == "hash-type":
        compressed["sha256"] = None
    elif fault == "closed":
        compressed["encoding"] = "gzip"
    elif fault in ("zero", "bool", "float", "oversize"):
        compressed["bytes"] = {"zero": 0, "bool": True, "float": 2.0, "oversize": 8_000_001}[fault]
    elif fault == "decoded-oversize":
        decoded["bytes"] = 8_000_001
    elif fault == "duplicate":
        other = descriptor(b"other table")
        catalog["shapes"] = [dict(part=other, first=0, count=1)]
        catalog["table_transports"][other["path"]] = copy.deepcopy(compressed)
    with pytest.raises(ValueError):
        validate(catalog)


def test_decoder_verifies_both_representations():
    raw, encoded, decoded, compressed, _ = transport_fixture()
    assert helper("decode_table_transport")(encoded, compressed, decoded) == raw


@pytest.mark.parametrize(
    "fault",
    [
        "encoded-size",
        "encoded-hash",
        "decoded-size",
        "decoded-hash",
        "overflow",
        "truncated",
        "crc",
        "malformed",
        "concatenated",
        "trailing",
        "encoded-oversize",
        "decoded-oversize",
        "descriptor-path",
    ],
)
def test_decoder_rejects_integrity_bounds_and_invalid_streams(fault):
    decode = helper("decode_table_transport")
    raw, encoded, decoded, compressed, _ = transport_fixture()
    if fault == "encoded-size":
        compressed["bytes"] += 1
    elif fault == "encoded-hash":
        compressed = descriptor(b"wrong compressed bytes", compressed=True)
        compressed["bytes"] = len(encoded)
    elif fault in ("decoded-size", "overflow"):
        decoded["bytes"] += 1 if fault == "decoded-size" else -1
    elif fault == "decoded-hash":
        decoded = descriptor(b"x" * len(raw))
    elif fault in ("encoded-oversize", "decoded-oversize"):
        (compressed if fault == "encoded-oversize" else decoded)["bytes"] = 8_000_001
    elif fault == "descriptor-path":
        compressed["path"] = "../table.json.gz"
    else:
        if fault == "truncated":
            encoded = encoded[:-1]
        elif fault == "crc":
            encoded = encoded[:-8] + bytes([encoded[-8] ^ 1]) + encoded[-7:]
        elif fault == "malformed":
            encoded = b"not a gzip stream"
        elif fault == "concatenated":
            encoded += gzip.compress(b"", mtime=0)
        elif fault == "trailing":
            encoded += b"trailing"
        compressed = descriptor(encoded, compressed=True)
    with pytest.raises(ValueError):
        decode(encoded, compressed, decoded)


def test_catalog_reader_rejects_invalid_map_before_fetch():
    _, _, _, compressed, catalog = transport_fixture()
    catalog["table_transports"] = {descriptor(b"tokens")["path"]: compressed}
    with pytest.raises(ValueError):
        codec.CatalogReader(None, catalog, {}, {})


def test_writer_emits_deterministic_beneficial_tables_only(tmp_path):
    writer = publication.Writer(tmp_path, {})
    tiny = writer.part("strings", ["x"])
    table = writer.part("strings", ["repeat " * 1000])
    shapes = writer.part("shapes", [["repeat " * 1000]])
    tokens = writer.part("tokens", [None] * 1000)
    transports = getattr(writer, "table_transports", {})
    assert set(transports) == {table["path"], shapes["path"]}
    assert (tmp_path / tiny["path"]).exists() and tokens["path"] not in transports
    for raw_desc in (table, shapes):
        raw = (tmp_path / raw_desc["path"]).read_bytes()
        expected = io.BytesIO()
        with gzip.GzipFile(fileobj=expected, mode="wb", filename="", mtime=0) as stream:
            stream.write(raw)
        encoded = (tmp_path / transports[raw_desc["path"]]["path"]).read_bytes()
        assert encoded == expected.getvalue()
        assert len(encoded) < len(raw)
        assert gzip.decompress(encoded) == raw


@pytest.fixture
def generation(tmp_path):
    return publish(dataset(), tmp_path, publication_format="v2")


def rebind_catalog(generation, catalog):
    raw = publication.encode(catalog)
    (generation / "publication-v2.json").write_bytes(raw)
    index_path = generation / "data/index.json"
    index = json.loads(index_path.read_bytes())
    index["publication_v2"].update(bytes=len(raw), sha256=sha256(raw).hexdigest())
    index_path.write_bytes(publication.encode(index))
    manifest_path = generation / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for path in generation.rglob("*"):
        if path.is_file() and path != manifest_path:
            manifest["sha256"][str(path.relative_to(generation))] = sha256(
                path.read_bytes()
            ).hexdigest()
    manifest_path.write_bytes(publication.encode(manifest))


def test_bundle_keeps_raw_archive_scope_and_logical_identity(generation):
    reader = PublicationReader(generation)
    catalog = reader.catalog
    assert catalog.get("table_transports")
    archive = json.loads((generation / "snapshot-v2.json").read_bytes())
    assert all(asset["path"].endswith(".json") for asset in archive["assets"])
    logical = b"".join(reader.stream_root("snapshot.json"))
    for raw_path, compressed in catalog["table_transports"].items():
        assert (generation / raw_path).exists()
        assert (generation / compressed["path"]).exists()
    # Removing the optional transport map leaves every logical/root hash intact.
    catalog.pop("table_transports")
    rebind_catalog(generation, catalog)
    legacy = PublicationReader(generation)
    assert b"".join(legacy.stream_root("snapshot.json")) == logical
    assert legacy.catalog["roots"] == reader.catalog["roots"]


def test_native_reader_rejects_non_table_mapping(generation):
    catalog = json.loads((generation / "publication-v2.json").read_bytes())
    catalog["table_transports"] = {
        catalog["roots"]["snapshot.json"]["path"]: descriptor(b"bad", compressed=True)
    }
    rebind_catalog(generation, catalog)
    with pytest.raises(ValueError):
        PublicationReader(generation)


def test_physical_inspection_verifies_sidecars(generation):
    reader = publication.inspect_bundle(generation, {})
    assert reader.catalog.get("table_transports")


@pytest.mark.parametrize("fault", ["unbound", "unbound-outside-v2", "wrong-decoded", "truncated"])
def test_physical_inspection_rejects_rebound_gzip_faults(generation, fault):
    catalog = json.loads((generation / "publication-v2.json").read_bytes())
    transports = catalog.get("table_transports", {})
    assert transports, "writer must provide table transports"
    raw_path = next(iter(transports))
    if fault in ("unbound", "unbound-outside-v2"):
        compressed = descriptor(b"unbound gzip", compressed=True)
        if fault == "unbound-outside-v2":
            compressed["path"] = "unbound.json.gz"
        encoded = b"unbound gzip"
    else:
        original = transports[raw_path]
        (generation / original["path"]).unlink()
        manifest_path = generation / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["sha256"].pop(original["path"])
        manifest_path.write_bytes(publication.encode(manifest))
        encoded = gzip.compress(b"wrong decoded table", mtime=0)
        if fault == "truncated":
            encoded = encoded[:-1]
        compressed = descriptor(encoded, compressed=True)
        transports[raw_path] = compressed
    (generation / compressed["path"]).write_bytes(encoded)
    rebind_catalog(generation, catalog)
    with pytest.raises(ValueError):
        publication.inspect_bundle(generation, {})
