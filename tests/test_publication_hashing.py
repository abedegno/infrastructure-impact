"""Real range hashing preserves bytes and bounds without per-fragment hash calls."""

import json
from hashlib import sha256

import pytest

from infrastructure_impact import publication_codec as codec
from infrastructure_impact.application.publication_v2 import Writer

IDENTITY = dict(
    publication=dict(id="a" * 32, advisory_schema_version=2),
    generated_at="2026-11-08T10:00:00Z",
)


def reader_for(tmp_path, value):
    """Use real writer files; CatalogReader's transport callback reads local envelopes."""
    writer = Writer(tmp_path, IDENTITY)
    writer.root("facts.json", value)
    catalog = dict(roots=writer.roots)
    for kind, values in (("strings", writer.encoder.strings), ("shapes", writer.encoder.shapes)):
        catalog[kind] = [dict(part=writer.part(kind, values), first=0, count=len(values))]

    def fetch(descriptor, *, kind):
        raw = (tmp_path / descriptor["path"]).read_bytes()
        assert len(raw) == descriptor["bytes"] and sha256(raw).hexdigest() == descriptor["sha256"]
        envelope = codec.strict_loads(raw, transport=kind not in ("overview",))
        assert envelope["kind"] == kind
        return envelope["data"]

    return codec.CatalogReader(fetch, catalog, IDENTITY, dict(stream=1_000_000_000))


def counted_hashes(monkeypatch, module=codec):
    counts = dict(updates=0, largest=0)

    class CountedHash:
        def __init__(self, data=b""):
            self.hash = sha256(data)

        def update(self, raw):
            counts["updates"] += 1
            counts["largest"] = max(counts["largest"], len(raw))
            self.hash.update(raw)

        def hexdigest(self):
            return self.hash.hexdigest()

    monkeypatch.setattr(module, "sha256", CountedHash)
    return counts


def test_many_small_literals_do_not_hash_each_fragment(tmp_path, monkeypatch):
    value = dict(facts=["vendor advisory text"] * 10_000, nested=dict(end="é😀"))
    reader = reader_for(tmp_path, value)
    counts = counted_hashes(monkeypatch)
    expected = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    actual = b"".join(reader.stream_root("facts.json"))
    assert actual == expected
    assert reader.root("facts.json")["logical"] == dict(
        bytes=len(expected), sha256=sha256(expected).hexdigest()
    )
    # Count real cryptographic operations rather than impose a flaky wall-time SLO.
    assert counts["updates"] < 500
    assert counts["largest"] <= 65_536


@pytest.mark.parametrize("field", ["logical_bytes", "logical_sha256", "end_token"])
def test_batched_hashing_still_rejects_bad_child_ranges(tmp_path, field):
    reader = reader_for(tmp_path, dict(facts=["x"] * 200, nested=dict(end="tail")))
    bound = reader.ranges("facts.json")[("facts",)]
    bound[field] = "0" * 64 if field == "logical_sha256" else bound[field] - 1
    with pytest.raises(ValueError, match="range"):
        b"".join(reader.stream_root("facts.json"))


@pytest.mark.parametrize("name", ["facts.json", "snapshot.json"])
def test_writer_batches_hash_updates_with_identical_ranges_and_legacy_bytes(
    tmp_path, monkeypatch, name
):
    from infrastructure_impact.application import publication_v2

    value = dict(facts=["vendor advisory text"] * 10_000, nested=dict(end="é😀\x7f"))
    counts = counted_hashes(monkeypatch, publication_v2)
    writer = Writer(tmp_path, IDENTITY)
    writer.root(name, value)
    for path, bound in writer.root_ranges[name].items():
        item = value
        for key in path:
            item = item[key]
        raw = json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode()
        assert bound["logical_bytes"] == len(raw)
        assert bound["logical_sha256"] == sha256(raw).hexdigest()
    if name == "snapshot.json":
        raw = (json.dumps(value, separators=(",", ":")) + "\n").encode()
        assert writer.legacy_snapshot == dict(bytes=len(raw), sha256=sha256(raw).hexdigest())
    assert counts["updates"] < 500
    assert counts["largest"] <= 65_536


def test_large_literals_do_not_expand_hash_buffers(tmp_path, monkeypatch):
    from infrastructure_impact.application import publication_v2

    class BoundedBuffer(bytearray):
        def extend(self, raw):
            assert len(self) + len(raw) <= 65_536
            super().extend(raw)

    monkeypatch.setattr(codec, "bytearray", BoundedBuffer, raising=False)
    monkeypatch.setattr(publication_v2, "bytearray", BoundedBuffer, raising=False)
    value = dict(facts=["é😀" * 30_000, "small", "x" * 70_000], nested=dict(end="tail"))
    reader = reader_for(tmp_path, value)
    expected = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    assert b"".join(reader.stream_root("facts.json")) == expected


def test_parent_range_limit_rejects_before_emitting_overflow(tmp_path):
    reader = reader_for(tmp_path, dict(facts=["allowed", "blocked"], nested=dict(end="tail")))
    # The enclosing limit must remain active while a child node is being decoded.
    bound = reader.ranges("facts.json")[("facts",)]
    bound["logical_bytes"] = len(b'["allowed",')
    emitted = []
    with pytest.raises(ValueError, match="range declared byte bound"):
        for chunk in reader.stream_root("facts.json"):
            emitted.append(chunk)
    assert b'"blocked"' not in b"".join(emitted)
