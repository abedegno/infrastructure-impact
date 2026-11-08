"""Small synthetic regressions for redundant v2 root serialization."""

import json
from hashlib import sha256

import pytest

from infrastructure_impact.application.publication_v2 import Writer

IDENTITY = {
    "publication": {"id": "synthetic", "advisory_schema_version": 2},
    "generated_at": "2026-11-07T00:00:00Z",
}


def test_root_hash_work_scales_with_ranges_not_unindexed_values(tmp_path, monkeypatch):
    from infrastructure_impact.application import publication_v2

    empty_hashes = []
    original = publication_v2.sha256

    def measured(raw=b""):
        if not raw:
            empty_hashes.append(None)
        return original(raw)

    monkeypatch.setattr(publication_v2, "sha256", measured)
    value = {"values": ["ordinary-value"] * 200}
    writer = Writer(tmp_path, IDENTITY)
    writer.root("ordinary.json", value)
    logical = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    assert writer.root_data["ordinary.json"]["logical"]["sha256"] == sha256(logical).hexdigest()
    assert writer.root_ranges["ordinary.json"][()]["logical_sha256"] == sha256(logical).hexdigest()
    assert len(empty_hashes) <= 4


def test_ascii_keys_and_strings_are_serialized_once(tmp_path, monkeypatch):
    original = json.dumps
    calls = []

    def measured(value, *args, **kwargs):
        if isinstance(value, str) and value in ("ascii-key", 'ascii-value\n\t\\"'):
            calls.append(value)
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "dumps", measured)
    writer = Writer(tmp_path, IDENTITY)
    writer.root("snapshot.json", {"ascii-key": 'ascii-value\n\t\\"'})
    assert calls.count("ascii-key") == 1
    assert calls.count('ascii-value\n\t\\"') == 1


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        -1,
        1.0,
        -0.0,
        1e-30,
        10**50,
        "\x7f",
        {"\x7f": "\x7f"},
        "\\u007f",
        "",
        'ascii\n\t\\"',
        "é😀\u2028",
        {"é😀": ["ascii", "é", True, 1, 1.0, -0.0], "control\n": "\x00\x7f"},
    ],
)
def test_root_and_legacy_hashes_match_independent_json_serialization(tmp_path, value):
    writer = Writer(tmp_path, IDENTITY)
    writer.root("snapshot.json", value)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    ascii_raw = (
        json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n"
    ).encode()
    assert writer.root_data["snapshot.json"]["logical"] == {
        "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
    }
    assert writer.legacy_snapshot == {
        "bytes": len(ascii_raw),
        "sha256": sha256(ascii_raw).hexdigest(),
    }


@pytest.mark.parametrize("value", [float("nan"), float("inf"), "\ud800"])
def test_invalid_scalar_rejection_is_preserved(tmp_path, value):
    with pytest.raises(ValueError):
        Writer(tmp_path, IDENTITY).root("snapshot.json", value)
