"""Shared transport vectors are deliberately independent of the writer."""

import json
from pathlib import Path

import pytest

from infrastructure_impact import publication_codec as codec

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures/publication-v2-codec-vectors.json").read_text()
)


@pytest.mark.parametrize("vector", VECTORS["valid"], ids=lambda x: x["name"])
def test_shared_stream_vectors(vector):
    for encoding in ("logical", "ascii"):
        assert (
            b"".join(
                codec.stream_tokens(
                    vector["tokens"], vector["strings"], vector["shapes"], serialization=encoding
                )
            ).decode()
            == vector[encoding]
        )


@pytest.mark.parametrize("vector", VECTORS["invalid"], ids=lambda x: x["name"])
def test_shared_invalid_vectors(vector):
    with pytest.raises(ValueError):
        b"".join(codec.stream_tokens(vector["tokens"], vector["strings"], vector["shapes"]))


@pytest.mark.parametrize("raw", VECTORS["invalid_json"])
def test_strict_json(raw):
    with pytest.raises(ValueError):
        codec.strict_loads(raw.encode())


def test_invalid_utf8():
    with pytest.raises(ValueError):
        codec.strict_loads(b'"\xff"')


@pytest.mark.parametrize("path", VECTORS["invalid_paths"])
def test_bad_descriptor_paths(path):
    with pytest.raises(ValueError):
        codec.validate_descriptor({"path": path, "sha256": "a" * 64, "bytes": 5})


def test_actual_requested_allocation_bound():
    tokens = [[-1, 1000]] + [-2] * 1000
    with pytest.raises(ValueError, match="budget"):
        codec.materialize_tokens(tokens, ["🚀" * 100], [], max_bytes=10000, serialization="ascii")


def test_depth_before_recursing():
    with pytest.raises(ValueError, match="depth"):
        b"".join(codec.stream_tokens([[-1, 1]] * 65 + [None], [], []))


def test_route_recovery_and_exact_membership():
    parts = [{"base": 10, "final_end": 18, "rows": [[0, 0, 3], [1, 4, 5]]}]
    assert codec.claim_routes(parts, ["a", "b"]) == [("a", 10, 14, 3), ("b", 14, 18, 5)]
    for rows in ([[0, 1, 3]], [[0, 0, 3], [0, 4, 5]], [[0, 0, 3], [1, 0, 5]]):
        with pytest.raises(ValueError):
            codec.claim_routes([{"base": 10, "final_end": 18, "rows": rows}], ["a", "b"])


def test_encode_stream_preserves_python_numbers():
    encoder = codec.Encoder()
    value = {"id": 9007199254740993, "float": 1.0, "zero": -0.0, "nested": [None, True, "🚀"]}
    tokens = list(encoder.encode(value))
    assert (
        b"".join(codec.stream_tokens(tokens, encoder.strings, encoder.shapes))
        == json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    )
