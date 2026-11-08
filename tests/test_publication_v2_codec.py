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


def test_materialization_retains_explicit_numeric_kind_and_zero_sign():
    import math

    value = codec.materialize_tokens(
        [[-1, 4], [-2, "f", "-0"], [-2, "f", "1"], [-2, "i", "1"], [-2, "i", "9007199254740993"]],
        [],
        [],
    )
    assert type(value[0]) is float and math.copysign(1, value[0]) == -1
    assert type(value[1]) is float
    assert type(value[2]) is int
    assert value[3] == 9007199254740993


def test_number_lexeme_charged_before_encoding():
    class GuardedLexeme(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("allocated before budget rejection")

    with pytest.raises(ValueError, match="budget"):
        list(
            codec.stream_tokens(
                [[-2, "i", GuardedLexeme("1" * 10000)]], [], [], budget=codec.Budget(1)
            )
        )


def test_private_context_preserves_real_stat_nanoseconds():
    from jsonschema import Draft202012Validator

    schema = json.loads(
        (
            Path(__file__).parents[1]
            / "infrastructure_impact/schemas/target-import-context-v2.json"
        ).read_text()
    )
    stat = Path(__file__).stat()
    state = {
        k: getattr(stat, k) for k in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    }
    state["sha256"] = "a" * 64
    for key in ("source_before", "source_after"):
        subschema = schema["properties"]["preservation"]["properties"][key]["properties"][""][
            "anyOf"
        ][0]
        Draft202012Validator(subschema).validate(state)


def test_ascii_del_is_charged_before_allocation():
    with pytest.raises(ValueError, match="budget"):
        codec.materialize_tokens([-2], [chr(127)], [], max_bytes=3, serialization="ascii")


def test_alias_shares_budget_and_deadline_and_closes_cursor():
    from time import monotonic

    closed = []

    def child():
        try:
            yield -2
        finally:
            closed.append(True)

    tokens = [[0], [1], [-3, "switching-evidence.json"]]
    shapes = [["inputs"], ["evidence"]]
    with pytest.raises(ValueError, match="budget"):
        b"".join(
            codec.stream_tokens(
                tokens,
                ["x" * 100],
                shapes,
                root="switching-comparison.json",
                aliases=lambda _: child(),
                budget=codec.Budget(40),
            )
        )
    assert closed == [True]
    with pytest.raises(ValueError, match="deadline"):
        b"".join(codec.stream_tokens([None], [], [], budget=codec.Budget(deadline=monotonic() - 1)))


def test_consumer_close_closes_underlying_token_iterator():
    closed = []

    def tokens():
        try:
            yield [-1, 1]
            yield None
        finally:
            closed.append(True)

    stream = codec.stream_tokens(tokens(), [], [])
    assert next(stream) == b"["
    stream.close()
    assert closed == [True]


def test_charge_value_bounds_without_serializing_large_literals():
    value = {"x": "🚀" * 10000}
    with pytest.raises(ValueError, match="budget"):
        codec.charge_value(value, codec.Budget(20))
    assert codec.string_cost(chr(127), True) == 8


def test_declared_logical_limit_rejects_before_literal_serialization(monkeypatch):
    budget = codec.NodeBudget(codec.Budget(1000), 2)

    def allocated(*args, **kwargs):
        raise AssertionError("serialized past declared output bound")

    monkeypatch.setattr(codec.json, "dumps", allocated)
    with pytest.raises(ValueError, match="declared"):
        list(codec.stream_tokens([-2], ["abcdef"], [], budget=budget))


@pytest.mark.parametrize("raw", VECTORS["invalid_transport_json"])
def test_strict_transport_json(raw):
    with pytest.raises(ValueError):
        codec.strict_loads(raw, transport=True)


def test_transport_mode_preserves_literal_boolean_tokens_and_logical_floats():
    assert codec.strict_loads('[true,false,null,[-2,"f","1.0"]]', transport=True) == [
        True,
        False,
        None,
        [-2, "f", "1.0"],
    ]
    assert type(codec.strict_loads("1.0")) is float


def test_child_allocation_budget_shares_stream_ceiling_and_deadline():
    parent = codec.Budget(20)
    child = codec.Budget(8, parent=parent)
    codec.charge_value("é", child)
    assert child.used == parent.used == 8
    assert child.deadline == parent.deadline
    with pytest.raises(ValueError, match="budget"):
        child.charge(1, 1)
    assert parent.used == 8
    second = codec.Budget(20, parent=parent)
    with pytest.raises(ValueError, match="budget"):
        second.charge(13, 13)
