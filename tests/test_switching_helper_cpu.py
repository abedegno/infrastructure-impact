"""Pure helper work bounds retain the original fingerprint and charging contracts."""

import hashlib
import json
import math
import random
import struct
from collections import Counter
from decimal import Decimal

import pytest

from infrastructure_impact import publication_codec as codec
from infrastructure_impact.application import switching_evidence as evidence


def original_fingerprint(value):
    """Independent pre-repair encoder, including strict prevalidation."""
    if type(value) is not dict:
        raise TypeError("Expected a JSON object")

    def check(node):
        if type(node) is dict:
            if any(type(key) is not str for key in node):
                raise TypeError("JSON object keys must be strings")
            for item in node.values():
                check(item)
        elif type(node) is list:
            for item in node:
                check(item)
        elif node is not None and type(node) not in (str, int, float, bool):
            raise TypeError("Expected a JSON-compatible value")

    check(value)
    json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")

    def encode(node):
        if type(node) is dict:
            return (
                "{"
                + ",".join(
                    json.dumps(key, ensure_ascii=False) + ":" + encode(node[key])
                    for key in sorted(node)
                )
                + "}"
            )
        if type(node) is list:
            return "[" + ",".join(encode(item) for item in node) + "]"
        if type(node) is float:
            if node.is_integer():
                return str(int(node))
            return format(Decimal.from_float(node), "f").rstrip("0")
        return json.dumps(node, ensure_ascii=False, allow_nan=False)

    return hashlib.sha256(encode(value).encode("utf-8")).hexdigest()


def test_fingerprint_uses_general_encoder_only_for_strict_whole_object_validation(monkeypatch):
    value = {"rows": [{"key": [None, True, False, 7, "é\n😀", 0.1]} for _ in range(100)]}
    expected = original_fingerprint(value)
    calls = []
    dumps = json.dumps

    def counted(node, *args, **kwargs):
        calls.append(type(node))
        return dumps(node, *args, **kwargs)

    monkeypatch.setattr(evidence.json, "dumps", counted)
    assert evidence.definition_sha256(value) == expected
    assert calls == [dict]
    value["rows"][0]["key"].append("changed")
    assert evidence.definition_sha256(value) != expected
    assert calls == [dict, dict]


def test_fingerprint_matches_original_exact_binary64_and_escaping():
    rng = random.Random(392)
    numbers = [0.0, -0.0, 1.0, -1.0, 0.1, 1e-7, 1e23, 5e-324, -5e-324, 1.7976931348623157e308]
    for _ in range(500):
        value = struct.unpack("!d", rng.getrandbits(64).to_bytes(8, "big"))[0]
        if math.isfinite(value):
            numbers.append(value)
    strings = ["", "é😀", "\u2028\u2029", '"\\/', "".join(map(chr, range(128)))]
    value = {"z": numbers, "a": [{s: [s, None, True, False, 9007199254740993]} for s in strings]}
    expected = original_fingerprint(value)
    assert evidence.definition_sha256(value) == expected
    assert evidence.definition_sha256(dict(reversed(list(value.items())))) == expected


class StringSubclass(str):
    pass


@pytest.mark.parametrize(
    "value",
    [
        [],
        {1: "x"},
        {StringSubclass("x"): 1},
        {"x": StringSubclass("text")},
        {"x": (1, 2)},
        {"x": {1, 2}},
        {"x": b"x"},
        {"x": Decimal("0.1")},
        {"x": float("nan")},
        {"x": float("inf")},
        {"x": -float("inf")},
        {"x": "\ud800"},
        {"\udfff": "x"},
        {"x": [None, {"nested": "\ud800\udfff"}]},
    ],
)
def test_fingerprint_retains_original_rejection_types(value):
    with pytest.raises(Exception) as original:
        original_fingerprint(value)
    with pytest.raises(type(original.value)) as repaired:
        evidence.definition_sha256(value)
    assert type(repaired.value) is type(original.value)


@pytest.mark.parametrize("ascii", [False, True])
@pytest.mark.parametrize("spaced", [False, True])
def test_repeated_builtin_keys_are_costed_once_across_child_budgets(monkeypatch, ascii, spaced):
    rows = [{"é😀\n\x7f": i, 'quoted"\\': None} for i in range(100)]
    expected = len(
        json.dumps(
            rows, ensure_ascii=ascii, separators=(", ", ": ") if spaced else (",", ":")
        ).encode()
    )
    costs = Counter()
    string_cost = codec.string_cost

    def counted(value, ascii=False):
        costs[value, ascii] += 1
        return string_cost(value, ascii)

    monkeypatch.setattr(codec, "string_cost", counted)
    parent = codec.Budget(100_000)
    first = codec.Budget(100_000, parent=parent)
    second = codec.Budget(100_000, parent=parent)
    codec.charge_value(rows, first, ascii=ascii, spaced=spaced)
    codec.charge_value(rows, second, ascii=ascii, spaced=spaced)
    assert first.used == second.used == expected
    assert parent.used == expected * 2
    assert costs == Counter({(key, mode): 1 for key in rows[0] for mode in (False, True)})
    codec.charge_value(rows, codec.Budget(100_000), ascii=ascii, spaced=spaced)
    assert costs == Counter({(key, mode): 2 for key in rows[0] for mode in (False, True)})


def test_cached_keys_still_charge_each_visit_and_enforce_deadline_depth_and_parent(monkeypatch):
    parent = codec.Budget(1000)
    budget = codec.Budget(1000, parent=parent)
    codec.charge_value({"key": 0}, budget)
    assert budget.used == parent.used == 9
    with pytest.raises(ValueError, match="depth"):
        codec.charge_value({"key": 0}, budget, depth=codec.MAX_DEPTH)
    assert budget.used == parent.used == 17  # Object and key charged before child depth rejection.
    parent.max_bytes = parent.used + 8
    with pytest.raises(ValueError, match="budget"):
        codec.charge_value({"key": 0}, budget)
    assert budget.used == parent.used == 25
    monkeypatch.setattr(codec.time, "monotonic", lambda: budget.deadline + 1)
    with pytest.raises(ValueError, match="deadline"):
        codec.charge_value({"key": 0}, budget)
    assert budget.used == parent.used == 25


def test_cached_key_costs_retain_declared_canonical_bound():
    parent = codec.Budget(1000)
    codec.charge_value({"é": 0}, parent)
    budget = codec.NodeBudget(parent, 7)
    with pytest.raises(ValueError, match="declared"):
        codec.charge_value({"é": 0}, budget)
    assert budget.canonical_used == 7
    assert parent.used == 23  # ASCII costs: first object 12, then braces/key 11.


def test_key_cache_does_not_reuse_subclass_value_costs_or_skip_subclass_visits():
    class DifferentIteration(str):
        def __iter__(self):
            return iter("oversized")

    parent = codec.Budget(1000)
    codec.charge_value(DifferentIteration("é"), parent)
    before = parent.used
    codec.charge_value({"é": 0}, parent)
    assert parent.used - before == 12
    before = parent.used
    codec.charge_value({DifferentIteration("é"): 0}, parent)
    assert parent.used - before == 15
    before = parent.used
    codec.charge_value({DifferentIteration("é"): 0}, parent)
    assert parent.used - before == 15


@pytest.mark.parametrize("key", [1, None, "\ud800", StringSubclass("\udfff")])
def test_key_costing_rejects_invalid_keys_even_after_valid_cached_key(key):
    budget = codec.Budget(1000)
    codec.charge_value({"valid": 0}, budget)
    with pytest.raises(ValueError):
        codec.charge_value({key: 0}, budget)
