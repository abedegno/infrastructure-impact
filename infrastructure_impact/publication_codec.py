"""Canonical, stdlib-only publication-v2 primitives (also shipped standalone).

Transport integers are never logical numbers. Streaming keeps number lexemes and
object order; materialization is a separate, explicitly bounded operation.
"""

import json
import math
import re
import time
from collections import deque
from dataclasses import dataclass
from hashlib import sha256

SAFE_INTEGER = 9_007_199_254_740_991
MAX_PART = 8_000_000
MAX_SELECTED = 128_000_000
MAX_STREAM = 1_000_000_000
MAX_DEPTH = 64
NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
NAME = re.compile(r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+(?:\.json)?\Z")
PART_PATH = re.compile(r"data/v2/([a-f0-9]{64})\.json\Z")


def safe_int(value, *, minimum=0):
    if type(value) is not int or not minimum <= value <= SAFE_INTEGER:
        raise ValueError("unsafe transport integer")
    return value


def literal(value):
    if not isinstance(value, str):
        raise ValueError("literal must be a string")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("unpaired surrogate")
    return value


def strict_loads(raw, *, max_bytes=MAX_PART, parse_int=int, parse_float=float):
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="strict")
    if len(raw) > max_bytes:
        raise ValueError("JSON byte budget")

    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("nonfinite JSON number")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
            parse_int=parse_int,
            parse_float=parse_float,
        )
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid JSON encoding/depth") from exc

    def check(node, depth):
        if depth > MAX_DEPTH:
            raise ValueError("JSON depth")
        if isinstance(node, str):
            literal(node)
        elif isinstance(node, float) and not math.isfinite(node):
            raise ValueError("nonfinite JSON number")
        elif isinstance(node, (dict, list)):
            for k, v in node.items() if isinstance(node, dict) else enumerate(node):
                if isinstance(k, str):
                    literal(k)
                check(v, depth + 1)

    check(value, 0)
    return value


def validate_descriptor(value, *, paths=None, max_bytes=MAX_PART):
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "bytes"}:
        raise ValueError("descriptor fields")
    path = value["path"]
    match = PART_PATH.fullmatch(path) if isinstance(path, str) else None
    if paths is None:
        if not match or match[1] != value["sha256"]:
            raise ValueError("descriptor path/hash")
    elif path not in paths:
        raise ValueError("descriptor path")
    if not isinstance(value["sha256"], str) or not HASH.fullmatch(value["sha256"]):
        raise ValueError("descriptor hash")
    if safe_int(value["bytes"], minimum=1) > max_bytes:
        raise ValueError("descriptor byte budget")
    return value


def validate_range(value):
    if not isinstance(value, dict) or set(value) != {
        "root",
        "first_token",
        "end_token",
        "logical_bytes",
        "logical_sha256",
    }:
        raise ValueError("range fields")
    if not isinstance(value["root"], str) or not NAME.fullmatch(value["root"]):
        raise ValueError("range root")
    if safe_int(value["first_token"]) >= safe_int(value["end_token"], minimum=1):
        raise ValueError("empty or reversed range")
    safe_int(value["logical_bytes"], minimum=1)
    if not isinstance(value["logical_sha256"], str) or not HASH.fullmatch(value["logical_sha256"]):
        raise ValueError("range hash")
    return value


def validate_tables(strings, shapes):
    seen = set()
    for s in strings:
        literal(s)
    for shape in shapes:
        if not isinstance(shape, list):
            raise ValueError("shape type")
        keys = tuple(literal(k) for k in shape)
        if len(set(keys)) != len(keys) or keys in seen:
            raise ValueError("duplicate layout key/definition")
        seen.add(keys)


@dataclass(frozen=True)
class LogicalNumber:
    kind: str
    lexeme: str

    def __post_init__(self):
        grammar = INTEGER if self.kind == "i" else NUMBER if self.kind == "f" else None
        if (
            grammar is None
            or not isinstance(self.lexeme, str)
            or not grammar.fullmatch(self.lexeme)
        ):
            raise ValueError("invalid numeric lexeme")
        if self.kind == "f" and not math.isfinite(float(self.lexeme)):
            raise ValueError("nonfinite logical number")

    def value(self):
        return int(self.lexeme) if self.kind == "i" else float(self.lexeme)


@dataclass
class Budget:
    max_bytes: int = MAX_STREAM
    deadline: float | None = None
    used: int = 0

    def __post_init__(self):
        self.max_bytes = min(safe_int(self.max_bytes), MAX_STREAM)
        if self.deadline is None:
            self.deadline = time.monotonic() + 300

    def charge(self, canonical, requested):
        if time.monotonic() > self.deadline:
            raise ValueError("stream deadline")
        cost = max(canonical, requested)
        if cost > self.max_bytes - self.used:
            raise ValueError("decoded byte budget")
        self.used += cost


def string_cost(value, ascii=False):
    literal(value)
    total = 2
    for char in value:
        code = ord(char)
        if char in '"\\' or char in "\b\f\n\r\t":
            total += 2
        elif code < 32 or (ascii and code >= 128):
            total += 12 if code > 0xFFFF else 6
        else:
            total += 1 if code < 128 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
    return total


def stream_tokens(
    tokens,
    strings,
    shapes,
    *,
    serialization="logical",
    budget=None,
    root=None,
    path=(),
    aliases=None,
    depth=0,
    validate=True,
    observer=None,
    number_observer=None,
):
    """Validate/emit a single complete node; charge *before* encoding each literal.

    aliases(name) returns its token iterator. The same tables, budget, depth and
    path authority are used for the child; no alias can reset stream limits.
    """
    if serialization not in ("logical", "ascii"):
        raise ValueError("serialization")
    if validate:
        validate_tables(strings, shapes)
    budget = budget or Budget()
    tokens = iter(tokens)
    ascii = serialization == "ascii"

    def emit(raw):
        budget.charge(len(raw), len(raw))
        if observer is not None:
            observer(raw)
        return raw

    def quoted(value):
        budget.charge(string_cost(value), string_cost(value, ascii))
        if observer is not None:
            observer(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        return json.dumps(value, ensure_ascii=ascii, separators=(",", ":")).encode("utf-8")

    def node(level, location):
        if level > MAX_DEPTH:
            raise ValueError("decoder depth")
        try:
            token = next(tokens)
        except StopIteration as exc:
            raise ValueError("truncated node") from exc
        if token is None or type(token) is bool:
            yield emit(b"null" if token is None else b"true" if token else b"false")
        elif type(token) is int:
            index = -token - 2
            safe_int(index)
            if token < -SAFE_INTEGER or index >= len(strings):
                raise ValueError("string reference")
            yield quoted(strings[index])
        elif isinstance(token, list) and len(token) == 1:
            index = safe_int(token[0])
            if index >= len(shapes):
                raise ValueError("shape reference")
            keys = shapes[index]
            # At least one null child per key. Reject amplification immediately.
            if len(keys) * 5 + 2 > budget.max_bytes - budget.used:
                raise ValueError("object minimum byte budget")
            yield emit(b"{")
            for i, key in enumerate(keys):
                if i:
                    yield emit(b",")
                yield quoted(key)
                yield emit(b":")
                yield from node(level + 1, location + (key,))
            yield emit(b"}")
        elif (
            isinstance(token, list) and len(token) == 2 and type(token[0]) is int and token[0] == -1
        ):
            count = safe_int(token[1])
            if (count * 2 + 1 if count else 2) > budget.max_bytes - budget.used:
                raise ValueError("array minimum byte budget")
            yield emit(b"[")
            for i in range(count):
                if i:
                    yield emit(b",")
                yield from node(level + 1, location + (i,))
            yield emit(b"]")
        elif (
            isinstance(token, list) and len(token) == 3 and type(token[0]) is int and token[0] == -2
        ):
            if not isinstance(token[2], str):
                raise ValueError("invalid numeric lexeme")
            budget.charge(len(token[2]), len(token[2]))
            number = LogicalNumber(token[1], token[2])
            raw = number.lexeme.encode("ascii")
            if observer is not None:
                observer(raw)
            if number_observer is not None:
                number_observer(number)
            yield raw
        elif (
            isinstance(token, list) and len(token) == 2 and type(token[0]) is int and token[0] == -3
        ):
            if (
                root != "switching-comparison.json"
                or location != ("inputs", "evidence")
                or token[1] != "switching-evidence.json"
                or aliases is None
            ):
                raise ValueError("forbidden root alias")
            yield from stream_tokens(
                aliases(token[1]),
                strings,
                shapes,
                serialization=serialization,
                budget=budget,
                root=token[1],
                aliases=None,
                depth=level,
                validate=False,
                observer=observer,
                number_observer=number_observer,
            )
        else:
            raise ValueError("invalid token")

    yield from node(depth, tuple(path))
    try:
        next(tokens)
    except StopIteration:
        return
    raise ValueError("extra node or invalid range boundary")


def materialize_tokens(
    tokens, strings, shapes, *, max_bytes=MAX_SELECTED, serialization="logical", **kwargs
):
    budget = Budget(min(safe_int(max_bytes), MAX_SELECTED))
    # Each append is preceded by actual accounting, including ASCII expansion.
    raw = bytearray()
    kinds = deque()
    for chunk in stream_tokens(
        tokens,
        strings,
        shapes,
        serialization=serialization,
        budget=budget,
        number_observer=lambda number: kinds.append(number.kind),
        **kwargs,
    ):
        raw.extend(chunk)

    def number(lexeme):
        return int(lexeme) if kinds.popleft() == "i" else float(lexeme)

    return strict_loads(raw, max_bytes=budget.max_bytes, parse_int=number, parse_float=number)


def claim_routes(parts, strings, *, expected_ids=None):
    result = []
    seen = set()
    previous_end = None
    for part in parts:
        if not isinstance(part, dict) or set(part) != {"base", "final_end", "rows"}:
            raise ValueError("claim routes fields")
        start = safe_int(part["base"])
        end = safe_int(part["final_end"], minimum=1)
        if end <= start or (previous_end is not None and previous_end != start):
            raise ValueError("claim routes contiguity")
        rows = part["rows"]
        if not isinstance(rows, list) or not rows:
            raise ValueError("empty claim routes")
        local = []
        for i, row in enumerate(rows):
            if not isinstance(row, list) or len(row) != 3:
                raise ValueError("claim route row")
            atom, delta, size = row
            safe_int(atom)
            safe_int(delta)
            safe_int(size, minimum=1)
            if atom >= len(strings) or (delta != 0 if i == 0 else delta == 0):
                raise ValueError("claim route delta/atom")
            claim = literal(strings[atom])
            if claim in seen:
                raise ValueError("duplicate claim identity")
            seen.add(claim)
            start += delta
            if start >= end:
                raise ValueError("claim route outside end")
            local.append((claim, start, size))
        for i, (claim, first, size) in enumerate(local):
            result.append((claim, first, local[i + 1][1] if i + 1 < len(local) else end, size))
        previous_end = end
    if expected_ids is not None and (len(expected_ids) != len(seen) or set(expected_ids) != seen):
        raise ValueError("claim membership mismatch")
    return result


class Encoder:
    """Only accepts a public logical projection; caller owns that privacy boundary."""

    def __init__(self):
        self.strings = []
        self.shapes = []
        self._strings = {}
        self._shapes = {}

    def atom(self, text):
        literal(text)
        if text not in self._strings:
            self._strings[text] = len(self.strings)
            self.strings.append(text)
        return self._strings[text]

    def encode(self, value, *, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError("encoder depth")
        if value is None or type(value) is bool:
            yield value
        elif isinstance(value, LogicalNumber):
            yield [-2, value.kind, value.lexeme]
        elif type(value) in (int, float):
            lexeme = json.dumps(value, allow_nan=False)
            yield [-2, "i" if type(value) is int else "f", lexeme]
        elif isinstance(value, str):
            yield -(self.atom(value) + 2)
        elif isinstance(value, dict):
            shape = tuple(literal(k) for k in value)
            if shape not in self._shapes:
                self._shapes[shape] = len(self.shapes)
                self.shapes.append(list(shape))
            yield [self._shapes[shape]]
            for child in value.values():
                yield from self.encode(child, depth=depth + 1)
        elif isinstance(value, (tuple, list)):
            yield [-1, len(value)]
            for child in value:
                yield from self.encode(child, depth=depth + 1)
        else:
            raise ValueError("unsupported logical type")


def digest(chunks):
    size, hash = 0, sha256()
    for chunk in chunks:
        size += len(chunk)
        hash.update(chunk)
    return {"bytes": size, "sha256": hash.hexdigest()}
