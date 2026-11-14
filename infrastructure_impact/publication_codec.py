"""Canonical, stdlib-only publication-v2 primitives (also shipped standalone).

Transport integers are never logical numbers. Streaming keeps number lexemes and
object order; materialization is a separate, explicitly bounded operation.
"""

import copy
import json
import math
import re
import time
import zlib
from collections import OrderedDict, deque
from dataclasses import dataclass, field
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
TABLE_TRANSPORT_PATH = re.compile(r"data/v2/([a-f0-9]{64})\.json\.gz\Z")
SURROGATE = re.compile("[\ud800-\udfff]")
CONTROL = re.compile("[\x00-\x1f]")
LONG_CONTROL = "".join(chr(i) for i in range(32) if chr(i) not in "\b\f\n\r\t")


def safe_int(value, *, minimum=0):
    if type(value) is not int or not minimum <= value <= SAFE_INTEGER:
        raise ValueError("unsafe transport integer")
    return value


def literal(value):
    if not isinstance(value, str):
        raise ValueError("literal must be a string")
    # Scan in the C regex engine without allocating an encoded copy. This check
    # runs for every decoded literal and must stay cheap on full advisory text.
    if SURROGATE.search(value) is not None:
        raise ValueError("unpaired surrogate")
    return value


def strict_loads(raw, *, max_bytes=MAX_PART, parse_int=int, parse_float=float, transport=False):
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

    if transport:

        def parse_int(lexeme):
            return safe_int(int(lexeme), minimum=-SAFE_INTEGER)

        def parse_float(lexeme):
            raise ValueError("noninteger transport lexeme")

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


def _validate_table_transport_descriptor(value):
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "bytes"}:
        raise ValueError("table transport descriptor fields")
    path = value["path"]
    match = TABLE_TRANSPORT_PATH.fullmatch(path) if isinstance(path, str) else None
    if not match or match[1] != value["sha256"]:
        raise ValueError("table transport descriptor path/hash")
    return validate_descriptor(value, paths={path})


def validate_table_transports(catalog):
    """Bind an optional gzip map exclusively to existing raw table parts."""
    transports = catalog.get("table_transports", {})
    if not isinstance(transports, dict):
        raise ValueError("table transports map")
    tables = {}
    table_bytes = 0
    for kind in ("strings", "shapes"):
        rows = catalog.get(kind)
        if not isinstance(rows, list):
            raise ValueError("table descriptors array")
        for row in rows:
            if not isinstance(row, dict) or "part" not in row:
                raise ValueError("table descriptor fields")
            part = validate_descriptor(row["part"])
            table_bytes += part["bytes"]
            if part["path"] in tables and tables[part["path"]] != part:
                raise ValueError("conflicting raw table descriptors")
            tables[part["path"]] = part
    seen = set()
    for raw_path, compressed in transports.items():
        if raw_path not in tables:
            raise ValueError("table transport key is not a table part")
        _validate_table_transport_descriptor(compressed)
        if compressed["path"] in seen:
            raise ValueError("duplicate table transport path")
        seen.add(compressed["path"])
    if transports and table_bytes > MAX_SELECTED:
        raise ValueError("decoded byte budget")
    return transports


def decode_table_transport(raw, compressed, decoded):
    """Verify and inflate exactly one gzip member within the raw part bound."""
    _validate_table_transport_descriptor(compressed)
    validate_descriptor(decoded)
    if len(raw) != compressed["bytes"] or sha256(raw).hexdigest() != compressed["sha256"]:
        raise ValueError("table transport encoded bytes/hash mismatch")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        result = decoder.decompress(raw, decoded["bytes"] + 1)
    except zlib.error as exc:
        raise ValueError("invalid table transport gzip") from exc
    if len(result) > decoded["bytes"]:
        raise ValueError("table transport decoded byte budget")
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("truncated or trailing table transport gzip")
    if len(result) != decoded["bytes"] or sha256(result).hexdigest() != decoded["sha256"]:
        raise ValueError("table transport decoded bytes/hash mismatch")
    return result


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


def validate_record_routes(rows):
    if not isinstance(rows, list):
        raise ValueError("record routes array")
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "record_index",
            "first_token",
            "end_token",
            "logical_bytes",
        }:
            raise ValueError("record route fields")
        safe_int(row["record_index"])
        if safe_int(row["first_token"]) >= safe_int(row["end_token"], minimum=1):
            raise ValueError("record route interval")
        safe_int(row["logical_bytes"], minimum=1)
    return rows


def validate_path(path):
    if not isinstance(path, (list, tuple)):
        raise ValueError("range path array")
    for component in path:
        if isinstance(component, str):
            literal(component)
        else:
            safe_int(component)
    return tuple(path)


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


class LiteralCache:
    """Invocation-local FIFO of pure built-in string encodings, never validation."""

    def __init__(self):
        self.entries = OrderedDict()
        self.payload_bytes = 0

    def quoted(self, value, *, ascii=False):
        if type(value) is not str:
            return json.dumps(value, ensure_ascii=ascii, separators=(",", ":")).encode("utf-8")
        key = (value, ascii)
        raw = self.entries.get(key)
        if raw is not None:
            return raw
        raw = json.dumps(value, ensure_ascii=ascii, separators=(",", ":")).encode("utf-8")
        if len(raw) <= 1_048_576:
            while len(self.entries) >= 4096 or self.payload_bytes + len(raw) > 1_048_576:
                self.payload_bytes -= len(self.entries.popitem(last=False)[1])
            self.entries[key] = raw
            self.payload_bytes += len(raw)
        return raw


@dataclass
class Budget:
    max_bytes: int = MAX_STREAM
    deadline: float | None = None
    used: int = 0
    costs: dict = field(default_factory=dict)
    parent: "Budget | None" = None

    literals: LiteralCache = field(
        default_factory=LiteralCache, init=False, repr=False, compare=False
    )
    _key_costs: dict = field(default_factory=dict, init=False, repr=False, compare=False)

    def __post_init__(self):
        self.max_bytes = min(safe_int(self.max_bytes), MAX_STREAM)
        if self.deadline is None:
            self.deadline = (
                self.parent.deadline if self.parent is not None else time.monotonic() + 300
            )
        if self.parent is not None:
            self.deadline = min(self.deadline, self.parent.deadline)
            self.costs = self.parent.costs
            self.literals = self.parent.literals
            self._key_costs = self.parent._key_costs

    def charge(self, canonical, requested):
        if time.monotonic() > self.deadline:
            raise ValueError("stream deadline")
        cost = max(canonical, requested)
        if cost > self.max_bytes - self.used:
            raise ValueError("decoded byte budget")
        if self.parent is not None:
            self.parent.charge(canonical, requested)
        self.used += cost


class NodeBudget:
    """A declared canonical bound nested in a shared requested-byte deadline."""

    def __init__(self, parent, canonical_limit):
        self.parent = parent
        self.canonical_limit = safe_int(canonical_limit, minimum=1)
        self.canonical_used = 0
        self.costs = parent.costs
        self.literals = parent.literals
        self._key_costs = parent._key_costs

    @property
    def max_bytes(self):
        return self.parent.max_bytes

    @property
    def used(self):
        return self.parent.used

    def charge(self, canonical, requested):
        if canonical > self.canonical_limit - self.canonical_used:
            raise ValueError("declared logical output bound")
        self.parent.charge(canonical, requested)
        self.canonical_used += canonical


def string_cost(value, ascii=False):
    literal(value)
    if type(value) is str and value.isascii():
        total = 2 + len(value) + value.count('"') + value.count("\\")
        if CONTROL.search(value) is not None:
            total += sum(value.count(c) for c in "\b\f\n\r\t")
            total += 5 * sum(value.count(c) for c in LONG_CONTROL)
        if ascii:
            total += 5 * value.count("\x7f")
        return total
    total = 2
    for char in value:
        code = ord(char)
        if char in '"\\' or char in "\b\f\n\r\t":
            total += 2
        elif code < 32 or (ascii and code >= 127):
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
    node_observer=None,
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
    position = 0

    def emit(raw):
        budget.charge(len(raw), len(raw))
        if observer is not None:
            observer(raw)
        return raw

    def quoted(value):
        if value not in budget.costs:
            budget.costs[value] = (string_cost(value), string_cost(value, True))
        canonical, escaped = budget.costs[value]
        budget.charge(canonical, escaped if ascii else canonical)
        if observer is not None:
            observer(budget.literals.quoted(value))
        return budget.literals.quoted(value, ascii=ascii)

    def node(level, location):
        nonlocal position
        if node_observer is not None:
            node_observer("start", location, position)
        if level > MAX_DEPTH:
            raise ValueError("decoder depth")
        try:
            token = next(tokens)
            position += 1
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
        if node_observer is not None:
            node_observer("end", location, position)

    try:
        yield from node(depth, tuple(path))
        try:
            next(tokens)
        except StopIteration:
            return
        raise ValueError("extra node or invalid range boundary")
    finally:
        if hasattr(tokens, "close"):
            tokens.close()


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


class CatalogReader:
    """Shared stdlib bounded token reader; fetch verifies envelopes and wire bytes."""

    def __init__(self, fetch, catalog, identity, limits):
        self.fetch = fetch
        self.catalog = catalog
        self.identity = identity
        self.limits = limits
        self._strings = self._shapes = None
        self._roots = {}
        self._ranges = {}
        self._validate_table_descriptors(catalog["strings"])
        self._validate_table_descriptors(catalog["shapes"])
        validate_table_transports(catalog)

    @staticmethod
    def _validate_table_descriptors(descriptors):
        first = 0
        for item in descriptors:
            if set(item) != {"part", "first", "count"} or safe_int(item["first"]) != first:
                raise ValueError("table index gap/overlap/order")
            first += safe_int(item["count"], minimum=1)
            validate_descriptor(item["part"])

    def metadata(self):
        return dict(
            **copy.deepcopy(self.identity),
            schema_version=2,
            publication_format="v2",
            roots=list(self.catalog["roots"]),
        )

    def _tables(self):
        if self._strings is not None:
            return self._strings, self._shapes
        values = []
        for name in ("strings", "shapes"):
            table = []
            for item in self.catalog[name]:
                part = self.fetch(item["part"], kind=name)
                if len(part) != item["count"]:
                    raise ValueError("literal table count")
                table.extend(part)
            values.append(table)
        validate_tables(*values)
        self._strings, self._shapes = values
        self._literal_costs = [string_cost(value) for value in self._strings]
        self._layout_costs = [
            2 + max(0, len(keys) - 1) + sum(string_cost(key) + 1 for key in keys)
            for keys in self._shapes
        ]
        return values

    def root(self, name):
        if name not in self.catalog["roots"]:
            raise ValueError("unknown mandatory root")
        if name not in self._roots:
            root = self.fetch(self.catalog["roots"][name], kind="root")
            if root["name"] != name:
                raise ValueError("root name mismatch")
            first = 0
            for page in root["pages"]:
                if safe_int(page["first_token"]) != first:
                    raise ValueError("page gap/overlap/order")
                first += safe_int(page["count"], minimum=1)
                safe_int(page["decoded_upper_bound"], minimum=1)
            safe_int(root["token_count"], minimum=1)
            safe_int(root["logical"]["bytes"], minimum=1)
            if first != root["token_count"]:
                raise ValueError("root token count")
            self._roots[name] = root
        return self._roots[name]

    def ranges(self, name):
        if name not in self._ranges:
            result = {}
            previous = None
            for part in self.root(name)["ranges"]:
                for item in self.fetch(part, kind="ranges"):
                    key = validate_path(item["path"])
                    bound = validate_range(item["range"])
                    order = (bound["first_token"], -bound["end_token"])
                    if (
                        key in result
                        or bound["root"] != name
                        or bound["end_token"] > self.root(name)["token_count"]
                        or (previous is not None and order < previous)
                    ):
                        raise ValueError("range identity/order")
                    previous = order
                    result[key] = bound
            self._ranges[name] = result
        return self._ranges[name]

    def record_routes(self):
        """Bind typed routes to the complete snapshot record array and ranges."""
        rows = []
        for part in self.catalog["routes"]["records"]:
            rows.extend(validate_record_routes(self.fetch(part, kind="record_routes")))
        ranges = self.ranges("snapshot.json")
        parent = ranges[("records",)]
        tokens = self.iter_tokens("snapshot.json", parent["first_token"], parent["end_token"])
        try:
            header = next(tokens)
        finally:
            tokens.close()
        if header != [-1, len(rows)] or type(header[1]) is not int:
            raise ValueError("record route count")
        paths = {path for path in ranges if len(path) == 2 and path[0] == "records"}
        if paths != {("records", i) for i in range(len(rows))}:
            raise ValueError("record route membership")
        first = parent["first_token"] + 1
        for index, row in enumerate(rows):
            bound = ranges[("records", index)]
            expected = dict(
                record_index=index,
                **{k: bound[k] for k in ("first_token", "end_token", "logical_bytes")},
            )
            if row != expected or row["first_token"] != first:
                raise ValueError("record route membership/interval/size")
            first = row["end_token"]
        if first != parent["end_token"]:
            raise ValueError("record route final interval")
        return rows

    def iter_tokens(self, name, first=0, end=None):
        root = self.root(name)
        end = root["token_count"] if end is None else end
        if not 0 <= first < end <= root["token_count"]:
            raise ValueError("token range bounds")
        strings, shapes = self._tables()
        for page in root["pages"]:
            start, finish = page["first_token"], page["first_token"] + page["count"]
            if finish <= first or start >= end:
                continue
            cached = getattr(self, "_token_page", None)
            if cached is not None and cached[0] == page["part"]["sha256"]:
                tokens, cost = cached[1], cached[2]
            else:
                tokens = self.fetch(page["part"], kind="tokens")
                if len(tokens) != page["count"]:
                    raise ValueError("token page count")
                cost = 0
                for token in tokens:
                    if type(token) is int:
                        index = -token - 2
                        if index < 0 or index >= len(strings):
                            raise ValueError("string reference")
                        cost += self._literal_costs[index]
                    elif isinstance(token, list) and len(token) == 1:
                        index = safe_int(token[0])
                        if index >= len(shapes):
                            raise ValueError("shape reference")
                        cost += self._layout_costs[index]
                    elif isinstance(token, list) and token[0] == -1:
                        cost += 2 + max(0, safe_int(token[1]) - 1)
                    elif isinstance(token, list) and token[0] == -2:
                        cost += len(LogicalNumber(token[1], token[2]).lexeme)
                    elif isinstance(token, list) and token[0] == -3:
                        cost += 1
                    else:
                        cost += 4 if token is None or token is True else 5
                self._token_page = (page["part"]["sha256"], tokens, cost)
            if len(tokens) != page["count"] or cost > page["decoded_upper_bound"]:
                raise ValueError("page count/decoded upper bound")
            for token in tokens[max(0, first - start) : min(len(tokens), end - start)]:
                yield list(token) if isinstance(token, list) else token

    def _stream(
        self,
        name,
        first,
        end,
        expected,
        *,
        serialization,
        maximum,
        path=(),
        budget=None,
        number_observer=None,
    ):
        budget = Budget(min(maximum, self.limits["stream"]), parent=budget)
        strings, shapes = self._tables()
        budget.charge(0, 0)
        digest, size = sha256(), 0
        declared = (
            self.ranges(name)
            if first == 0 and end == self.root(name)["token_count"] and not path
            else {}
        )
        active, visited = [], set()
        pending = bytearray()
        limits = [expected["bytes"]]

        def hash_bytes(raw):
            digest.update(raw)
            for current in active:
                current[2].update(raw)

        def flush_hashes():
            if pending:
                hash_bytes(pending)
                pending.clear()

        def node_event(event, location, position):
            bound = declared.get(location)
            if bound is None:
                return
            # Flush before changing membership: every range sees exactly its
            # own bytes, including punctuation, aliases and empty containers.
            flush_hashes()
            if event == "start":
                if position != bound["first_token"]:
                    raise ValueError("range path/start mismatch")
                active.append([location, bound, sha256(), size])
                limits.append(min(limits[-1], size + bound["logical_bytes"]))
                visited.add(location)
            else:
                current = active.pop()
                limits.pop()
                if (
                    current[0] != location
                    or position != bound["end_token"]
                    or size - current[3] != bound["logical_bytes"]
                    or current[2].hexdigest() != bound["logical_sha256"]
                ):
                    raise ValueError("range path/end/digest mismatch")

        def observe(raw):
            nonlocal size
            size += len(raw)
            if size > expected["bytes"]:
                raise ValueError("declared logical output bound")
            # Absolute end offsets enforce every enclosing byte bound before
            # emission without walking the active stack for each tiny fragment.
            if size > limits[-1]:
                raise ValueError("range declared byte bound")
            if len(raw) >= 65_536:
                flush_hashes()
                hash_bytes(raw)  # Already allocated by the decoder; do not copy.
            else:
                if len(pending) + len(raw) > 65_536:
                    flush_hashes()
                pending.extend(raw)

        budget = NodeBudget(budget, expected["bytes"])
        yield from stream_tokens(
            self.iter_tokens(name, first, end),
            strings,
            shapes,
            serialization=serialization,
            budget=budget,
            root=name,
            path=path,
            aliases=lambda target: self.iter_tokens(target),
            validate=False,
            observer=observe,
            number_observer=number_observer,
            node_observer=node_event if declared else None,
        )
        flush_hashes()
        if set(declared) != visited:
            raise ValueError("unvisited range path")
        if size != expected["bytes"] or (
            expected["sha256"] is not None and digest.hexdigest() != expected["sha256"]
        ):
            raise ValueError("logical root/range digest mismatch")

    def stream_root(self, name, serialization="logical"):
        budget = Budget(self.limits["stream"])
        root = self.root(name)
        budget.charge(0, 0)
        return self._stream(
            name,
            0,
            root["token_count"],
            root["logical"],
            serialization=serialization,
            maximum=self.limits["stream"],
            budget=budget,
        )

    def materialize_range(
        self, bound, *, max_bytes=None, path=None, budget=None, serialization="logical"
    ):
        validate_range(bound)
        maximum = min(
            self.limits["selected"] if max_bytes is None else safe_int(max_bytes),
            self.limits["selected"],
        )
        if bound["logical_bytes"] > maximum:
            raise ValueError("selected byte budget")
        if path is None:
            matches = [p for p, r in self.ranges(bound["root"]).items() if r == bound]
            if not matches:
                raise ValueError("unbound range/path")
            path = matches[0]
        elif self.ranges(bound["root"]).get(validate_path(path)) != bound:
            raise ValueError("unbound range/path")
        path = tuple(path)
        raw = bytearray()
        kinds = deque()
        for chunk in self._stream(
            bound["root"],
            bound["first_token"],
            bound["end_token"],
            dict(bytes=bound["logical_bytes"], sha256=bound["logical_sha256"]),
            serialization=serialization,
            maximum=maximum,
            path=path,
            number_observer=lambda number: kinds.append(number.kind),
            budget=budget,
        ):
            raw.extend(chunk)

        def number(lexeme):
            return int(lexeme) if kinds.popleft() == "i" else float(lexeme)

        return strict_loads(raw, max_bytes=maximum, parse_int=number, parse_float=number)

    def field(self, root, *path):
        return self.materialize_range(self.ranges(root)[tuple(path)], path=path)


def charge_value(value, budget, *, ascii=True, depth=0, spaced=False):
    """Precharge a logical value without constructing its encoded JSON string."""
    if depth > MAX_DEPTH:
        raise ValueError("value depth")
    if isinstance(value, str):
        if value not in budget.costs:
            budget.costs[value] = (string_cost(value), string_cost(value, True))
        canonical, escaped = budget.costs[value]
        budget.charge(canonical, escaped if ascii else canonical)
    elif value is None or type(value) is bool:
        size = 4 if value is None or value else 5
        budget.charge(size, size)
    elif type(value) is int:
        # A lower bound permits rejecting huge integers before decimal conversion.
        lower = max(1, (value.bit_length() - 1) * 301 // 1000)
        if lower > budget.max_bytes - budget.used:
            raise ValueError("number byte budget")
        size = len(str(value))
        budget.charge(size, size)
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError("nonfinite number")
        size = len(repr(value))
        budget.charge(size, size)
    elif isinstance(value, (dict, list, tuple)):
        size = 2 + max(0, len(value) - 1)
        budget.charge(size, size + (max(0, len(value) - 1) if spaced else 0))
        for key, item in value.items() if isinstance(value, dict) else enumerate(value):
            if isinstance(value, dict):
                if type(key) is str:
                    # Key costs are invocation-local and pure only for built-ins.
                    # A separate map prevents subclass value hash/equality collisions.
                    if key not in budget._key_costs:
                        budget._key_costs[key] = (string_cost(key), string_cost(key, True))
                    canonical, escaped = budget._key_costs[key]
                    budget.charge(canonical + 1, (escaped if ascii else canonical) + 1 + spaced)
                else:
                    budget.charge(string_cost(key) + 1, string_cost(key, ascii) + 1 + spaced)
            charge_value(item, budget, ascii=ascii, depth=depth + 1, spaced=spaced)
    else:
        raise ValueError("unsupported logical value")
