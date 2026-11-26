"""Lossless table factoring for complete, validated switching analysis."""

import copy
import json

from .. import publication_codec as codec
from . import switching_analysis as analysis

ROOT = "switching-analysis-packed.json"
IDENTITY = ("publication", "generated_at", "definition_sha256", "observation_end")
TABLES = ("claims", "members", "requirements")
FIELDS = {
    "schema_version",
    "representation",
    *IDENTITY,
    "source_content_sha256",
    "source_logical_bytes",
    "skeleton_json",
    "layouts",
    "values_json",
    "tables",
    "counts",
    "content_sha256",
}
# Keep even highly escaped literals comfortably below v2's per-part limit.
CHUNK = 65_536
DEFS = analysis._SCHEMA["$defs"]
ROW_SHAPES = {
    "claims": DEFS["compiled"]["properties"]["claims"]["additionalProperties"],
    "members": DEFS["compact"]["properties"]["members"]["additionalProperties"],
    "requirements": DEFS["compact"]["properties"]["requirements"]["items"],
}


def _compact(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _chunks(text):
    return [text[start : start + CHUNK] for start in range(0, len(text), CHUNK)]


def _maximum(max_bytes):
    return min(codec.safe_int(max_bytes, minimum=1), codec.MAX_SELECTED)


def _digest(value):
    return analysis._hash({k: v for k, v in value.items() if k != "content_sha256"})


def pack_report(source, *, max_bytes=codec.MAX_SELECTED):
    """Validate the complete source before constructing a packed report."""
    analysis.validate_report(source)
    return _pack_validated(source, max_bytes=max_bytes)


def _pack_validated(source, *, max_bytes=codec.MAX_SELECTED):
    """Derive from the private writer's freshly validated complete source."""
    max_bytes = _maximum(max_bytes)
    source_bytes = codec.Budget(max_bytes)
    codec.charge_value(source, source_bytes, ascii=False)
    requirements = source["requirements"]
    skeleton = dict(source, claims=None)
    skeleton["requirements"] = dict(requirements, members=None, requirements=None)
    values, layouts, tables = [], [], {}
    value_ids, string_ids, layout_ids = {}, {}, {}

    def pool(value):
        if type(value) is str and value in string_ids:
            return string_ids[value]
        literal = _compact(value)
        index = value_ids.get(literal)
        if index is None:
            index = value_ids[literal] = len(values)
            values.append(_chunks(literal))
        if type(value) is str:
            string_ids[value] = index
        return index

    for name, source_table in (
        ("claims", source["claims"]),
        ("members", requirements["members"]),
        ("requirements", requirements["requirements"]),
    ):
        rows = tables[name] = []
        keyed = name != "requirements"
        for key, values_by_field in source_table.items() if keyed else enumerate(source_table):
            row = [pool(key)] if keyed else []
            layout = tuple(values_by_field)
            index = layout_ids.get(layout)
            if index is None:
                index = layout_ids[layout] = len(layouts)
                layouts.append(list(layout))
            row.append(index)
            row.extend(pool(value) for value in values_by_field.values())
            rows.append(row)
    packed = dict(
        schema_version=1,
        representation="packed-analysis",
        **{key: copy.deepcopy(source[key]) for key in IDENTITY},
        source_content_sha256=source["content_sha256"],
        source_logical_bytes=source_bytes.used,
        skeleton_json=_chunks(_compact(skeleton)),
        layouts=layouts,
        values_json=values,
        tables=tables,
        counts={name: len(rows) for name, rows in tables.items()},
        content_sha256="0" * 64,
    )
    codec.charge_value(packed, codec.Budget(max_bytes), ascii=False)
    packed["content_sha256"] = _digest(packed)
    return packed


def _text(raw, maximum):
    if (
        type(raw) is not list
        or not raw
        or (len(raw) - 1) * CHUNK >= maximum
        or any(type(piece) is not str or len(piece) != CHUNK for piece in raw[:-1])
        or type(raw[-1]) is not str
        or not 0 < len(raw[-1]) <= CHUNK
    ):
        raise ValueError("Invalid packed analysis literal chunks")
    # The enclosing byte budget has already charged every chunk, before joining.
    return "".join(raw)


def _parse(raw, maximum):
    raw = raw.encode("utf-8")
    value = codec.strict_loads(raw, max_bytes=maximum)
    if _compact(value).encode("utf-8") != raw:
        raise ValueError("Invalid packed analysis compact JSON literal")
    return value, len(raw)


def _index(value, length):
    index = codec.safe_int(value)
    if index >= length:
        raise ValueError("Packed analysis index out of range")
    return index


def _preflight(packed, skeleton_bytes, pool, costs):
    layouts = packed["layouts"]
    if type(layouts) is not list or type(packed["tables"]) is not dict:
        raise ValueError("Invalid packed analysis layout or tables")
    if (
        set(packed["tables"]) != set(TABLES)
        or type(packed["counts"]) is not dict
        or set(packed["counts"]) != set(TABLES)
    ):
        raise ValueError("Invalid packed analysis table counts")
    layout_seen, layout_costs = set(), []
    allowed = set().union(*(row["properties"] for row in ROW_SHAPES.values()))
    for layout in layouts:
        if (
            type(layout) is not list
            or not layout
            or len(layout) > len(allowed)
            or any(type(key) is not str or key not in allowed for key in layout)
            or len(set(layout)) != len(layout)
        ):
            raise ValueError("Invalid packed analysis layout")
        keys = tuple(layout)
        if keys in layout_seen:
            raise ValueError("Duplicate packed analysis layout")
        layout_seen.add(keys)
        layout_costs.append(2 + len(keys) - 1 + sum(codec.string_cost(k) + 1 for k in keys))

    quota = codec.Budget(packed["source_logical_bytes"])
    quota.charge(skeleton_bytes - 12, skeleton_bytes - 12)
    used_layouts, used_values = set(), set()
    for name, shape in ROW_SHAPES.items():
        rows = packed["tables"][name]
        if type(rows) is not list or len(rows) != codec.safe_int(packed["counts"][name]):
            raise ValueError("Invalid packed analysis row counts")
        layout_domain = [
            set(shape["required"]).issubset(keys) and set(keys).issubset(shape["properties"])
            for keys in layouts
        ]
        base = 2 + max(0, len(rows) - 1)
        quota.charge(base, base)
        keyed = name != "requirements"
        prefix = 2 if keyed else 1
        keys_seen = set()
        for row in rows:
            if type(row) is not list or len(row) < prefix:
                raise ValueError("Invalid packed analysis row")
            layout_index = _index(row[prefix - 1], len(layouts))
            if len(row) != prefix + len(layouts[layout_index]):
                raise ValueError("Invalid packed analysis row length")
            if not layout_domain[layout_index]:
                raise ValueError("Invalid packed analysis table layout")
            used_layouts.add(layout_index)
            size = layout_costs[layout_index]
            if keyed:
                index = _index(row[0], len(pool))
                key = pool[index]
                if type(key) is not str or not codec.HASH.fullmatch(key):
                    raise ValueError("Invalid packed analysis row key")
                if key in keys_seen:
                    raise ValueError("Duplicate packed analysis row key")
                keys_seen.add(key)
                used_values.add(index)
                size += costs[index] + 1
            for cell in row[prefix:]:
                index = _index(cell, len(pool))
                used_values.add(index)
                size += costs[index]
            quota.charge(size, size)
    if quota.used != quota.max_bytes:
        raise ValueError("Packed analysis source byte budget differs")
    if len(used_layouts) != len(layouts) or len(used_values) != len(pool):
        raise ValueError("Packed analysis pool/layout closure differs")


def _expand_tables(packed, skeleton, pool):
    for name in TABLES:
        keyed = name != "requirements"
        target = {} if keyed else []
        for row in packed["tables"][name]:
            prefix = 2 if keyed else 1
            layout = packed["layouts"][row[prefix - 1]]
            value = {
                key: copy.deepcopy(pool[cell])
                for key, cell in zip(layout, row[prefix:], strict=True)
            }
            if keyed:
                target[pool[row[0]]] = value
            else:
                target.append(value)
        owner = skeleton if name == "claims" else skeleton["requirements"]
        owner[name] = target


def unpack_report(packed, *, max_bytes=codec.MAX_SELECTED):
    """Check all bounds and references before reconstructing owned compiled analysis."""
    max_bytes = _maximum(max_bytes)
    if (
        type(packed) is not dict
        or set(packed) != FIELDS
        or type(packed["schema_version"]) is not int
        or packed["schema_version"] != 1
        or packed["representation"] != "packed-analysis"
        or type(packed["source_content_sha256"]) is not str
        or not codec.HASH.fullmatch(packed["source_content_sha256"])
    ):
        raise ValueError("Invalid packed analysis envelope")
    source_bytes = codec.safe_int(packed["source_logical_bytes"], minimum=1)
    if source_bytes > max_bytes:
        raise ValueError("Packed analysis source byte budget")
    codec.charge_value(packed, codec.Budget(max_bytes), ascii=False)
    if packed["content_sha256"] != _digest(packed):
        raise ValueError("Packed analysis fingerprint differs")
    skeleton, size = _parse(_text(packed["skeleton_json"], max_bytes), max_bytes)
    if (
        type(skeleton) is not dict
        or "claims" not in skeleton
        or skeleton["claims"] is not None
        or type(skeleton.get("requirements")) is not dict
        or any(
            k not in skeleton["requirements"] or skeleton["requirements"][k] is not None
            for k in ("members", "requirements")
        )
    ):
        raise ValueError("Invalid packed analysis table placeholders")
    if any(_compact(packed[key]) != _compact(skeleton.get(key)) for key in IDENTITY):
        raise ValueError("Packed analysis source identity differs")
    if packed["source_content_sha256"] != skeleton.get("content_sha256"):
        raise ValueError("Packed analysis source fingerprint differs")
    if type(packed["values_json"]) is not list:
        raise ValueError("Invalid packed analysis value pool")
    seen, pool, costs = set(), [], []
    for entry in packed["values_json"]:
        raw = _text(entry, max_bytes)
        if raw in seen:
            raise ValueError("Duplicate packed analysis pool value")
        seen.add(raw)
        value, cost = _parse(raw, max_bytes)
        pool.append(value)
        costs.append(cost)
    _preflight(packed, size, pool, costs)
    _expand_tables(packed, skeleton, pool)
    analysis.validate_report(skeleton)
    return skeleton
