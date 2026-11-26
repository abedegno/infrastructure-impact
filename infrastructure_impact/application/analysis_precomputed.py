"""Bounded gzip transport for exact, ordinary native analysis selections."""

import gzip
import json
import re
import zlib
from hashlib import sha256
from io import BytesIO
from pathlib import Path

from .. import publication_codec as codec
from . import switching_analysis as analysis
from . import switching_comparison as comparison

ROOT = "switching-analysis-selected.json"
SLICE = 4_000_000
MANIFEST_MAX = 2_000_000
MAX_VIEWS = 32
HEADER = bytes.fromhex("1f8b08000000000000ff")
DEFAULT_OPTION = dict(vendor=None, window="all", scope_level="os_family", cve_ids=None)
IDENTITY = ("publication", "generated_at", "definition_sha256", "observation_end")


def compact_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def manifest_descriptor(root):
    logical = root["logical"]
    _decoded(logical, MANIFEST_MAX)
    return f"data/v2/{logical['sha256']}.json", logical


def _fields(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError("Invalid selected delivery fields")


def _hash(value):
    if not isinstance(value, str) or not codec.HASH.fullmatch(value):
        raise ValueError("Invalid selected delivery fingerprint")


def _decoded(value, limit):
    _fields(value, ("bytes", "sha256"))
    _hash(value["sha256"])
    if codec.safe_int(value["bytes"], minimum=1) > limit:
        raise ValueError("Selected analysis decoded byte budget")


def _options(value, end):
    if not isinstance(value, dict) or value.keys() - DEFAULT_OPTION.keys():
        raise ValueError("Invalid precomputed analysis options")
    option = DEFAULT_OPTION | value
    if (
        option["vendor"] not in (None, *comparison.VENDORS)
        or option["scope_level"] not in ("os_family", "model_qualified")
        or option["cve_ids"] is not None
    ):
        raise ValueError("Invalid precomputed analysis options")
    comparison._bounds(analysis.contracts.definition(), end, option["window"])
    return option


def _key(options):
    return options["vendor"], options["scope_level"], options["window"]


def options_for(source, options):
    if options is None:
        end = source["observation_end"]
        previous = str(int(end[:4]) - 1)
        start = analysis.contracts.definition()["start_date"]
        windows = ("all", previous) if int(previous) >= int(start[:4]) else ("all",)
        options = [
            dict(vendor=vendor, window=window)
            for vendor in (None, *comparison.VENDORS)
            for window in windows
        ]
    if not isinstance(options, (list, tuple)) or not 1 <= len(options) <= MAX_VIEWS:
        raise ValueError("Invalid precomputed analysis option count")
    result = [_options(option, source["observation_end"]) for option in options]
    if len({_key(option) for option in result}) != len(result):
        raise ValueError("Duplicate precomputed analysis options")
    return result


def encode_view(report, options, write_part):
    """Encode an already selected candidate for transport; this grants no source authority."""
    codec.charge_value(report, codec.Budget(codec.MAX_SELECTED), ascii=False)
    raw = memoryview(compact_bytes(report))
    if not 1 <= len(raw) <= codec.MAX_SELECTED:
        raise ValueError("Selected analysis decoded byte budget")
    chunks = []
    for offset in range(0, len(raw), SLICE):
        decoded = raw[offset : offset + SLICE]
        output = BytesIO()
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=6) as z:
            z.write(decoded)
        wire = output.getvalue()
        if len(wire) > codec.MAX_PART:
            raise ValueError("Selected analysis physical byte budget")
        digest = sha256(wire).hexdigest()
        path = f"data/v2/{digest}.json.gz"
        if write_part is not None:
            write_part(path, wire)
        chunks.append(
            dict(
                offset=offset,
                part=dict(path=path, sha256=digest, bytes=len(wire)),
                decoded=dict(bytes=len(decoded), sha256=sha256(decoded).hexdigest()),
            )
        )
    return dict(
        options=options,
        selection=report["selection"],
        decoded=dict(bytes=len(raw), sha256=sha256(raw).hexdigest()),
        chunks=chunks,
    )


def build_manifest(source_header, views):
    manifest = dict(
        schema_version=1,
        representation="analysis-selected-delivery",
        **{k: source_header[k] for k in IDENTITY},
        source_content_sha256=source_header["content_sha256"],
        views=views,
    )
    return validate_manifest(manifest, source_header)


def validate_manifest(manifest, identity):
    _fields(
        manifest, ("schema_version", "representation", *IDENTITY, "source_content_sha256", "views")
    )
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or (manifest["representation"] != "analysis-selected-delivery")
    ):
        raise ValueError("Invalid selected delivery manifest")
    publication = manifest["publication"]
    if publication is not None:
        _fields(publication, ("id", "advisory_schema_version"))
        if (
            not isinstance(publication["id"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", publication["id"])
            or type(publication["advisory_schema_version"]) is not int
            or publication["advisory_schema_version"] != 2
        ):
            raise ValueError("Invalid selected delivery publication")
    for k in IDENTITY:
        if (k in identity or k in ("publication", "generated_at")) and manifest[k] != identity.get(
            k
        ):
            raise ValueError("Selected delivery identity differs")
    if (
        manifest["definition_sha256"] != analysis._hash(analysis.contracts.definition())
        or not isinstance(manifest["generated_at"], str)
        or manifest["observation_end"] != comparison.day(manifest["generated_at"])
        or manifest["observation_end"] is None
        or manifest["observation_end"] < analysis.contracts.definition()["start_date"]
    ):
        raise ValueError("Selected delivery definition/cutoff differs")
    _hash(manifest["source_content_sha256"])
    if (
        "content_sha256" in identity
        and manifest["source_content_sha256"] != identity["content_sha256"]
    ):
        raise ValueError("Selected delivery source fingerprint differs")

    views = manifest["views"]
    if not isinstance(views, list) or not 1 <= len(views) <= MAX_VIEWS:
        raise ValueError("Invalid selected delivery view count")
    seen, physical = set(), {}
    for view in views:
        _fields(view, ("options", "selection", "decoded", "chunks"))
        option = view["options"]
        _fields(option, DEFAULT_OPTION)
        option = _options(option, manifest["observation_end"])
        key = _key(option)
        if key in seen:
            raise ValueError("Duplicate selected delivery options")
        seen.add(key)
        selection = view["selection"]
        expected = analysis.selection_context(manifest, option)["selection"]
        _fields(selection, expected)
        cves = selection["effective_cve_ids"]
        if not isinstance(cves, list):
            raise ValueError("Invalid selected delivery cohort")
        comparison._selection_evaluation(
            option["vendor"], option["scope_level"], cves, manifest["generated_at"]
        )
        expected["effective_cve_ids"] = sorted(set(cves))
        if selection != expected:
            raise ValueError("Selected delivery cohort differs")
        _decoded(view["decoded"], codec.MAX_SELECTED)
        total = view["decoded"]["bytes"]
        chunks = view["chunks"]
        if not isinstance(chunks, list) or len(chunks) != (total + SLICE - 1) // SLICE:
            raise ValueError("Selected delivery slice count differs")
        for i, chunk in enumerate(chunks):
            _fields(chunk, ("offset", "decoded", "part"))
            offset = i * SLICE
            if codec.safe_int(chunk["offset"]) != offset:
                raise ValueError("Selected delivery slice offset differs")
            size = min(SLICE, total - offset)
            _decoded(chunk["decoded"], size)
            if chunk["decoded"]["bytes"] != size:
                raise ValueError("Selected delivery slice size differs")
            part = chunk["part"]
            codec._validate_table_transport_descriptor(part)
            binding = (part, chunk["decoded"])
            if physical.setdefault(part["path"], binding) != binding:
                raise ValueError("Conflicting selected delivery slice descriptor")
    codec.charge_value(manifest, codec.Budget(MANIFEST_MAX), ascii=False)
    return manifest


def _derive(source, options, write_part):
    return build_manifest(
        source,
        [
            encode_view(
                analysis._select_report_validated(
                    source, analysis.selection_context(source, option)
                ),
                option,
                write_part,
            )
            for option in options_for(source, options)
        ],
    )


def _write_views_validated(destination, source, options=None):
    destination = Path(destination)
    (destination / "data/v2").mkdir(parents=True, exist_ok=True)
    return _derive(source, options, lambda path, raw: (destination / path).write_bytes(raw))


def write_views(destination, source, options=None):
    """Generate preview parts from independently validated public source facts."""
    analysis.validate_report(source)
    return _write_views_validated(destination, source, options)


def _verify_views(reader, projected, options):
    source = projected["switching_analysis"]
    analysis.validate_report(
        source,
        evidence=projected["switching_evidence"],
        records=projected["records"],
        retained=[item["record"] for item in projected.get("retained_advisories", [])],
        publication=projected["publication"],
        generated_at=projected["generated_at"],
    )
    observed = reader._precomputed_manifest()
    if [_key(v["options"]) for v in observed["views"]] != [
        _key(option) for option in options_for(source, options)
    ]:
        raise ValueError("Native selected analysis option membership differs")

    def compare(path, raw):
        with reader._path(path).open("rb") as stream:
            if stream.read(len(raw) + 1) != raw:
                raise ValueError("Native selected analysis asset differs: " + path)

    expected = _derive(source, options, compare)
    raw_manifest = compact_bytes(expected)
    if compact_bytes(observed) != raw_manifest:
        raise ValueError("Native selected analysis manifest differs")
    path, _ = manifest_descriptor(reader.root(ROOT))
    compare(path, raw_manifest)
    return expected


def match_view(manifest, study):
    selection = study["selection"]
    if selection["requested_cve_ids"] is not None:
        return None
    key = (
        selection["requested_vendor"],
        selection["scope_level"],
        selection["requested_window"],
    )
    view = next((v for v in manifest["views"] if _key(v["options"]) == key), None)
    if view is not None:
        analysis._identity(manifest, study)
        if view["selection"] != selection:
            raise ValueError("Selected analysis cohort differs")
    return view


def _inflate(wire, chunk):
    part, decoded = chunk["part"], chunk["decoded"]
    if len(wire) != part["bytes"] or sha256(wire).hexdigest() != part["sha256"]:
        raise ValueError("Selected analysis compressed bytes/hash mismatch")
    if not wire.startswith(HEADER):
        raise ValueError("Invalid selected analysis gzip header")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        result = decoder.decompress(wire, decoded["bytes"] + 1)
    except zlib.error as exc:
        raise ValueError("Invalid selected analysis gzip") from exc
    if len(result) != decoded["bytes"] or sha256(result).hexdigest() != decoded["sha256"]:
        raise ValueError("Selected analysis decoded bytes/hash mismatch")
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("Truncated or trailing selected analysis gzip")
    return result


def _read_view(view, study, load, max_bytes):
    limit = min(codec.safe_int(max_bytes, minimum=1), codec.MAX_SELECTED)
    decoded = view["decoded"]
    if decoded["bytes"] > limit:
        raise ValueError("Selected analysis decoded byte budget")
    raw = bytearray(decoded["bytes"])
    for chunk in view["chunks"]:
        offset = chunk["offset"]
        result = _inflate(load(chunk["part"]), chunk)
        raw[offset : offset + len(result)] = result
    if sha256(raw).hexdigest() != decoded["sha256"]:
        raise ValueError("Selected analysis aggregate fingerprint differs")
    selected = codec.strict_loads(raw, max_bytes=limit)
    analysis._validate_shape(selected, "selected")
    if selected["availability"] != "available" or selected["selection"] != study["selection"]:
        raise ValueError("Selected analysis report cohort differs")
    for key in (
        "upgrades",
        "disclosure",
        "model_coverage",
        "kev_reconciliation",
        "release_history",
    ):
        child = selected[key]
        analysis._identity(child, study)
        if child["selection"] != study["selection"]:
            raise ValueError("Selected analysis child cohort differs")
    if any(selected[k] != study[k] for k in ("publication", "generated_at")):
        raise ValueError("Selected analysis report identity differs")
    analysis._check_selected_upgrades(selected["upgrades"], shape_checked=True)
    codec.charge_value(selected, codec.Budget(limit), ascii=False)
    return selected


def read_selected(directory, manifest, study, max_bytes=codec.MAX_SELECTED):
    validate_manifest(manifest, study)
    view = match_view(manifest, study)
    if view is None:
        return None
    directory = Path(directory).resolve()

    def load(part):
        path = directory / part["path"]
        if path.is_symlink() or not path.resolve().is_relative_to(directory):
            raise ValueError("Selected analysis path escape")
        with path.open("rb") as stream:
            return stream.read(part["bytes"] + 1)

    return _read_view(view, study, load, max_bytes)
