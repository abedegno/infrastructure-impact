"""Direct, opt-in bounded publication of the sanitized public projection."""

import gzip
import json
from collections import deque
from functools import lru_cache
from hashlib import sha256
from pathlib import Path

from .. import publication_codec as codec
from ..phase_events import phase
from ..settings import PACKAGE

PART = 8_000_000
INDEX = 2_000_000
EXPANDED = 128_000_000
COMPRESSED = 8_000_000
SITE = 1_000_000_000
TARGET = 512_000
PAGE_LOGICAL = 1_000_000
DEFERRED = (
    "advisory_ids",
    "affected_advisory_ids",
    "cve_ids",
    "claim_ids",
    "conditional_cve_ids",
    "event_ids",
    "events",
)


def publication_format(value):
    if value not in ("v1", "v2"):
        raise ValueError("publication_format must be v1 or v2")
    return value


def encode(value):
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n"
    ).encode()


@lru_cache(maxsize=1)
def validators():
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource

    schemas = {}
    for path in (PACKAGE / "schemas").glob("*.json"):
        schema = json.loads(path.read_text())
        schemas[path.name] = schema
    schemas["kev-v1.json"]["$id"] = "urn:infrastructure-impact:kev:1"
    registry = Registry().with_resources(
        (s["$id"], Resource.from_contents(s)) for s in schemas.values() if "$id" in s
    )
    return {
        name: Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
        for name, schema in schemas.items()
    }


def validate(value, name):
    validators()[name].validate(value)


def validate_envelope(value, kind):
    """Validate the complete envelope against its disjoint, literal kind branch.

    Trying every branch can run quadratic uniqueItems checks for string tables
    against unrelated arrays of objects, even after their kind has failed.
    """
    validator = validators()["publication-v2.json"]
    variants = validator.schema["$defs"]["envelope"]["oneOf"]
    matches = [
        i for i, branch in enumerate(variants) if branch["properties"]["kind"]["const"] == kind
    ]
    if len(matches) != 1:
        raise ValueError("unknown or ambiguous publication envelope kind")
    validator.evolve(
        schema={
            "$ref": f"urn:infrastructure-impact:publication:2#/$defs/envelope/oneOf/{matches[0]}"
        }
    ).validate(value)


class Writer:
    def __init__(self, destination, identity):
        self.destination = Path(destination)
        (self.destination / "data/v2").mkdir(parents=True, exist_ok=True)
        self.identity = identity
        self.encoder = codec.Encoder()
        self.roots = {}
        self.root_data = {}
        self.root_ranges = {}
        self.detail_entries = dict(sources=[], diagnostics=[])
        self.snapshot_tables = None
        self.snapshot_members = []
        self.claim_intervals = []
        self.record_intervals = []
        self.string_parts = []
        self.shape_parts = []

    def part(self, kind, data):
        raw = encode(dict(schema_version=2, **self.identity, kind=kind, data=data))
        if len(raw) > PART:
            raise ValueError("v2 part exceeds 8 MB")
        digest = sha256(raw).hexdigest()
        path = "data/v2/" + digest + ".json"
        (self.destination / path).write_bytes(raw)
        return dict(path=path, sha256=digest, bytes=len(raw))

    def chunks(self, kind, values):
        result, batch, size = [], [], 0
        for value in values:
            length = len(encode(value))
            if batch and size + length > TARGET:
                result.append(self.part(kind, batch))
                batch, size = [], 0
            batch.append(value)
            size += length
        if batch:
            result.append(self.part(kind, batch))
        return result

    @staticmethod
    def ranged(name, path):
        if len(path) <= 1:
            return True
        if name == "snapshot.json":
            return (path[0] in ("records", "retained_advisories") and len(path) == 2) or (
                path[0] == "switching_comparison"
                and (len(path) == 2 or (path[1] == "rows" and len(path) in (3, 4)))
            )
        if name == "switching-evidence.json":
            return path[0] == "claims" and len(path) == 2
        return name == "switching-comparison.json" and path == ("inputs", "kev")

    def root(self, name, value, *, alias=None):
        pages, ranges, active = [], [], []
        tokens, encoded, decoded, position, page_first = [], 0, 0, 0, 0
        root_hash, root_bytes, ascii_bytes = sha256(), 0, 0
        ascii_hash = sha256() if name == "snapshot.json" else None

        pending, ascii_pending = bytearray(), bytearray()

        def hash_bytes(raw, ascii_raw):
            root_hash.update(raw)
            if ascii_hash is not None:
                ascii_hash.update(ascii_raw)
            for item in active:
                item["hash"].update(raw)

        def flush_hashes():
            if pending:
                hash_bytes(pending, ascii_pending)
                pending.clear()
                ascii_pending.clear()

        def logical(raw, ascii_raw=None):
            nonlocal root_bytes, ascii_bytes
            ascii_raw = raw if ascii_raw is None else ascii_raw
            root_bytes += len(raw)
            ascii_bytes += len(ascii_raw)
            if root_bytes > SITE or ascii_bytes > SITE:
                raise ValueError("root stream exceeds 1 GB")
            if len(raw) >= 65_536 or ascii_hash is not None and len(ascii_raw) >= 65_536:
                flush_hashes()
                hash_bytes(raw, ascii_raw)
            else:
                if len(pending) + len(raw) > 65_536 or (
                    ascii_hash is not None and len(ascii_pending) + len(ascii_raw) > 65_536
                ):
                    flush_hashes()
                pending.extend(raw)
                if ascii_hash is not None:
                    ascii_pending.extend(ascii_raw)

        def flush():
            nonlocal tokens, encoded, decoded, page_first
            if tokens:
                part = self.part("tokens", tokens)
                pages.append(
                    dict(
                        part=part,
                        first_token=page_first,
                        count=len(tokens),
                        decoded_upper_bound=max(1, decoded),
                    )
                )
                page_first += len(tokens)
                tokens, encoded, decoded = [], 0, 0

        def token(item, cost):
            nonlocal position, encoded, decoded
            length = len(encode(item))
            if tokens and (encoded + length > TARGET or decoded + cost > PAGE_LOGICAL):
                flush()
            tokens.append(item)
            encoded += length
            decoded += cost
            position += 1

        def walk(node, path=(), depth=0):
            if depth > codec.MAX_DEPTH:
                raise ValueError("encoder depth")
            detail_kind = (
                "sources"
                if name == "snapshot.json"
                and len(path) == 3
                and path[:2] == ("switching_comparison", "sources")
                else "diagnostics"
                if name == "switching-evidence.json"
                and len(path) == 2
                and path[0] == "score_availability"
                else None
            )
            marked = self.ranged(name, path) or detail_kind is not None
            if marked:
                flush_hashes()
                marker = dict(
                    path=path,
                    first=position,
                    hash=sha256() if path else root_hash,
                    start_bytes=root_bytes,
                )
                if path:
                    active.append(marker)
            if alias is not None and path == ("inputs", "evidence"):
                token([-3, "switching-evidence.json"], 1)
                # Exact equality is proved by caller. Stream canonical literals
                # solely to hash this root; no expansion enters its token pages.
                utf8 = json.JSONEncoder(
                    ensure_ascii=False, allow_nan=False, separators=(",", ":")
                ).iterencode(node)
                ascii = json.JSONEncoder(
                    ensure_ascii=True, allow_nan=False, separators=(",", ":")
                ).iterencode(node)
                for chunk, ascii_chunk in zip(utf8, ascii, strict=True):
                    logical(chunk.encode(), ascii_chunk.encode())
            elif isinstance(node, dict):
                shape = tuple(codec.literal(k) for k in node)
                if shape not in self.encoder._shapes:
                    self.encoder._shapes[shape] = len(self.encoder.shapes)
                    self.encoder.shapes.append(list(shape))
                token(
                    [self.encoder._shapes[shape]],
                    2 + max(0, len(node) - 1) + sum(codec.string_cost(k) + 1 for k in node),
                )
                logical(b"{")
                for i, (key, child) in enumerate(node.items()):
                    if i:
                        logical(b",")
                    raw = json.dumps(key, ensure_ascii=False).encode()
                    # ensure_ascii also escapes DEL, although it is an ASCII byte.
                    ascii_raw = (
                        raw if raw.isascii() and b"\x7f" not in raw else json.dumps(key).encode()
                    )
                    logical(raw, ascii_raw)
                    logical(b":")
                    walk(child, path + (key,), depth + 1)
                logical(b"}")
            elif isinstance(node, (list, tuple)):
                token([-1, len(node)], 2 + max(0, len(node) - 1))
                logical(b"[")
                for i, child in enumerate(node):
                    if i:
                        logical(b",")
                    walk(child, path + (i,), depth + 1)
                logical(b"]")
            else:
                item = next(self.encoder.encode(node))
                raw = json.dumps(
                    node, ensure_ascii=False, allow_nan=False, separators=(",", ":")
                ).encode()
                token(item, len(raw))
                ascii_raw = (
                    raw
                    if raw.isascii() and b"\x7f" not in raw
                    else json.dumps(node, allow_nan=False, separators=(",", ":")).encode()
                )
                logical(raw, ascii_raw)
            if marked:
                flush_hashes()
                if path:
                    active.pop()
                bound = dict(
                    root=name,
                    first_token=marker["first"],
                    end_token=position,
                    logical_bytes=root_bytes - marker["start_bytes"],
                    logical_sha256=marker["hash"].hexdigest(),
                )
                if detail_kind is not None:
                    entry = dict(ordinal=path[-1], range=bound)
                    if detail_kind == "diagnostics":
                        entry["vendor"] = node["vendor"]
                    self.detail_entries[detail_kind].append(entry)
                elif not (
                    name == "switching-evidence.json" and len(path) == 2 and path[0] == "claims"
                ):
                    ranges.append(dict(path=list(path), range=bound))
                if name == "switching-evidence.json" and len(path) == 2 and path[0] == "claims":
                    self.claim_intervals.append((node["claim_id"], bound))
                if name == "snapshot.json" and len(path) == 2 and path[0] == "records":
                    self.record_intervals.append(
                        dict(
                            record_index=path[1],
                            first_token=bound["first_token"],
                            end_token=bound["end_token"],
                            logical_bytes=bound["logical_bytes"],
                        )
                    )

        walk(value)
        flush()
        ranges.sort(key=lambda item: (item["range"]["first_token"], -item["range"]["end_token"]))
        range_parts = self.chunks("ranges", ranges)
        data = dict(
            name=name,
            token_count=position,
            logical=dict(bytes=root_bytes, sha256=root_hash.hexdigest()),
            pages=pages,
            ranges=range_parts,
        )
        self.roots[name] = self.part("root", data)
        self.root_data[name] = data
        self.root_ranges[name] = {tuple(r["path"]): r["range"] for r in ranges}
        if name == "snapshot.json":
            self.snapshot_tables = (len(self.encoder.strings), len(self.encoder.shapes))
            self.snapshot_members = [self.roots[name], *range_parts, *(p["part"] for p in pages)]
            ascii_hash.update(b"\n")
            self.legacy_snapshot = dict(bytes=ascii_bytes + 1, sha256=ascii_hash.hexdigest())
        return self.roots[name]

    def detail_indexes(self):
        """Optional paging metadata, deliberately absent from ordinary root ranges."""
        indexes = {}
        for kind, entries in self.detail_entries.items():
            chunks, batch, size = [], [], 0

            def flush():
                nonlocal batch, size
                if not batch:
                    return
                vendors = {}
                for entry in batch:
                    if "vendor" in entry:
                        vendor = entry["vendor"]
                        vendors[vendor] = vendors.get(vendor, 0) + 1
                chunks.append(
                    dict(
                        first=batch[0]["ordinal"],
                        count=len(batch),
                        vendors=vendors,
                        part=self.part("detail_index", batch),
                    )
                )
                batch, size = [], 0

            for entry in entries:
                length = len(encode(entry))
                if batch and size + length > TARGET:
                    flush()
                batch.append(entry)
                size += length
            flush()
            indexes[kind] = chunks
        return indexes

    def tables(self):
        for kind, values, boundary, result in [
            ("strings", self.encoder.strings, self.snapshot_tables[0], self.string_parts),
            ("shapes", self.encoder.shapes, self.snapshot_tables[1], self.shape_parts),
        ]:
            first = 0
            for section in (values[:boundary], values[boundary:]):
                for part in self.chunks(kind, section):
                    count = len(
                        codec.strict_loads((self.destination / part["path"]).read_bytes())["data"]
                    )
                    result.append(dict(part=part, first=first, count=count))
                    if first < boundary:
                        self.snapshot_members.append(part)
                    first += count

    def routes(self):
        claims, batch, base, previous, size = [], [], None, None, 0
        for claim, bound in self.claim_intervals:
            first, end = bound["first_token"], bound["end_token"]
            if previous is not None and first != previous:
                raise ValueError("noncontiguous original claim intervals")
            row = [
                self.encoder.atom(claim),
                0 if not batch else first - batch[-1][1],
                bound["logical_bytes"],
            ]
            # Keep absolute positions privately while encoding deltas separately.
            if batch and size + len(encode(row)) > TARGET:
                rows = [
                    [atom, 0 if i == 0 else start - batch[i - 1][1], count]
                    for i, (atom, start, count) in enumerate(batch)
                ]
                claims.append(
                    self.part("claim_routes", dict(base=base, final_end=first, rows=rows))
                )
                batch, base, size = [], None, 0
            if base is None:
                base = first
            batch.append((row[0], first, row[2]))
            size += len(encode(row))
            previous = end
        if batch:
            rows = [
                [atom, 0 if i == 0 else start - batch[i - 1][1], count]
                for i, (atom, start, count) in enumerate(batch)
            ]
            claims.append(self.part("claim_routes", dict(base=base, final_end=previous, rows=rows)))
        records = self.chunks("record_routes", self.record_intervals)
        self.snapshot_members.extend(records)
        return dict(claims=claims, records=records)

    def overview(self, report):
        ranges = self.root_ranges["snapshot.json"]
        overview = {
            k: v
            for k, v in report.items()
            if k not in ("rows", "sources", "schema_version", "representation")
        }
        overview.update(
            schema_version=2,
            representation="switching-overview",
            rows=[],
            detail_ranges=dict(sources=ranges[("switching_comparison", "sources")]),
        )
        for i, row in enumerate(report["rows"]):
            overview["rows"].append(
                {
                    **{k: v for k, v in row.items() if k not in DEFERRED},
                    "detail_ranges": {
                        k: ranges[("switching_comparison", "rows", i, k)] for k in DEFERRED
                    },
                }
            )
        validate(overview, "switching-overview-v2.json")
        return overview

    def archive(self, records):
        strings = [p for p in self.string_parts if p["first"] < self.snapshot_tables[0]]
        shapes = [p for p in self.shape_parts if p["first"] < self.snapshot_tables[1]]
        members = list({d["path"]: d for d in self.snapshot_members}.values())
        scope = self.part(
            "archive",
            dict(
                scope="snapshot-v1",
                root=self.roots["snapshot.json"],
                strings=strings,
                shapes=shapes,
                record_routes=records,
                members=members,
                legacy_snapshot=self.legacy_snapshot,
            ),
        )
        destination = self.destination / "snapshot-v2.json"
        total = 0
        with destination.open("wb") as stream:

            def write(raw):
                nonlocal total
                if total + len(raw) > EXPANDED:
                    raise ValueError("v2 expanded archive exceeds 128 MB")
                stream.write(raw)
                total += len(raw)

            header = dict(schema_version=2, representation="snapshot-archive", **self.identity)
            write(encode(header).rstrip()[:-1] + b',"assets":[')
            for i, desc in enumerate([scope, *members]):
                if i:
                    write(b",")
                write(encode(desc).rstrip()[:-1] + b',"data":')
                write((self.destination / desc["path"]).read_bytes().rstrip())
                write(b"}")
            write(b"]}\n")
        gzip_path = self.destination / "snapshot-v2.json.gz"
        with gzip_path.open("wb") as output, destination.open("rb") as source:
            with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
                while chunk := source.read(1_048_576):
                    compressed.write(chunk)
                    if output.tell() > COMPRESSED:
                        raise ValueError("v2 gzip exceeds 8 MB")

        def descriptor(path, maximum):
            size = path.stat().st_size
            if size > maximum:
                raise ValueError("archive byte budget")
            with path.open("rb") as stream:
                measured = codec.digest(iter(lambda: stream.read(1_048_576), b""))
            return dict(path=path.name, **measured)

        return dict(
            scope="snapshot-v1",
            manifest=scope,
            expanded=descriptor(destination, EXPANDED),
            gzip=descriptor(gzip_path, COMPRESSED),
        )


def logical_views(data):
    """Same mandatory semantic views as the v1 writer, without legacy sidecars."""
    from .switching_comparison import summary

    compact = {k: v for k, v in data.items() if k != "switching_evidence"}
    compact["switching_comparison"] = summary(data["switching_comparison"])
    yield "snapshot.json", compact
    yield "switching-evidence.json", data["switching_evidence"]
    yield "switching-comparison.json", data["switching_comparison"]
    yield "current-evidence.json", data["current_evidence"]
    yield "release-assets.json", data["research"].get("release_assets", [])
    yield "catalogue.json", data.get("catalogue", {})
    for name in (
        "scorecards",
        "timeline",
        "source_audit",
        "vendor_gaps",
        "casefiles",
        "comparison_eligibility",
        "product_groups",
        "extraction_validation",
        "review_packet",
        "publisher_history",
        "family_completeness",
        "comparison_readiness",
        "fix_leads",
        "component_studies",
        "product_cohorts",
        "disclosure_review",
        "research_dossiers",
        "kev",
    ):
        yield (
            name.replace("_", "-") + ".json",
            {
                **data.get(name, {}),
                "publication": data["publication"],
                "generated_at": data["generated_at"],
            },
        )
    yield "benchmark.json", data.get("benchmark", {})
    for record in data["records"] + [w["record"] for w in data["retained_advisories"]]:
        yield (
            "evidence/" + str(record["evidence_id"]) + ".json",
            {
                k: record.get(k)
                for k in (
                    "evidence_id",
                    "source_url",
                    "sha256",
                    "source_observed_at",
                    "observed_at",
                    "source_format",
                )
            },
        )
    for change in data["changes"]:
        yield "changes/" + str(change["id"]) + ".json", change


def write_bundle(destination, data):
    from ..exports import csv_export
    from .eligibility import monitor_summary
    from .publication import write_manifest, write_reader_assets
    from .static_delivery import write_static_delivery
    from .switching_comparison import summary

    destination = Path(destination)
    writer = Writer(
        destination, dict(publication=data["publication"], generated_at=data["generated_at"])
    )
    for name, value in logical_views(data):
        # Existing small report/download endpoints remain ordinary assets. The
        # three giant logical documents are served only from bounded v2 roots.
        if name not in ("snapshot.json", "switching-evidence.json", "switching-comparison.json"):
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w") as stream:
                json.dump(value, stream, allow_nan=False)
        writer.root(
            name,
            value,
            alias="switching-evidence.json" if name == "switching-comparison.json" else None,
        )
    overview = writer.overview(summary(data["switching_comparison"]))
    runtime = {
        k: v for k, v in data.items() if k not in ("switching_evidence", "switching_comparison")
    }
    runtime["switching_overview"] = overview
    writer.root("runtime-snapshot", runtime)
    routes = writer.routes()
    writer.tables()
    overview_part = writer.part("overview", overview)
    catalog = dict(
        schema_version=2,
        representation="publication-catalog",
        **writer.identity,
        codec="json-token-v1",
        strings=writer.string_parts,
        shapes=writer.shape_parts,
        roots=writer.roots,
        routes=routes,
        switching=dict(
            overview=overview_part,
            definition_sha256=overview["selection"]["definition_sha256"],
            kev=writer.root_ranges["switching-comparison.json"][("inputs", "kev")],
            diagnostics=writer.root_ranges["switching-evidence.json"][("score_availability",)],
            detail_indexes=writer.detail_indexes(),
        ),
        archive=writer.archive(routes["records"]),
    )
    validate(catalog, "publication-v2.json")
    raw = encode(catalog)
    if len(raw) > INDEX:
        raise ValueError("v2 catalog exceeds 2 MB")
    (destination / "publication-v2.json").write_bytes(raw)
    descriptor = dict(path="publication-v2.json", bytes=len(raw), sha256=sha256(raw).hexdigest())
    (destination / "impact.csv").write_text(csv_export(data))
    summary_eligibility = monitor_summary(
        json.dumps({**data["comparison_eligibility"], **writer.identity}).encode(),
        publication=data["publication"],
        generated_at=data["generated_at"],
        vendors=data["vendors"],
    )
    (destination / "comparison-eligibility-summary.json").write_bytes(encode(summary_eligibility))
    write_reader_assets(destination, data, publication_format="v2")
    write_static_delivery(destination, data, publication_v2=descriptor)
    write_manifest(destination, data)
    if sum(p.stat().st_size for p in destination.rglob("*") if p.is_file()) > SITE:
        raise ValueError("v2 site exceeds 1 GB")
    return catalog


@phase("publication.inspection")
def inspect_bundle(directory, facts):
    """Verify the complete physical inventory before independent native parity."""
    from .import_candidate import CapacityFailure, _measure
    from .publication_reader import PublicationReader

    directory = Path(directory)
    manifest = codec.strict_loads((directory / "manifest.json").read_bytes(), max_bytes=INDEX)
    if set(manifest) != {"generation", "sha256"} or any(
        p.is_symlink() for p in directory.rglob("*")
    ):
        raise ValueError("manifest layout")
    files = {str(p.relative_to(directory)): p for p in directory.rglob("*") if p.is_file()}
    if set(files) != set(manifest["sha256"]) | {"manifest.json"}:
        raise ValueError("manifest inventory")
    total = 0
    for name, path in files.items():
        maximum = COMPRESSED if name == "snapshot-v2.json.gz" else EXPANDED
        if name.startswith("data/"):
            maximum = INDEX if name == "data/index.json" else PART
        if name in ("publication-v2.json", "manifest.json"):
            maximum = INDEX
        size, digest = _measure(path, maximum)
        total += size
        if total > SITE:
            raise CapacityFailure("public site size")
        if name != "manifest.json" and digest != manifest["sha256"][name]:
            raise ValueError("manifest hash")
        if name.startswith("schemas/") and (
            not (PACKAGE / name).is_file() or digest != _measure(PACKAGE / name)[1]
        ):
            raise ValueError("installed schema mismatch")
    reader = PublicationReader(directory)
    if manifest["generation"] != reader.identity["publication"]["id"]:
        raise ValueError("manifest generation")
    # Every physically inventoried v2 envelope is strictly parsed and bound,
    # including assets not reached by the default route.
    for name, path in files.items():
        if name.startswith("data/v2/"):
            value = codec.strict_loads(path.read_bytes())
            if (
                set(value) != {"schema_version", "publication", "generated_at", "kind", "data"}
                or value["schema_version"] != 2
                or type(value["schema_version"]) is not int
                or any(value[k] != v for k, v in reader.identity.items())
            ):
                raise ValueError("v2 physical envelope identity")
    for name in reader.catalog["roots"]:
        reader.root(name)
    for key, name in [
        ("expanded_bytes", "snapshot-v2.json"),
        ("compressed_bytes", "snapshot-v2.json.gz"),
    ]:
        facts[key] = files[name].stat().st_size
    facts.update(
        generation=manifest["generation"],
        manifest_sha256=_measure(directory / "manifest.json", INDEX)[1],
        public_bytes=total,
    )
    return reader


@phase("publication.native_parity")
def native_parity(database, directory, home, reader):
    """Bind mandatory roots to independently queried sanitized native facts."""
    from contextlib import closing

    from ..collection.config import load_config
    from ..exports import csv_export, switching_csv
    from ..storage.repository import connect
    from .publication import public_projection
    from .query import state
    from .switching_comparison import _select_summaries

    with closing(connect(database, read_only=True)) as db:
        native = state(db)
    native["publication"] = reader.identity["publication"]
    native["current_evidence"]["publication"] = reader.identity["publication"]
    projected = public_projection(
        native,
        [d["url"] for d in load_config().get("release_documents", [])],
        publication_format="v2",
    )
    verify_projection(reader, projected)
    if (Path(directory) / "impact.csv").read_bytes() != csv_export(projected).encode():
        raise ValueError("native CSV mismatch")
    with phase("publication.native_queries"):
        scopes = ("os_family", "model_qualified")
        actuals = reader.switching_selections(
            [dict(scope_level=scope) for scope in scopes], evaluated_at=projected["generated_at"]
        )
        expected_summaries = _select_summaries(
            projected["switching_comparison"],
            [dict(scope_level=scope) for scope in scopes],
            evaluated_at=projected["generated_at"],
        )
        for expected, actual in zip(expected_summaries, actuals, strict=True):
            if codec.digest(
                c.encode()
                for c in json.JSONEncoder(
                    ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).iterencode(actual)
            ) != codec.digest(
                c.encode()
                for c in json.JSONEncoder(
                    ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).iterencode(expected)
            ) or switching_csv(actual) != switching_csv(expected):
                raise ValueError("native switching query mismatch")


@phase("publication.native_roots")
def verify_projection(reader, projected):
    """Root membership comes from native views, never the untrusted catalog."""
    from .switching_comparison import summary

    views = dict(logical_views(projected))
    complete_summary = summary(projected["switching_comparison"])
    ranges = reader.ranges("snapshot.json")
    overview = {
        k: v
        for k, v in complete_summary.items()
        if k not in ("rows", "sources", "schema_version", "representation")
    }
    overview.update(
        schema_version=2,
        representation="switching-overview",
        rows=[],
        detail_ranges=dict(sources=ranges[("switching_comparison", "sources")]),
    )
    for i, row in enumerate(complete_summary["rows"]):
        overview["rows"].append(
            {
                **{k: v for k, v in row.items() if k not in DEFERRED},
                "detail_ranges": {
                    k: ranges[("switching_comparison", "rows", i, k)] for k in DEFERRED
                },
            }
        )
    if reader.switching_overview() != overview:
        raise ValueError("native overview mismatch")
    views["runtime-snapshot"] = {
        **{
            k: v
            for k, v in projected.items()
            if k not in ("switching_evidence", "switching_comparison")
        },
        "switching_overview": overview,
    }
    if set(views) != set(reader.catalog["roots"]):
        raise ValueError("missing or extra mandatory logical root")
    if "detail_indexes" in reader.catalog["switching"]:

        def token_count(value):
            if isinstance(value, dict):
                return 1 + sum(token_count(child) for child in value.values())
            if isinstance(value, (list, tuple)):
                return 1 + sum(token_count(child) for child in value)
            return 1

        # Membership and vendor identity come from fresh projected native facts.
        for kind, items in (
            ("sources", complete_summary["sources"]),
            ("diagnostics", projected["switching_evidence"].get("score_availability", [])),
        ):
            parent, _, chunks, total = reader._detail_chunks(kind)
            if total != len(items):
                raise ValueError("detail index native count mismatch")
            position, ordinal = parent["first_token"] + 1, 0
            for chunk in chunks:
                for entry in reader._detail_chunk(kind, chunk, parent, total):
                    item = items[ordinal]
                    raw = json.dumps(
                        item, ensure_ascii=False, allow_nan=False, separators=(",", ":")
                    ).encode()
                    end = position + token_count(item)
                    expected = dict(
                        root=parent["root"],
                        first_token=position,
                        end_token=end,
                        logical_bytes=len(raw),
                        logical_sha256=sha256(raw).hexdigest(),
                    )
                    if (
                        entry["range"] != expected
                        or entry["ordinal"] != ordinal
                        or (kind == "diagnostics" and entry.get("vendor") != item["vendor"])
                    ):
                        raise ValueError("detail index native membership mismatch")
                    position, ordinal = end, ordinal + 1
            if ordinal != len(items) or position != parent["end_token"]:
                raise ValueError("detail index native boundary mismatch")
    record_routes = reader.record_routes()
    expected_records = [
        dict(
            record_index=i,
            first_token=ranges[("records", i)]["first_token"],
            end_token=ranges[("records", i)]["end_token"],
            logical_bytes=ranges[("records", i)]["logical_bytes"],
        )
        for i in range(len(projected["records"]))
    ]
    if record_routes != expected_records:
        raise ValueError("record route membership mismatch")
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    for name, value in views.items():
        expected = codec.digest(chunk.encode() for chunk in encoder.iterencode(value))
        if reader.root(name)["logical"] != expected:
            raise ValueError("native logical root mismatch: " + name)
        # The authenticated descriptor now binds this root to native facts.
        # Exhaustion still verifies every byte, declared range and EOF via
        # Reader._stream; avoid hashing the same decoded chunks a second time.
        deque(reader.stream_root(name), maxlen=0)
