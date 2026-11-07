"""Metadata-first verified v2 store with bounded page and selected-node reads."""

import json
from collections import OrderedDict
from hashlib import sha256
from pathlib import Path

from .. import publication_codec as codec
from .publication_v2 import validate

DEFAULT_LIMITS = dict(
    part=8_000_000,
    index=2_000_000,
    selected=128_000_000,
    cache=16_000_000,
    stream=1_000_000_000,
    default=20_000_000,
)


class PublicationReader(codec.CatalogReader):
    def __init__(self, directory, *, limits=None):
        self.directory = Path(directory).resolve()
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}
        if any(codec.safe_int(v, minimum=1) > DEFAULT_LIMITS[k] for k, v in self.limits.items()):
            raise ValueError("cannot increase reader limits")
        self.cache = OrderedDict()
        self.cache_bytes = 0
        self.read_bytes = 0
        self._strings = self._shapes = None
        self._roots = {}
        self._ranges = {}
        self.index = self._read_fixed("data/index.json", self.limits["index"])
        validate(self.index, "static-index-v2.json")
        if type(self.index["schema_version"]) is not int:
            raise ValueError("index version type")
        self.identity = {k: self.index[k] for k in ("publication", "generated_at")}
        self.catalog = self.fetch(
            self.index["publication_v2"],
            fixed={"publication-v2.json"},
            maximum=self.limits["index"],
        )
        validate(self.catalog, "publication-v2.json")
        if type(self.catalog["schema_version"]) is not int:
            raise ValueError("catalog version type")
        self._identity(self.catalog)
        self._validate_table_descriptors(self.catalog["strings"])
        self._validate_table_descriptors(self.catalog["shapes"])

    def _path(self, path):
        target = self.directory / path
        if target.is_symlink() or not target.resolve().is_relative_to(self.directory):
            raise ValueError("publication path escape")
        return target

    def _read_fixed(self, path, maximum):
        with self._path(path).open("rb") as stream:
            raw = stream.read(maximum + 1)
        self.read_bytes += len(raw)
        return codec.strict_loads(raw, max_bytes=maximum, transport=True)

    def _identity(self, value):
        if any(value.get(k) != v for k, v in self.identity.items()):
            raise ValueError("mixed publication generation")

    def fetch(self, descriptor, *, fixed=None, maximum=None, kind=None, ordinary=False):
        maximum = maximum or self.limits["part"]
        if ordinary:
            import re

            path = descriptor.get("path", "")
            if not re.fullmatch(r"data/[a-f0-9]{64}\.json", path) or path[5:-5] != descriptor.get(
                "sha256"
            ):
                raise ValueError("ordinary part path")
            fixed = {path}
        codec.validate_descriptor(descriptor, paths=fixed, max_bytes=maximum)
        path = descriptor["path"]
        raw = self.cache.pop(path, None)
        if raw is None:
            with self._path(path).open("rb") as stream:
                raw = stream.read(min(maximum, descriptor["bytes"]) + 1)
            self.read_bytes += len(raw)
            if len(raw) != descriptor["bytes"] or sha256(raw).hexdigest() != descriptor["sha256"]:
                raise ValueError("part bytes/hash mismatch")
            while self.cache and self.cache_bytes + len(raw) > self.limits["cache"]:
                _, evicted = self.cache.popitem(last=False)
                self.cache_bytes -= len(evicted)
            if len(raw) <= self.limits["cache"]:
                self.cache_bytes += len(raw)
        else:
            self.cache_bytes -= len(raw)
            self.cache_bytes += len(raw)
        if len(raw) <= self.limits["cache"]:
            self.cache[path] = raw
        result = codec.strict_loads(
            raw, max_bytes=maximum, transport=not ordinary and kind != "overview"
        )
        if kind is not None or ordinary:
            self._identity(result)
            if ordinary:
                if (
                    set(result) != {"schema_version", "publication", "generated_at", "data"}
                    or type(result["schema_version"]) is not int
                    or result["schema_version"] != 1
                ):
                    raise ValueError("ordinary part envelope")
            else:
                if (
                    set(result) != {"schema_version", "publication", "generated_at", "kind", "data"}
                    or type(result["schema_version"]) is not int
                    or result["schema_version"] != 2
                    or result["kind"] != kind
                ):
                    raise ValueError("v2 part envelope")
                if kind == "record_routes":
                    codec.validate_record_routes(result["data"])
                # Closed kind-specific schemas, including tokens and array counts.
                from .publication_v2 import validators

                if kind not in ("tokens", "strings", "shapes"):
                    validators()["publication-v2.json"].evolve(
                        schema={"$ref": "urn:infrastructure-impact:publication:2#/$defs/envelope"}
                    ).validate(result)
            return result["data"]
        return result

    def switching_overview(self, evaluated_at=None):
        from . import kev

        result = self.fetch(self.catalog["switching"]["overview"], kind="overview")
        validate(result, "switching-overview-v2.json")
        if evaluated_at is not None:
            report = self.materialize_range(self.catalog["switching"]["kev"])
            for row in result["rows"]:
                selected = kev.select_report(
                    report, row["affected_cve_ids"], evaluated_at=evaluated_at
                )
                membership = selected["selection"]["membership"]
                listed = sorted(c for c in row["affected_cve_ids"] if membership[c] == "listed")
                unknown = sorted(c for c in row["affected_cve_ids"] if membership[c] == "unknown")
                row["kev"] = dict(
                    availability=selected["source"]["availability"],
                    listed_cve_ids=listed,
                    unknown_cve_ids=unknown,
                    listed_count=len(listed),
                    unknown_count=len(unknown),
                    denominator=len(row["affected_cve_ids"]),
                )
            result["evaluated_at"] = evaluated_at
        return result

    def runtime_snapshot(self, *, cohort=None, fields=None):
        if cohort is None:
            ranges = self.ranges("runtime-snapshot")
            if fields is None:
                return self.materialize_range(ranges[()])
            result = {}
            used = 2
            for key in fields:
                bound = ranges[(key,)]
                used += bound["logical_bytes"] + codec.string_cost(key) + 2
                if used > self.limits["selected"]:
                    raise ValueError("selected byte budget")
                result[key] = self.materialize_range(bound)
            return result
        # Ordinary cohort parts carry complete global catalogs/denominators in
        # bootstrap; selecting a cohort never triggers the giant runtime root.
        result = self.fetch(self.index["bootstrap"], ordinary=True)
        result["coverage"] = []
        result["retained_advisories"] = []
        accumulator = codec.Budget(self.limits["selected"])
        codec.charge_value(result, accumulator)

        def entry(value, count):
            # The empty container was charged with bootstrap. Charge its comma
            # and the entire new value before retaining the next element.
            accumulator.charge(bool(count), bool(count))
            codec.charge_value(value, accumulator)

        def field(key, value):
            # These fields are absent from the ordinary bootstrap contract.
            if key in result:
                raise ValueError("duplicate assembled field")
            accumulator.charge(
                codec.string_cost(key) + 1 + bool(result),
                codec.string_cost(key, True) + 1 + bool(result),
            )
            codec.charge_value(value, accumulator)
            result[key] = value

        records, assessments, seen, timeline = {}, {}, set(), {}
        for cid in sorted(set(cohort)):
            for desc in self.index["cohorts"].get(cid, []):
                if desc["path"] in seen:
                    continue
                seen.add(desc["path"])
                for row in self.fetch(desc, ordinary=True):
                    if row["kind"] == "record":
                        index = row["index"]
                        if index not in records:
                            entry(row["record"], len(records))
                            # Add the assessments key and empty list before
                            # constructing the record that will retain them.
                            extra = codec.string_cost("assessments") + 3 + bool(row["record"])
                            accumulator.charge(extra, extra)
                            records[index] = {**row["record"], "assessments": []}
                            assessments[index] = {}
                        for item_index, assessment in row["assessments"]:
                            if item_index not in assessments[index]:
                                entry(assessment, len(assessments[index]))
                                assessments[index][item_index] = assessment
                    elif row["kind"] == "coverage":
                        entry(row["value"], len(result["coverage"]))
                        result["coverage"].append(row["value"])
                    elif row["kind"] == "timeline":
                        if row["index"] not in timeline:
                            entry(row["value"], len(timeline))
                            timeline[row["index"]] = row["value"]
                    elif row["kind"] == "scorecard":
                        cases = next(
                            v
                            for v in result["scorecards"]["vendors"]
                            if v["vendor"] == row["vendor"]
                        )["cases"]
                        entry(row["value"], len(cases))
                        cases.append(row["value"])
        for index, record in sorted(records.items()):
            record["assessments"] = [a for _, a in sorted(assessments[index].items())]
            result["records"].append(record)
        result["timeline"]["events"] = [e for _, e in sorted(timeline.items())]
        current = self.index.get("current_evidence")
        if current:
            field("current_evidence", self.fetch(current["report"], ordinary=True))
            for part in current["retained"]:
                if set(part["cve_ids"]).intersection(cohort):
                    for wrapper in self.fetch(part["part"], ordinary=True):
                        entry(wrapper, len(result["retained_advisories"]))
                        result["retained_advisories"].append(wrapper)
        field("switching_overview", self.switching_overview())
        return {k: v for k, v in result.items() if fields is None or k in fields}

    def _claim_routes(self):
        strings, _ = self._tables()
        result = codec.claim_routes(
            [self.fetch(p, kind="claim_routes") for p in self.catalog["routes"]["claims"]], strings
        )
        ranges = self.ranges("switching-evidence.json")
        parent = ranges[("claims",)]
        first = next(
            self.iter_tokens("switching-evidence.json", parent["first_token"], parent["end_token"])
        )
        if first != [-1, len(result)] or (
            result
            and (result[0][1] != parent["first_token"] + 1 or result[-1][2] != parent["end_token"])
        ):
            raise ValueError("missing claim routes")
        return result

    def iter_claims(self):
        from . import switching_evidence as contracts

        metadata = {
            key: self.field("switching-evidence.json", key)
            for key in (
                "schema_version",
                "publication",
                "generated_at",
                "definition_sha256",
                "issues",
            )
        }
        metadata["coverage"] = []
        study = contracts.definition()
        validator = contracts._validators()["switching-evidence-v1.json"]
        claim_validator = validator.evolve(schema=validator.schema["properties"]["claims"]["items"])
        links, fixed, held = [], [], 0
        stream_budget = codec.Budget(self.limits["stream"])
        for i, route in enumerate(self._claim_routes()):
            from collections import deque

            kinds = deque()
            raw = bytearray()
            if route[3] > self.limits["selected"]:
                raise ValueError("claim byte budget")
            for chunk in self._stream(
                "switching-evidence.json",
                route[1],
                route[2],
                dict(bytes=route[3], sha256=None),
                serialization="logical",
                maximum=self.limits["selected"],
                path=("claims", i),
                budget=stream_budget,
                number_observer=lambda number: kinds.append(number.kind),
            ):
                raw.extend(chunk)

            def number(lexeme):
                return int(lexeme) if kinds.popleft() == "i" else float(lexeme)

            claim = codec.strict_loads(
                raw, max_bytes=self.limits["selected"], parse_int=number, parse_float=number
            )
            if claim["claim_id"] != route[0]:
                raise ValueError("claim identity mismatch")
            claim_validator.validate(claim)
            contracts._validate_evidence_semantics(
                {**metadata, "claims": [claim]}, **self.identity, _study=study, _linkage=links
            )
            if (
                claim["vendor"] == "arista"
                and claim["advisory_id"] == "19904-security-advisory-0100"
            ):
                held += route[3]
                if held > self.limits["selected"]:
                    raise ValueError("cross-claim linkage byte budget")
                fixed.append(claim)
            yield claim
        for claim, remediation, binding in links:
            contracts._validate_reviewed_link(claim, remediation, binding, fixed)

    def switching_selection(self, options, *, evaluated_at):
        return next(self.switching_selections([options], evaluated_at=evaluated_at))

    def switching_selections(self, selections, *, evaluated_at):
        from .switching_comparison import ReducerClaim, select_reducer_claims

        claims = []
        accumulator = codec.Budget(self.limits["selected"])
        for claim in self.iter_claims():
            projection = ReducerClaim.from_validated(claim)
            codec.charge_value([projection.fields, projection.sources], accumulator)
            claims.append(projection)
        overview = self.switching_overview()
        coverage = self.field("switching-evidence.json", "coverage")
        issues = self.field("switching-evidence.json", "issues")
        kev = self.materialize_range(self.catalog["switching"]["kev"])
        for options in selections:
            result = select_reducer_claims(
                overview,
                claims,
                coverage,
                issues,
                kev,
                options,
                evaluated_at=evaluated_at,
                max_bytes=self.limits["selected"],
            )
            codec.charge_value(result, codec.Budget(self.limits["selected"]))
            yield result

    def detail_page(self, selection, kind, *, row_id=None, cursor=None, limit=25):
        import base64

        if codec.safe_int(limit, minimum=1) > 25:
            raise ValueError("detail page limit")
        if (
            selection.get("publication") != self.identity["publication"]
            or selection.get("generated_at") != self.identity["generated_at"]
        ):
            raise ValueError("detail generation")
        binding = sha256(
            json.dumps(
                [
                    self.identity,
                    selection.get("selection"),
                    selection.get("evaluated_at"),
                    kind,
                    row_id,
                ],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        offset = 0
        if cursor is not None:
            try:
                decoded = codec.strict_loads(base64.urlsafe_b64decode(cursor), max_bytes=1024)
                if set(decoded) != {"binding", "offset"} or decoded["binding"] != binding:
                    raise ValueError("detail cursor binding")
                offset = codec.safe_int(decoded["offset"])
            except Exception as exc:
                raise ValueError("invalid detail cursor") from exc
        rows = (
            selection["rows"]
            if row_id is None
            else [r for r in selection["rows"] if r["row_id"] == row_id]
        )
        if row_id is not None and not rows:
            raise ValueError("unknown detail row")
        if kind == "claims":
            used = {c for r in rows for c in r["claim_ids"]} | {
                c for r in rows for e in r["events"] for c in e["claim_ids"]
            }
            iterable = (c for c in self.iter_claims() if c["claim_id"] in used)
        elif kind == "sources":
            iterable = selection["sources"]
        elif kind in ("events", "status_buckets"):
            iterable = (item for row in rows for item in row[kind])
        elif kind == "diagnostics":
            iterable = self.iter_array(self.catalog["switching"]["diagnostics"])
        else:
            raise ValueError("unknown detail kind")
        items, total = [], 0
        accumulator = codec.Budget(self.limits["selected"])
        for i, item in enumerate(iterable):
            total += 1
            if offset <= i < offset + limit:
                codec.charge_value(item, accumulator)
                items.append(item)
        if offset > total:
            raise ValueError("detail cursor offset")
        next_cursor = (
            base64.urlsafe_b64encode(
                json.dumps(
                    dict(binding=binding, offset=offset + limit), separators=(",", ":")
                ).encode()
            ).decode()
            if offset + limit < total
            else None
        )
        return dict(items=items, next_cursor=next_cursor, total=total)

    def iter_array(self, bound):
        """Scan a complete bound array, materializing only one child at a time."""
        codec.validate_range(bound)
        strings, shapes = self._tables()
        tokens = iter(self.iter_tokens(bound["root"], bound["first_token"], bound["end_token"]))
        first = next(tokens, None)
        if not isinstance(first, list) or len(first) != 2 or first[0] != -1:
            raise ValueError("expected array range")
        count = codec.safe_int(first[1])
        budget = codec.Budget(self.limits["stream"])
        digest, size = sha256(), 0

        def observe(raw):
            nonlocal size
            size += len(raw)
            if size > bound["logical_bytes"]:
                raise ValueError("array declared byte bound")
            digest.update(raw)

        def take(depth=0):
            if depth > codec.MAX_DEPTH:
                raise ValueError("array node depth")
            try:
                token = next(tokens)
            except StopIteration as exc:
                raise ValueError("truncated array child") from exc
            yield token
            children = 0
            if isinstance(token, list) and len(token) == 1:
                index = codec.safe_int(token[0])
                if index >= len(shapes):
                    raise ValueError("shape reference")
                children = len(shapes[index])
            elif isinstance(token, list) and len(token) == 2 and token[0] == -1:
                children = codec.safe_int(token[1])
            for _ in range(children):
                yield from take(depth + 1)

        observe(b"[")
        budget.charge(1, 1)
        for i in range(count):
            if i:
                observe(b",")
                budget.charge(1, 1)
            raw = bytearray()
            for chunk in codec.stream_tokens(
                take(),
                strings,
                shapes,
                budget=budget,
                root=bound["root"],
                validate=False,
                observer=observe,
            ):
                if len(raw) + len(chunk) > self.limits["selected"]:
                    raise ValueError("array child byte budget")
                raw.extend(chunk)
            yield codec.strict_loads(raw, max_bytes=self.limits["selected"])
        observe(b"]")
        budget.charge(1, 1)
        if (
            next(tokens, None) is not None
            or size != bound["logical_bytes"]
            or digest.hexdigest() != bound["logical_sha256"]
        ):
            raise ValueError("array range digest/boundary")

    def stream_document(self, overrides, *, exclude=()):
        """Complete legacy snapshot semantics with selected fields replaced.

        Deferred study fields remain complete root ranges, never an internal
        overview. One budget/deadline spans punctuation and every child range.
        """
        ranges = self.ranges("snapshot.json")
        budget = codec.Budget(self.limits["stream"])

        def emit(raw):
            budget.charge(len(raw), len(raw))
            return raw

        yield emit(b"{")
        first = True
        for path, bound in ranges.items():
            if len(path) != 1 or path[0] in exclude:
                continue
            key = path[0]
            if not first:
                yield emit(b",")
            first = False
            yield emit(json.dumps(key, ensure_ascii=True).encode() + b":")
            if key in overrides:
                logical = json.JSONEncoder(
                    ensure_ascii=False, allow_nan=False, separators=(",", ":")
                ).iterencode(overrides[key])
                ascii = json.JSONEncoder(
                    ensure_ascii=True, allow_nan=False, separators=(",", ":")
                ).iterencode(overrides[key])
                for a, b in zip(logical, ascii, strict=True):
                    budget.charge(len(a.encode()), len(b.encode()))
                    yield b.encode()
            else:
                yield from self._stream(
                    "snapshot.json",
                    bound["first_token"],
                    bound["end_token"],
                    dict(bytes=bound["logical_bytes"], sha256=bound["logical_sha256"]),
                    serialization="ascii",
                    maximum=self.limits["stream"],
                    path=path,
                    budget=budget,
                )
        yield emit(b"}\n")


def export_root(directory, root, output):
    """Exclusive local export; never overwrite or add files to a publication."""
    import os

    directory, output = Path(directory).resolve(), Path(output)
    if output.is_symlink() or output.resolve().is_relative_to(directory):
        raise ValueError("export output must be outside publication")
    reader = PublicationReader(directory)
    # Validate root before creating the destination. O_EXCL protects existing
    # sources/accepted outputs, including concurrent changes and symlinks.
    reader.root(root)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            for chunk in reader.stream_root(root):
                stream.write(chunk)
            stream.write(b"\n")
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return output
