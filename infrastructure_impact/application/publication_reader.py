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
    working=512_000_000,
    cache=16_000_000,
    stream=1_000_000_000,
    default=32_000_000,
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
        codec.validate_table_transports(self.catalog)

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
                from .publication_v2 import validate_envelope

                if kind not in ("tokens", "strings", "shapes"):
                    validate_envelope(result, kind)
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
            accumulator = codec.Budget(self.limits["selected"])
            accumulator.charge(2, 2)
            for key in fields:
                if key in result:
                    continue
                accumulator.charge(
                    codec.string_cost(key) + 1 + bool(result),
                    codec.string_cost(key, True) + 1 + bool(result),
                )
                result[key] = self.materialize_range(
                    ranges[(key,)],
                    budget=accumulator,
                    max_bytes=accumulator.max_bytes - accumulator.used,
                    serialization="ascii",
                )
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

    def _current_record_keys(self, routes):
        """Hash/validate the full current array, retaining only scalar identities.

        Metadata has its existing index allowance, independent of the requested
        retained page. The codec still walks every other field under one stream
        ceiling/deadline; no current record JSON string or object is assembled.
        """
        from .evidence_identity import record_key

        bound = self.ranges("snapshot.json")[("records",)]
        strings, shapes = self._tables()
        stream_budget = codec.Budget(self.limits["stream"])
        metadata_budget = codec.Budget(self.limits["index"], deadline=stream_budget.deadline)
        fields = {"vendor", "advisory_id", "revision_id", "source_url", "sha256"}
        location, identity, ready = (), None, None
        digest, size, count = sha256(), 0, 0

        def nodes(event, path, position):
            nonlocal location, identity, ready, count
            if event == "start":
                location = path
            if len(path) != 2:
                return
            index = path[1]
            if index >= len(routes):
                raise ValueError("current identity route count")
            expected = routes[index]["first_token" if event == "start" else "end_token"]
            if position + bound["first_token"] != expected:
                raise ValueError("current identity route interval")
            if event == "start":
                metadata_budget.charge(2, 2)
                identity = {}
            else:
                if set(identity) != fields:
                    raise ValueError("current record identity fields")
                key = record_key(identity)
                codec.charge_value(key, metadata_budget)
                ready = key
                identity = None
                count += 1

        def tokens():
            source = self.iter_tokens(bound["root"], bound["first_token"], bound["end_token"])
            try:
                for token in source:
                    if location == ("records",) and token != [-1, len(routes)]:
                        raise ValueError("current identity array count")
                    if len(location) == 2 and not (isinstance(token, list) and len(token) == 1):
                        raise ValueError("current record identity object")
                    if len(location) == 3 and location[2] in fields:
                        key = location[2]
                        if type(token) is int:
                            index = codec.safe_int(-token - 2)
                            if index >= len(strings):
                                raise ValueError("identity string reference")
                            value = strings[index]
                        elif (
                            isinstance(token, list)
                            and len(token) == 3
                            and type(token[0]) is int
                            and token[0] == -2
                            and isinstance(token[2], str)
                        ):
                            # Reserve numeric conversion before allocating its int.
                            metadata_budget.charge(len(token[2]), len(token[2]))
                            value = codec.LogicalNumber(token[1], token[2]).value()
                        else:
                            raise ValueError("current record identity scalar")
                        metadata_budget.charge(
                            codec.string_cost(key) + 1 + bool(identity),
                            codec.string_cost(key, True) + 1 + bool(identity),
                        )
                        codec.charge_value(value, metadata_budget)
                        identity[key] = value
                    yield token
            finally:
                source.close()

        def observe(raw):
            nonlocal size
            size += len(raw)
            if size > bound["logical_bytes"]:
                raise ValueError("current record range digest/length")
            digest.update(raw)

        for _ in codec.stream_tokens(
            tokens(),
            strings,
            shapes,
            root=bound["root"],
            path=("records",),
            budget=stream_budget,
            validate=False,
            observer=observe,
            node_observer=nodes,
        ):
            if ready is not None:
                yield ready
                ready = None
        if (
            count != len(routes)
            or size != bound["logical_bytes"]
            or digest.hexdigest() != bound["logical_sha256"]
        ):
            raise ValueError("current record range digest/length/count")

    def retained_selection(
        self, bootstrap, *, cves=None, vendor=None, offset=0, limit=100, export=False
    ):
        """Validate index authority, scan only routed parts, and retain one page.

        Untouched parts are represented by the complete ordered descriptor and
        bootstrap memberships. Every touched part is checked in full, including
        wrappers outside the requested page. No persistent validation cache.
        """
        from ..exports import RETAINED_FIELDS
        from .current_evidence import validate_report
        from .evidence_identity import record_key

        current = self.index["current_evidence"]
        report = self.fetch(current["report"], ordinary=True)
        validate_report(report, **self.identity)
        decisions = {d["decision_id"]: d for d in report["decisions"]}
        index = bootstrap["retained_index"]
        indexed = {r["decision_id"]: r for r in index}
        order = [r["decision_id"] for r in index]
        declared = [identity for part in current["retained"] for identity in part["decision_ids"]]
        if len(indexed) != len(index) or declared != order or set(indexed) != set(decisions):
            raise ValueError("retained partition membership/order")
        for part in current["retained"]:
            expected = sorted(
                {c for identity in part["decision_ids"] for c in indexed[identity]["cves"]}
            )
            if part["cve_ids"] != expected:
                raise ValueError("retained descriptor CVE membership")
        for entry in index:
            if entry["vendor"] != decisions[entry["decision_id"]]["vendor"]:
                raise ValueError("retained index vendor")
        if report["availability"] == "available":
            routes = self.record_routes()
            if report["counts"] != dict(
                current=len(routes), excluded=len(index), retained_total=len(routes) + len(index)
            ):
                raise ValueError("retained partition counts")
            # Verify the complete current identities without hydrating unrelated
            # payloads or allowing overlap with excluded targets.
            keys = {d["target_key"] for d in decisions.values()}
            for key in self._current_record_keys(routes):
                if key in keys:
                    raise ValueError("Duplicate retained/current identity")
                keys.add(key)

        cohort = set(cves) if cves is not None else None

        def matches(entry):
            return (cohort is None or cohort.intersection(entry["cves"])) and (
                vendor is None or entry["vendor"] == vendor
            )

        total = sum(bool(matches(entry)) for entry in index)
        result = dict(
            schema_version=1,
            **self.identity,
            record_scope="retained_latest_excluded",
            current_evidence=report,
        )
        if export:
            result["records"] = []
            items = result["records"]
        else:
            result.update(total=total, offset=offset, limit=limit, items=[])
            items = result["items"]
        budget = codec.Budget(self.limits["selected"])
        codec.charge_value(result, budget, spaced=True)
        position = 0
        for part in current["retained"]:
            if cohort is not None and not cohort.intersection(part["cve_ids"]):
                continue
            if vendor is not None and not any(
                indexed[i]["vendor"] == vendor for i in part["decision_ids"]
            ):
                continue
            wrappers = self.fetch(part["part"], ordinary=True)
            if [w["decision_id"] for w in wrappers] != part["decision_ids"]:
                raise ValueError("retained part membership/order")
            for wrapper in wrappers:
                decision = decisions[wrapper["decision_id"]]
                record = wrapper["record"]
                entry = indexed[wrapper["decision_id"]]
                key = record_key(record)
                if (
                    wrapper.get("record_scope") != "retained_latest_excluded"
                    or wrapper.get("target_key") != key
                    or decision["target_key"] != key
                    or decision["vendor"] != record["vendor"]
                    or entry["cves"] != record["cves"]
                ):
                    raise ValueError("Invalid retained decision reference")
                if not matches(entry):
                    continue
                take = export or offset <= position < offset + limit
                position += 1
                if not take:
                    continue
                budget.charge(bool(items), 2 * bool(items))
                if not export:
                    codec.charge_value(wrapper, budget, spaced=True)
                    items.append(wrapper)
                else:
                    metadata = {k: decision[k] for k in RETAINED_FIELDS if k != "record_scope"}
                    metadata["record_scope"] = wrapper["record_scope"]
                    # Preflight expanded assessments before allocating copies.
                    fields = {**record, **metadata, "assessments": []}
                    codec.charge_value(fields, budget, spaced=True)
                    assessments = []
                    for assessment in record["assessments"]:
                        if cohort is not None and assessment["cve_id"] not in cohort:
                            continue
                        budget.charge(bool(assessments), 2 * bool(assessments))
                        # Fixed metadata key set, values remain references until
                        # the entire new assessment's requested cost is accepted.
                        pairs = {**assessment, **metadata}
                        codec.charge_value(pairs, budget, spaced=True)
                        assessments.append(pairs)
                    fields["assessments"] = assessments
                    items.append(fields)
        if position != total:
            raise ValueError("retained filtered count")
        return result

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

    def iter_claims(self, *, max_bytes=None):
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
        links, fixed, held = [], [], 0
        stream_budget = codec.Budget(self.limits["stream"])
        for i, route in enumerate(self._claim_routes()):
            from collections import deque

            kinds = deque()
            raw = bytearray()
            maximum = min(
                self.limits["selected"],
                max_bytes(route[0])
                if callable(max_bytes)
                else max_bytes
                if max_bytes is not None
                else self.limits["selected"],
            )
            if route[3] > maximum:
                raise ValueError("claim byte budget")
            for chunk in self._stream(
                "switching-evidence.json",
                route[1],
                route[2],
                dict(bytes=route[3], sha256=None),
                serialization="ascii",
                maximum=maximum,
                path=("claims", i),
                budget=stream_budget,
                number_observer=lambda number: kinds.append(number.kind),
            ):
                raw.extend(chunk)

            def number(lexeme):
                return int(lexeme) if kinds.popleft() == "i" else float(lexeme)

            claim = codec.strict_loads(raw, max_bytes=maximum, parse_int=number, parse_float=number)
            if claim["claim_id"] != route[0]:
                raise ValueError("claim identity mismatch")
            contracts._validate_claim(claim)
            contracts._validate_evidence_semantics(
                {**metadata, "claims": [claim]}, **self.identity, _study=study, _linkage=links
            )
            if (
                claim["vendor"] == "arista"
                and claim["advisory_id"]
                in {
                    "19904-security-advisory-0100",
                    "23115-security-advisory-0128",
                    "24847-security-advisory-0201",
                    "15438-security-advisory-0075",
                }
            ) or (claim["vendor"] == "aruba" and claim["advisory_id"] == "HPESBNW04669"):
                held += route[3]
                if held > self.limits["selected"]:
                    raise ValueError("cross-claim linkage byte budget")
                fixed.append(claim)
            yield claim
        for claim, remediation, binding in links:
            contracts._validate_reviewed_link(claim, remediation, binding, fixed)

    def switching_release_history(self, study_selection):
        """Optional lazy root; authenticate generation before reading release arrays."""
        from .switching_releases import select_report

        self._identity(study_selection)
        name = "switching-release-history.json"
        if name not in self.catalog["roots"]:
            return select_report(None, study_selection)
        self._identity({k: self.field(name, k) for k in self.identity})
        value = self.materialize_range(self.ranges(name)[()])
        result = select_report(value, study_selection)
        codec.charge_value(result, codec.Budget(self.limits["selected"]))
        return result

    def switching_selection(self, options, *, evaluated_at):
        return next(self.switching_selections([options], evaluated_at=evaluated_at))

    def switching_selections(self, selections, *, evaluated_at):
        from .switching_comparison import ReducerClaim, select_reducer_claims

        claims = []
        # Aggregate reducer state is larger than the selected response it produces.
        accumulator = codec.Budget(self.limits["working"])
        accumulator.charge(2, 2)
        for claim in self.iter_claims():
            accumulator.charge(bool(claims), bool(claims))
            projection = ReducerClaim.from_validated(claim, budget=accumulator)
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

    def _detail_chunks(self, kind):
        """Check optional chunk counts against the authenticated parent array header."""
        chunks = self.catalog["switching"]["detail_indexes"][kind]
        if kind == "diagnostics":
            bound = self.catalog["switching"]["diagnostics"]
            path = ("score_availability",)
        else:
            bound = self.switching_overview()["detail_ranges"]["sources"]
            path = ("switching_comparison", "sources")
        codec.validate_range(bound)
        total = 0
        for chunk in chunks:
            if chunk["first"] != total:
                raise ValueError("detail chunk order/count")
            total += codec.safe_int(chunk["count"], minimum=1)
            if (kind == "diagnostics" and sum(chunk["vendors"].values()) != chunk["count"]) or (
                kind == "sources" and chunk["vendors"]
            ):
                raise ValueError("detail chunk vendor counts")
        tokens = self.iter_tokens(bound["root"], bound["first_token"], bound["first_token"] + 1)
        try:
            if next(tokens, None) != [-1, total]:
                raise ValueError("detail index parent count")
        finally:
            tokens.close()
        return bound, path, chunks, total

    def _detail_chunk(self, kind, chunk, bound, total):
        entries = self.fetch(chunk["part"], kind="detail_index")
        if len(entries) != chunk["count"]:
            raise ValueError("detail chunk count")
        vendors, previous = {}, None
        for index, entry in enumerate(entries, chunk["first"]):
            r = codec.validate_range(entry["range"])
            if (
                entry["ordinal"] != index
                or r["root"] != bound["root"]
                or r["first_token"] <= bound["first_token"]
                or r["end_token"] > bound["end_token"]
                or (previous is not None and previous != r["first_token"])
                or (index == 0 and r["first_token"] != bound["first_token"] + 1)
                or (index == total - 1 and r["end_token"] != bound["end_token"])
            ):
                raise ValueError("detail item routing")
            previous = r["end_token"]
            if kind == "diagnostics":
                vendor = entry.get("vendor")
                if not isinstance(vendor, str):
                    raise ValueError("detail vendor")
                vendors[vendor] = vendors.get(vendor, 0) + 1
            elif "vendor" in entry:
                raise ValueError("source detail vendor")
        if vendors != chunk["vendors"]:
            raise ValueError("detail chunk vendor counts")
        return entries

    def _detail_item(self, entry, path, maximum):
        from collections import deque

        bound = entry["range"]
        kinds, raw = deque(), bytearray()
        for chunk in self._stream(
            bound["root"],
            bound["first_token"],
            bound["end_token"],
            dict(bytes=bound["logical_bytes"], sha256=bound["logical_sha256"]),
            serialization="ascii",
            maximum=maximum,
            path=(*path, entry["ordinal"]),
            number_observer=lambda number: kinds.append(number.kind),
        ):
            raw.extend(chunk)

        def number(lexeme):
            return int(lexeme) if kinds.popleft() == "i" else float(lexeme)

        value = codec.strict_loads(raw, max_bytes=maximum, parse_int=number, parse_float=number)
        if "vendor" in entry and value.get("vendor") != entry["vendor"]:
            raise ValueError("detail vendor identity")
        return value

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
        if kind == "sources" or (
            kind == "diagnostics" and "detail_indexes" in self.catalog["switching"]
        ):
            if kind == "sources":
                total = len(selection["sources"])
                entries = selection["sources"][offset : offset + limit]
            else:
                bound, path, chunks, total = self._detail_chunks(kind)
                entries = []
                for chunk in chunks:
                    if (
                        chunk["first"] >= offset + limit
                        or chunk["first"] + chunk["count"] <= offset
                    ):
                        continue
                    entries.extend(
                        entry
                        for entry in self._detail_chunk(kind, chunk, bound, total)
                        if offset <= entry["ordinal"] < offset + limit
                    )
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
            envelope = dict(items=[], next_cursor=next_cursor, total=total)
            quota = codec.Budget(self.limits["selected"])
            codec.charge_value(envelope, quota)
            for entry in entries:
                comma = bool(envelope["items"])
                value = (
                    entry
                    if kind == "sources"
                    else self._detail_item(
                        entry, path, self.limits["selected"] - quota.used - comma
                    )
                )
                quota.charge(comma, comma)
                codec.charge_value(value, quota)
                envelope["items"].append(value)
            return envelope
        if kind == "claims":
            used = {c for r in rows for c in r["claim_ids"]} | {
                c for r in rows for e in r["events"] for c in e["claim_ids"]
            }

            def values():
                return (
                    c for c in self.iter_claims(max_bytes=claim_allowance) if c["claim_id"] in used
                )
        elif kind == "sources":

            def values():
                return iter(selection["sources"])
        elif kind in ("events", "status_buckets"):

            def values():
                return (item for row in rows for item in row[kind])
        elif kind == "diagnostics":

            def values():
                return self.iter_array(
                    self.catalog["switching"]["diagnostics"], max_bytes=item_allowance
                )
        else:
            raise ValueError("unknown detail kind")
        # Count/validate first without retaining the collection. The complete
        # envelope (including a non-null cursor) is known before page assembly.
        total = 0
        item_cost = codec.Budget(self.limits["selected"])
        chosen_claims = set()
        remaining = self.limits["selected"]

        def claim_allowance(identity):
            return remaining if identity in chosen_claims else self.limits["selected"]

        def item_allowance(index):
            return remaining if offset <= index < offset + limit else self.limits["selected"]

        for i, item in enumerate(values()):
            total += 1
            if offset <= i < offset + limit:
                codec.charge_value(item, item_cost)
                if kind == "claims":
                    chosen_claims.add(item["claim_id"])
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
        envelope = dict(items=[], next_cursor=next_cursor, total=total)
        accumulator = codec.Budget(self.limits["selected"])
        codec.charge_value(envelope, accumulator)
        count = min(limit, max(0, total - offset))
        accumulator.charge(item_cost.used + max(0, count - 1), item_cost.used + max(0, count - 1))
        remaining = self.limits["selected"] - (accumulator.used - item_cost.used)
        for i, item in enumerate(values()):
            if offset <= i < offset + limit:
                cost = codec.Budget(remaining)
                codec.charge_value(item, cost)
                remaining -= cost.used
                envelope["items"].append(item)
        return envelope

    def iter_array(self, bound, *, max_bytes=None):
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
            maximum = min(
                self.limits["selected"], max_bytes(i) if max_bytes else self.limits["selected"]
            )
            if i:
                observe(b",")
                budget.charge(1, 1)
            raw = bytearray()
            for chunk in codec.stream_tokens(
                take(),
                strings,
                shapes,
                budget=codec.Budget(maximum, parent=budget),
                serialization="ascii",
                root=bound["root"],
                validate=False,
                observer=observe,
            ):
                if len(raw) + len(chunk) > maximum:
                    raise ValueError("array child byte budget")
                raw.extend(chunk)
            yield codec.strict_loads(raw, max_bytes=maximum)
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
