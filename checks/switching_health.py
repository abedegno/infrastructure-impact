"""Standalone stdlib validation of compact switching publication summaries.

Schemas arrive through the monitor's fingerprinted, bounded asset reader. This
small closed-keyword validator never resolves remote references or loads history.
The publication writer remains the authority for claim-level derivations.
"""

import hashlib
import json
import re
from datetime import date, datetime
from urllib.parse import urlsplit

DEFINITION_SHA256 = "5224471b014fccc278f985d08328926bac29ebc6bfb96d25f98972f91be6fd33"
SCHEMAS = (
    "switching-study-v1.json",
    "switching-evidence-v1.json",
    "switching-comparison-v1.json",
    "switching-summary-v1.json",
    "kev-v1.json",
    "static-index-v1.json",
)
KEYWORDS = set(
    "$defs $id $ref $schema additionalProperties allOf anyOf const description else enum format if items prefixItems maxItems maxLength maxProperties maximum minItems minLength minimum not oneOf pattern properties propertyNames required then title type uniqueItems".split()
)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def timestamp(value):
    assert isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", value
    ), "Invalid switching timestamp"
    try:
        result = datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    except ValueError as error:
        raise AssertionError("Invalid switching timestamp") from error
    return result


def uri(value):
    assert isinstance(value, str), "Invalid switching URI"
    try:
        parsed = urlsplit(value)
        assert (
            parsed.scheme == "https"
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and parsed.port in (None, 443)
        )
        assert re.fullmatch(r"[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*", value)
        assert not re.search(r"%(?![0-9a-fA-F]{2})", value)
        assert not any(
            re.search(r"[\[\]]", p) for p in (parsed.path, parsed.query, parsed.fragment)
        )
    except ValueError as error:
        raise AssertionError("Invalid switching URI") from error
    return parsed


def validate_schema(value, schema, schemas, pointer=""):
    """Validate exactly the offline contracts' supported schema vocabulary."""
    registry = {s["$id"]: s for s in schemas.values() if "$id" in s}
    registry["urn:infrastructure-impact:kev:1"] = schemas["kev-v1.json"]

    def valid(v, s, root):
        try:
            check(v, s, root)
            return True
        except AssertionError:
            return False

    def check(v, s, root):
        if type(s) is bool:
            assert s, "Forbidden schema value"
            return
        assert isinstance(s, dict) and not set(s) - KEYWORDS, "Unsupported switching schema keyword"
        if "$ref" in s:
            base, _, fragment = s["$ref"].partition("#")
            target = registry[base] if base else root
            resolved = target
            for key in fragment.lstrip("/").split("/") if fragment else []:
                resolved = resolved[key.replace("~1", "/").replace("~0", "~")]
            check(v, resolved, target)
        if "type" in s:
            types = {
                "object": dict,
                "array": list,
                "string": str,
                "integer": int,
                "number": (int, float),
                "boolean": bool,
                "null": type(None),
            }
            names = s["type"] if isinstance(s["type"], list) else [s["type"]]
            expected = [
                t
                for name in names
                for t in (types[name] if isinstance(types[name], tuple) else (types[name],))
            ]
            assert type(v) in expected, "Invalid switching type"
        if "const" in s:
            assert canonical(v) == canonical(s["const"]), "Invalid switching constant"
        if "enum" in s:
            assert canonical(v) in [canonical(x) for x in s["enum"]], "Invalid switching enum"
        if "anyOf" in s:
            assert any(valid(v, x, root) for x in s["anyOf"]), "Invalid switching alternative"
        if "oneOf" in s:
            assert sum(valid(v, x, root) for x in s["oneOf"]) == 1, "Invalid exclusive alternative"
        for branch in s.get("allOf", []):
            check(v, branch, root)
        if "not" in s:
            assert not valid(v, s["not"], root), "Invalid switching exclusion"
        if "if" in s:
            branch = "then" if valid(v, s["if"], root) else "else"
            if branch in s:
                check(v, s[branch], root)
        if type(v) is dict:
            assert set(s.get("required", [])) <= set(v), "Missing switching field"
            props = s.get("properties", {})
            assert len(v) <= s.get("maxProperties", len(v))
            for k, item in v.items():
                if "propertyNames" in s:
                    check(k, s["propertyNames"], root)
                if k in props:
                    check(item, props[k], root)
                elif s.get("additionalProperties") is False:
                    raise AssertionError("Unexpected switching field")
                elif isinstance(s.get("additionalProperties"), dict):
                    check(item, s["additionalProperties"], root)
        if type(v) is list:
            assert s.get("minItems", 0) <= len(v) <= s.get("maxItems", len(v))
            if s.get("uniqueItems"):
                assert len({canonical(x) for x in v}) == len(v), "Duplicate switching items"
            for i, item in enumerate(v):
                if i < len(s.get("prefixItems", [])):
                    check(item, s["prefixItems"][i], root)
                elif "items" in s:
                    check(item, s["items"], root)
        if type(v) is str:
            assert s.get("minLength", 0) <= len(v) <= s.get("maxLength", len(v))
            if "pattern" in s:
                assert re.search(s["pattern"], v), "Invalid switching identity"
            if s.get("format") == "date-time":
                timestamp(v)
            elif s.get("format") == "date":
                try:
                    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", v)
                    date.fromisoformat(v)
                except ValueError as error:
                    raise AssertionError("Invalid switching date") from error
            elif s.get("format") == "uri":
                uri(v)
            elif "format" in s:
                raise AssertionError("Unsupported switching format")
        if type(v) in (int, float):
            assert s.get("minimum", v) <= v <= s.get("maximum", v)

    root = schemas[schema]
    target = root
    for key in pointer.lstrip("/").split("/") if pointer else []:
        target = target[key.replace("~1", "/").replace("~0", "~")]
    check(value, target, root)


def validate_switching_report(report, publication, generated_at, schemas):
    validate_schema(report, "switching-summary-v1.json", schemas)
    assert report["publication"] == publication, "Mixed switching generations"
    assert report["generated_at"] == report["evaluated_at"] == generated_at, "Mixed switching dates"
    digest = hashlib.sha256(canonical(report["definition"]).encode()).hexdigest()
    assert digest == report["selection"]["definition_sha256"] == DEFINITION_SHA256, (
        "Wrong switching definition"
    )
    selection = report["selection"]
    assert selection["requested_vendor"] is None and selection["requested_cve_ids"] is None
    assert selection["scope_level"] == "os_family" and selection["requested_window"] == "all"
    assert selection["effective_vendors"] == ["cisco", "aruba", "arista"]
    if report["availability"] == "unavailable":
        assert not report["rows"] and not report["sources"], "Unavailable study has observations"
        assert not selection["effective_windows"] and not selection["effective_cve_ids"]
        return
    expected_rows = [v + ":os_family:all" for v in selection["effective_vendors"]]
    assert [r["row_id"] for r in report["rows"]] == selection["effective_windows"] == expected_rows
    assert selection["effective_cve_ids"] == sorted(
        {cid for row in report["rows"] for cid in row["cve_ids"]}
    ), "Invalid switching effective CVE union"
    for source in report["sources"]:
        host = uri(source["source_url"]).hostname
        assert any(
            host == domain or host.endswith("." + domain)
            for domain in (
                "cisco.com",
                "arista.com",
                "hpe.com",
                "arubanetworks.com",
                "arubanetworking.hpe.com",
                "cve.org",
                "nist.gov",
                "mitre.org",
                "cisa.gov",
            )
        ), "Unofficial switching source"
    for row in report["rows"]:
        counts = row["counts"]
        assert row["row_id"] == row["vendor"] + ":os_family:all"
        assert row["scope_level"] == "os_family" and row["window"] == "all"
        for count, ids in [
            ("advisories", "advisory_ids"),
            ("affected_advisories", "affected_advisory_ids"),
            ("cves", "cve_ids"),
            ("claims", "claim_ids"),
            ("affected_cves", "affected_cve_ids"),
            ("conditional_cves", "conditional_cve_ids"),
            ("remediation_events", "event_ids"),
        ]:
            assert counts[count] == len(row[ids]), "Invalid switching count"
        assert set(row["affected_cve_ids"]) <= set(row["cve_ids"])
        assert set(row["conditional_cve_ids"]) <= set(row["affected_cve_ids"])
        assert set(row["affected_advisory_ids"]) <= set(row["advisory_ids"])
        for counter in (
            "draft_advisories",
            "fixed_only_claims",
            "planned_fix_claims",
            "workaround_claims",
            "model_unresolved_claims",
        ):
            assert counts[counter] <= counts["claims"], "Switching claim counter exceeds claims"
        assert counts["conditionality_unclassified_cves"] <= counts["affected_cves"], (
            "Unclassified conditionality exceeds affected CVEs"
        )
        assert row["event_ids"] == [e["event_id"] for e in row["events"]]
        assert counts["bundled_events"] == sum(e["kind"] == "bundle" for e in row["events"])
        assert counts["unbundled_publications"] == sum(
            e["kind"] == "unbundled" for e in row["events"]
        )
        for facet in row["severity"]:
            assert facet["count"] == len(facet["cve_ids"])
            assert set(facet["cve_ids"]) <= set(row["affected_cve_ids"])
        for facet in row["vendor_severity"]:
            assert facet["count"] == len(facet["advisory_ids"])
            assert set(facet["advisory_ids"]) <= set(row["advisory_ids"])
        for bucket in row["status_buckets"]:
            assert bucket["count"] == len(bucket["cve_ids"])
            assert set(bucket["cve_ids"]) <= set(row["cve_ids"])
            assert set(bucket["claim_ids"]) <= set(row["claim_ids"])
        kev = row["kev"]
        assert kev["listed_count"] == len(kev["listed_cve_ids"])
        assert kev["unknown_count"] == len(kev["unknown_cve_ids"])
        assert kev["denominator"] == counts["affected_cves"]
        listed, unknown = set(kev["listed_cve_ids"]), set(kev["unknown_cve_ids"])
        affected = set(row["affected_cve_ids"])
        assert listed <= affected and unknown <= affected and not listed & unknown
        if kev["availability"] == "available":
            assert not unknown, "Available KEV cannot have unknown membership"
        else:
            assert not listed and unknown == affected, "Unavailable KEV must be entirely unknown"
        for source in row["coverage"]["sources"]:
            assert source["vendor"] == row["vendor"], "Mixed coverage vendors"
            domains = {
                "cisco": ("cisco.com", "cveawg.mitre.org"),
                "aruba": ("hpe.com", "arubanetworks.com"),
                "arista": ("arista.com",),
            }[row["vendor"]]
            host = uri(source["source_url"]).hostname
            assert any(host == d or host.endswith("." + d) for d in domains), (
                "Foreign vendor coverage source"
            )
        assert row["coverage"]["expected_advisories"] is None
        assert row["coverage"]["observed_advisories"] == counts["advisories"]
        assert row["denominators"] == dict(
            affected_cves=counts["affected_cves"],
            observed_advisories=counts["advisories"],
            expected_advisories=None,
        )


def validate_public_metrics(record):
    """Only the writer's explicit CVSS projection may occupy public metrics."""
    fields = set(
        "system version value vector severity cve_id product_ids scope source provider origin applicability revision validation vector_group issues context product_context preferred".split()
    )
    for metric in record.get("metrics", []):
        assert isinstance(metric, dict) and set(metric) == fields, "Private metric fields"
        assert (
            metric["system"] == "CVSS"
            and metric["validation"] == "valid"
            and metric["scope"] == "cve_specific"
        )
        assert metric["version"] in ("2.0", "3.0", "3.1", "4.0")
        assert type(metric["value"]) in (int, float) and 0 <= metric["value"] <= 10
        assert metric["cve_id"] in record["cves"] and type(metric["preferred"]) is bool
        assert isinstance(metric["vector"], str) and metric["vector"]
        assert metric["origin"] in ("vendor_advisory", "cve_record", "nvd")
        assert metric["applicability"] in ("source_product", "cve_level")
        for field in ("provider", "revision"):
            assert metric[field] is None or isinstance(metric[field], str)
        assert metric["severity"] in ("None", "Low", "Medium", "High", "Critical", "Unknown")
        assert isinstance(metric["vector_group"], str)
        for field in ("product_ids", "issues", "context"):
            assert isinstance(metric[field], list) and all(
                isinstance(v, str) for v in metric[field]
            )
        source = metric["source"]
        assert isinstance(source, dict) and set(source) == set(
            "source_url source_sha256 retrieved_at source_locator".split()
        )
        uri(source["source_url"])
        assert re.fullmatch("[a-f0-9]{64}", source["source_sha256"])
        assert isinstance(source["source_locator"], str) and source["source_locator"]
        if source["retrieved_at"] is not None:
            timestamp(source["retrieved_at"])
        assert isinstance(metric["product_context"], list)
        for product in metric["product_context"]:
            assert set(product) == set(
                "product_id product source_locator version_expressions issues".split()
            )
            assert product["product_id"] in metric["product_ids"]
            for field in ("product", "source_locator"):
                assert product[field] is None or isinstance(product[field], str)
            for field in ("version_expressions", "issues"):
                assert isinstance(product[field], list) and all(
                    isinstance(v, str) for v in product[field]
                )


def publication_codec():
    """Load the shipped canonical stdlib codec; never maintain a monitor fork."""
    import importlib.util
    import sys
    from pathlib import Path

    path = Path(__file__).with_name("publication_codec.py")
    if not path.is_file():
        path = Path(__file__).parents[1] / "infrastructure_impact/publication_codec.py"
    assert path.is_file() and not path.is_symlink(), "Canonical publication codec missing"
    spec = importlib.util.spec_from_file_location("_impact_publication_codec", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def open_publication_v2(index, verified, manifest, schemas):
    from collections import OrderedDict

    codec = publication_codec()
    identity = {k: index[k] for k in ("publication", "generated_at")}
    cache, cache_bytes = OrderedDict(), 0

    def fetch(desc, *, kind=None):
        nonlocal cache_bytes
        codec.validate_descriptor(
            desc,
            paths={"publication-v2.json"} if kind is None else None,
            max_bytes=2_000_000 if kind is None else 8_000_000,
        )
        assert manifest["sha256"].get(desc["path"]) == desc["sha256"], "Unbound v2 part"
        raw = cache.pop(desc["path"], None)
        if raw is None:
            raw = verified(desc["path"], desc["bytes"])
            assert len(raw) == desc["bytes"], "V2 part size"
            while cache and cache_bytes + len(raw) > 16_000_000:
                _, old = cache.popitem(last=False)
                cache_bytes -= len(old)
            cache_bytes += len(raw)
        cache[desc["path"]] = raw
        value = codec.strict_loads(raw)
        assert all(value.get(k) == v for k, v in identity.items()), "Mixed v2 generation"
        if kind is not None:
            assert (
                set(value) == {"schema_version", "publication", "generated_at", "kind", "data"}
                and type(value["schema_version"]) is int
                and value["schema_version"] == 2
                and value["kind"] == kind
            ), "V2 envelope"
            if kind not in ("strings", "shapes", "tokens"):
                validate_schema(value, "publication-v2.json", schemas, "/$defs/envelope")
            return value["data"]
        return value

    validate_schema(index, "static-index-v2.json", schemas)
    catalog = fetch(index["publication_v2"])
    validate_schema(catalog, "publication-v2.json", schemas)
    reader = codec.CatalogReader(
        fetch,
        catalog,
        identity,
        dict(
            part=8_000_000,
            index=2_000_000,
            selected=128_000_000,
            cache=16_000_000,
            stream=1_000_000_000,
            default=20_000_000,
        ),
    )
    return reader


def validate_switching_overview(reader, schemas):
    codec = publication_codec()
    report = reader.fetch(reader.catalog["switching"]["overview"], kind="overview")
    validate_schema(report, "switching-overview-v2.json", schemas)
    assert (
        report["publication"] == reader.identity["publication"]
        and report["generated_at"] == report["evaluated_at"] == reader.identity["generated_at"]
    )
    assert (
        hashlib.sha256(canonical(report["definition"]).encode()).hexdigest()
        == reader.catalog["switching"]["definition_sha256"]
        == report["selection"]["definition_sha256"]
        == DEFINITION_SHA256
    )
    selection = report["selection"]
    assert selection["requested_vendor"] is None and selection["requested_cve_ids"] is None
    assert selection["scope_level"] == "os_family" and selection["requested_window"] == "all"
    assert selection["effective_vendors"] == ["cisco", "aruba", "arista"]
    strings, _ = reader._tables()
    routes = codec.claim_routes(
        [reader.fetch(p, kind="claim_routes") for p in reader.catalog["routes"]["claims"]], strings
    )
    claim_ids = {r[0] for r in routes}
    # Bind every declared claim interval against the independently paged range catalog.
    ranges = reader.ranges("switching-evidence.json")
    parent = ranges[("claims",)]
    first = next(
        reader.iter_tokens("switching-evidence.json", parent["first_token"], parent["end_token"])
    )
    assert first == [-1, len(routes)], "Incomplete claim routing"
    if routes:
        assert routes[0][1] == parent["first_token"] + 1 and routes[-1][2] == parent["end_token"]
    snapshot_ranges = reader.ranges("snapshot.json")

    def binding(bound, path):
        assert bound == snapshot_ranges[tuple(path)], "Overview range binding"
        first = next(reader.iter_tokens(bound["root"], bound["first_token"], bound["end_token"]))
        assert isinstance(first, list) and len(first) == 2 and first[0] == -1, (
            "Overview array boundary"
        )
        return codec.safe_int(first[1])

    binding(report["detail_ranges"]["sources"], ("switching_comparison", "sources"))
    for i, row in enumerate(report["rows"]):
        counts = row["counts"]
        assert row["row_id"] == row["vendor"] + ":os_family:all"
        assert row["scope_level"] == "os_family" and row["window"] == "all"
        for counter, key in [
            ("advisories", "advisory_ids"),
            ("affected_advisories", "affected_advisory_ids"),
            ("cves", "cve_ids"),
            ("claims", "claim_ids"),
            ("conditional_cves", "conditional_cve_ids"),
            ("remediation_events", "event_ids"),
        ]:
            assert counts[counter] == binding(
                row["detail_ranges"][key], ("switching_comparison", "rows", i, key)
            ), "Overview count mismatch"
        assert counts["remediation_events"] == binding(
            row["detail_ranges"]["events"], ("switching_comparison", "rows", i, "events")
        )
        assert counts["affected_cves"] == len(row["affected_cve_ids"])
        assert (
            counts["bundled_events"] + counts["unbundled_publications"]
            == counts["remediation_events"]
        )
        for bucket in row["status_buckets"]:
            assert (
                bucket["count"] == len(bucket["cve_ids"]) and set(bucket["claim_ids"]) <= claim_ids
            )
        for facet in row["severity"]:
            assert facet["count"] == len(facet["cve_ids"]) and set(facet["cve_ids"]) <= set(
                row["affected_cve_ids"]
            )
        for field in (
            "draft_advisories",
            "fixed_only_claims",
            "planned_fix_claims",
            "workaround_claims",
            "model_unresolved_claims",
        ):
            assert counts[field] <= counts["claims"]
        assert counts["conditionality_unclassified_cves"] <= counts["affected_cves"]
        kev = row["kev"]
        affected = set(row["affected_cve_ids"])
        assert (
            kev["listed_count"] == len(kev["listed_cve_ids"])
            and kev["unknown_count"] == len(kev["unknown_cve_ids"])
            and kev["denominator"] == len(affected)
        )
        listed, unknown = set(kev["listed_cve_ids"]), set(kev["unknown_cve_ids"])
        assert listed <= affected and unknown <= affected and not listed & unknown
        assert (
            (not unknown)
            if kev["availability"] == "available"
            else (not listed and unknown == affected)
        )
        assert (
            row["coverage"]["expected_advisories"] is None
            and row["coverage"]["observed_advisories"] == counts["advisories"]
        )
        assert row["denominators"] == dict(
            affected_cves=counts["affected_cves"],
            observed_advisories=counts["advisories"],
            expected_advisories=None,
        )
    assert [r["row_id"] for r in report["rows"]] == selection["effective_windows"]
    return report


def verify_publication_v2_archive(compressed, catalog, identity):
    import gzip
    import io

    codec = publication_codec()
    assert len(compressed) <= 8_000_000
    compressed_descriptor = catalog["archive"]["gzip"]
    codec.validate_descriptor(compressed_descriptor, paths={"snapshot-v2.json.gz"})
    assert (
        len(compressed) == compressed_descriptor["bytes"]
        and hashlib.sha256(compressed).hexdigest() == compressed_descriptor["sha256"]
    ), "Compressed archive descriptor mismatch"
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(128_000_001)
    assert len(raw) <= 128_000_000
    desc = catalog["archive"]["expanded"]
    assert len(raw) == desc["bytes"] and hashlib.sha256(raw).hexdigest() == desc["sha256"], (
        "Expanded archive mismatch"
    )
    archive = codec.strict_loads(raw, max_bytes=128_000_000)
    assert (
        set(archive)
        == {"schema_version", "representation", "publication", "generated_at", "assets"}
        and type(archive["schema_version"]) is int
        and archive["schema_version"] == 2
        and archive["representation"] == "snapshot-archive"
    )
    assert all(archive[k] == v for k, v in identity.items())
    assets = {}
    for asset in archive["assets"]:
        assert set(asset) == {"path", "sha256", "bytes", "data"}
        desc = {k: asset[k] for k in ("path", "sha256", "bytes")}
        codec.validate_descriptor(desc)
        assert desc["path"] not in assets, "Duplicate archive asset"
        encoded = (
            json.dumps(asset["data"], ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            + "\n"
        ).encode()
        assert (
            len(encoded) == desc["bytes"] and hashlib.sha256(encoded).hexdigest() == desc["sha256"]
        )
        assets[desc["path"]] = asset

    def fetch(desc, *, kind):
        codec.validate_descriptor(desc)
        assert desc["path"] in assets, "External archive reference"
        asset = assets[desc["path"]]
        assert all(asset[k] == desc[k] for k in ("path", "sha256", "bytes"))
        part = asset["data"]
        assert (
            set(part) == {"schema_version", "publication", "generated_at", "kind", "data"}
            and type(part["schema_version"]) is int
            and part["schema_version"] == 2
            and part["kind"] == kind
            and all(part[k] == v for k, v in identity.items())
        )
        return part["data"]

    scope_desc = catalog["archive"]["manifest"]
    scope = fetch(scope_desc, kind="archive")
    assert (
        set(scope)
        == {"scope", "root", "strings", "shapes", "record_routes", "members", "legacy_snapshot"}
        and scope["scope"] == "snapshot-v1"
    )
    assert scope["root"] == catalog["roots"]["snapshot.json"]
    members = {d["path"]: d for d in scope["members"]}
    assert len(members) == len(scope["members"]) and set(members) == set(assets) - {
        scope_desc["path"]
    }
    for descriptor in scope["members"]:
        codec.validate_descriptor(descriptor)
        assert all(
            assets[descriptor["path"]][key] == descriptor[key]
            for key in ("path", "sha256", "bytes")
        ), "Archive member descriptor mismatch"
    root = fetch(scope["root"], kind="root")
    closure = {
        d["path"]
        for d in [
            scope["root"],
            *scope["record_routes"],
            *root["ranges"],
            *(p["part"] for p in root["pages"]),
            *(p["part"] for p in scope["strings"]),
            *(p["part"] for p in scope["shapes"]),
        ]
    }
    assert closure == set(members), "Archive closure mismatch"
    reader = codec.CatalogReader(
        fetch,
        dict(
            roots={"snapshot.json": scope["root"]}, strings=scope["strings"], shapes=scope["shapes"]
        ),
        identity,
        dict(stream=1_000_000_000, selected=128_000_000),
    )
    # Verify canonical root and original ASCII snapshot bytes, never hydrate it.
    for _ in reader.stream_root("snapshot.json"):
        pass
    expected = scope["legacy_snapshot"]
    digest, size = hashlib.sha256(), 0
    for chunk in reader.stream_root("snapshot.json", "ascii"):
        size += len(chunk)
        digest.update(chunk)
    digest.update(b"\n")
    size += 1
    assert dict(bytes=size, sha256=digest.hexdigest()) == expected, "Legacy snapshot parity"
    return True
