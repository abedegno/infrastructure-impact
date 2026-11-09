"""Strict public contracts for the source-bound campus/branch switching study.

A binding records an explicit publisher statement or a reviewed literal alias;
validation never guesses applicability from an OS family or model-like string.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache
from importlib.resources import files
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators
from referencing import Registry, Resource

from ..source_policy import allowed
from .eligibility import timestamp

_SCHEMAS = (
    "switching-study-v1.json",
    "switching-evidence-v1.json",
    "switching-comparison-v1.json",
    "switching-summary-v1.json",
    "switching-release-history-v1.json",
    "customer-comparison-v1.json",
    "switching-overview-v2.json",
    "publication-v2.json",
    "switching-inputs-v1.json",
    "kev-v1.json",
)
_UNSET = object()
_SOURCE_FIELDS = ("source_url", "source_sha256", "retrieved_at", "source_locator")


def _source_unique_items(validator, unique, instance, schema):
    """Index only closed four-string sources; all other JSON uses stock equality.

    This replaces the pairwise object comparison, not item/type validation. The
    schema still requires uniqueItems and independently validates every source.
    """
    if (
        unique
        and type(instance) is list
        and schema.get("items")
        == {"$ref": "urn:infrastructure-impact:switching-evidence:1#/$defs/source"}
        and all(
            type(item) is dict
            and item.keys() == set(_SOURCE_FIELDS)
            and all(type(item[key]) is str for key in _SOURCE_FIELDS)
            for item in instance
        )
    ):
        seen = set()
        for item in instance:
            identity = tuple(item[key] for key in _SOURCE_FIELDS)
            if identity in seen:
                yield ValidationError("Array contains duplicate source identities")
                return
            seen.add(identity)
    else:
        yield from Draft202012Validator.VALIDATORS["uniqueItems"](
            validator, unique, instance, schema
        )


_SourceValidator = validators.extend(Draft202012Validator, {"uniqueItems": _source_unique_items})


def _json(value):
    """Reject Python-only values and nonfinite numbers at every public boundary."""

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
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def definition_sha256(value: dict) -> str:
    """Fingerprint canonical UTF-8 JSON independently of older cohort resources.

    Claim IDs use the same function over the complete claim without claim_id.
    Numeric tokens use exact finite binary64 decimal values, independent of a
    runtime's shortest-number/exponent spelling. Integral floats and signed zero
    use integer tokens. Reported scores and retained source bytes are unchanged.
    This identity format belongs only to the unreleased switching study.
    """
    if type(value) is not dict:
        raise TypeError("Expected a JSON object")
    _json(value)  # Reject non-JSON values and nonfinite numbers before hashing.

    def canonical(node):
        if type(node) is dict:
            return (
                "{"
                + ",".join(
                    json.dumps(k, ensure_ascii=False) + ":" + canonical(node[k])
                    for k in sorted(node)
                )
                + "}"
            )
        if type(node) is list:
            return "[" + ",".join(canonical(v) for v in node) + "]"
        if type(node) is float:
            if node.is_integer():
                return str(int(node))
            return format(Decimal.from_float(node), "f").rstrip("0")
        return json.dumps(node, ensure_ascii=False, allow_nan=False)

    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _validators():
    schemas = {
        name: json.loads(
            files("infrastructure_impact").joinpath("schemas", name).read_text(encoding="utf-8")
        )
        for name in _SCHEMAS
    }
    schemas["kev-v1.json"]["$id"] = "urn:infrastructure-impact:kev:1"
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    checker = FormatChecker()

    @checker.checks("date-time")
    def timestamp_format(value):
        return not isinstance(value, str) or timestamp(value) is not None

    @checker.checks("uri", raises=ValueError)
    def uri_format(value):
        if not isinstance(value, str):
            return True
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and re.fullmatch(r"[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*", value) is not None
            and not re.search(r"%(?![0-9a-fA-F]{2})", value)
            and not any(
                re.search(r"[\[\]]", part) for part in (parsed.path, parsed.query, parsed.fragment)
            )
        )

    return {
        name: _SourceValidator(schema, format_checker=checker, registry=registry)
        for name, schema in schemas.items()
    }


class _PythonPattern:
    """Preserve Python's Unicode regex behavior, including control whitespace."""

    def __init__(self, parent_schema, pattern, schema_path):
        self.pattern = re.compile(pattern)

    def validate(self, value):
        if isinstance(value, str) and self.pattern.search(value) is None:
            raise ValueError("Schema pattern mismatch")


def _deny_retrieval(uri):
    raise LookupError("Schema reference is not installed")


@lru_cache(maxsize=1)
def _compiled_validators():
    import jsonschema_rs

    originals = _validators()
    checker = next(iter(originals.values())).format_checker
    registry = jsonschema_rs.Registry(
        [(v.schema["$id"], v.schema) for v in originals.values()], retriever=_deny_retrieval
    )
    formats = {
        name: (lambda value, fmt=name: checker.conforms(value, fmt)) for name in checker.checkers
    }
    schemas = {name: validator.schema for name, validator in originals.items()}
    schemas["switching-claim"] = {
        "$ref": "urn:infrastructure-impact:switching-evidence:1#/$defs/claim"
    }
    return {
        name: jsonschema_rs.Draft202012Validator(
            schema,
            registry=registry,
            formats=formats,
            validate_formats=True,
            keywords={"pattern": _PythonPattern},
            offline=True,
        )
        for name, schema in schemas.items()
    }


def _validate_claim(value):
    """Validate a decoded claim freshly with the same installed schema/format rules."""
    _json(value)
    if not _compiled_validators()["switching-claim"].is_valid(value):
        legacy = _validators()["switching-evidence-v1.json"]
        legacy.evolve(schema=legacy.schema["properties"]["claims"]["items"]).validate(value)


def _validate(value, schema):
    _json(value)
    if not _compiled_validators()[schema].is_valid(value):
        # Preserve existing rejection/exception behavior on the compatibility path.
        _validators()[schema].validate(value)


def _official(url, vendor=None, *, reference=False):
    """Accept primary sources only, including official CVE/NVD score context."""
    u = urlsplit(url)
    if u.scheme != "https" or u.username or u.password or u.port not in (None, 443):
        raise ValueError("Source needs a public official HTTPS URL")
    if vendor is not None:
        if allowed(url, vendor):
            return
        if not reference:
            raise ValueError("Vendor evidence must retain its official publisher source")
    if reference:
        from ..adapters.cvss import official_route

        cid = u.path.rsplit("/", 1)[-1]
        if official_route(url, "cve_record", cid):
            return
    host = (u.hostname or "").lower()
    if any(
        host == domain or host.endswith("." + domain)
        for domain in (
            ("cve.org", "nvd.nist.gov") if reference else ("cve.org", "nvd.nist.gov", "cisa.gov")
        )
    ):
        return
    if not reference and allowed(url, "upstream"):
        return
    raise ValueError("Source is outside official publisher/reference domains")


def definition() -> dict:
    """Load and validate a fresh packaged resource; caller mutations stay local."""
    value = json.loads(
        files("infrastructure_impact")
        .joinpath("resources/switching-study.json")
        .read_text(encoding="utf-8")
    )
    _validate_definition(value)
    return value


def _validate_definition(value):
    _validate(value, "switching-study-v1.json")
    if value["start_date"] >= value["cutoff_date"]:
        raise ValueError("Study cutoff must follow its historical start")
    targets = value["targets"]
    if len({t["id"] for t in targets}) != len(targets):
        raise ValueError("Study target IDs must be unique")
    if len({r["id"] for r in value["references"]}) != len(value["references"]):
        raise ValueError("Study reference IDs must be unique")
    for target in targets:
        for alias in target["aliases"]:
            _official(alias["source_url"], target["vendor"])
            if alias["model"] not in target["models"]:
                raise ValueError("Alias must name a declared literal model")
    for reference in value["references"]:
        _official(reference["source_url"], reference["vendor"])


def _publication(report, publication, generated_at):
    # The enclosing generation is supplied by the publication/query boundary.
    # Without that context, the schema can validate identity shape only.
    if publication is not _UNSET and report["publication"] != publication:
        raise ValueError("Report publication must equal its enclosing generation")
    if generated_at is not _UNSET and report["generated_at"] != generated_at:
        raise ValueError("Report generation time must equal its enclosing generation")


def _missing(issues, value, code):
    if value is None and code not in issues:
        raise ValueError(f"Missing evidence requires issue code: {code}")


def validate_evidence(report: dict, *, publication=_UNSET, generated_at=_UNSET) -> None:
    """Validate strict shapes, provenance, binding attribution and missingness.

    Publication writers must supply enclosing publication and generated_at.
    Unpublished queries pass publication=None; omitted context checks shape only.
    """
    _validate(report, "switching-evidence-v1.json")
    _validate_evidence_semantics(report, publication=publication, generated_at=generated_at)


def _fingerprint(value):
    """Strict JSON types plus exact canonical bytes; never Python equality."""
    raw = _json(value)
    return len(raw), hashlib.sha256(raw).digest()


@dataclass(frozen=True, init=False)
class _ValidatedEvidence:
    """Invocation-local capability minted only after full evidence validation."""

    _value: tuple
    _context: bytes

    def __init__(self, report, *, publication, generated_at):
        validate_evidence(report, publication=publication, generated_at=generated_at)
        object.__setattr__(self, "_value", _fingerprint(report))
        object.__setattr__(self, "_context", _json([publication, generated_at]))

    def require(self, report, *, publication, generated_at):
        if (
            _json([publication, generated_at]) != self._context
            or _fingerprint(report) != self._value
        ):
            raise ValueError("Fresh evidence proof does not match complete value/context")


def _validate_aruba_reviewed_link(claim, remediation, binding, claims):
    from ..adapters.switching import aruba_reviewed_fixed, aruba_reviewed_rule

    rule = aruba_reviewed_rule(claim)
    matching = [] if rule is None else [c for c in claims if aruba_reviewed_fixed(claim, c, rule)]
    if (
        rule is None
        or binding["fixed_product"] != "AOS-CX"
        or binding.get("fixed_product_id") != rule[0]
        or binding["source"] != claim["source"]
        or binding["cve_id"] != claim["cve_id"]
        or len(matching) != 1
        or binding["fixed_source"] != matching[0]["source"]
        or matching[0]["version_expressions"] != [rule[1]]
        or remediation["product_ids"]
        or remediation["version_expressions"] != [rule[1]]
        or remediation["category"] != "vendor_fix"
        or remediation.get("availability") != "vendor_reports_fixed"
        or remediation["source"]["source_locator"] != "/vulnerabilities/0/remediations/0"
        or any(
            remediation["source"][k] != claim["source"][k]
            for k in ("source_url", "source_sha256", "retrieved_at")
        )
        or not any(
            fixed["product_ids"] == [rule[0]]
            and not fixed.get("scope_binding")
            and all(
                remediation.get(key) == fixed.get(key)
                for key in (
                    "publisher_id",
                    "category",
                    "details",
                    "published_availability",
                    "availability",
                    "availability_date",
                    "source",
                )
            )
            for fixed in matching[0]["remediations"]
        )
    ):
        raise ValueError("Reviewed section remediation requires exact retained AOS-CX/CVE linkage")


def _validate_reviewed_link(claim, remediation, binding, claims):
    if claim["vendor"] == "aruba":
        return _validate_aruba_reviewed_link(claim, remediation, binding, claims)
    from ..adapters.switching import ARISTA_FIX_RULES, ARISTA_FIXED_VERSIONS, arista_reviewed_rule

    rule = arista_reviewed_rule(claim)
    vendor = claim["vendor"]
    cid = claim["cve_id"]
    row = binding["source"]["source_locator"]
    locator = remediation["source"]["source_locator"]
    fixed_source = binding["fixed_source"]
    expected_url = (
        "https://www.arista.com/en/support/advisories-notices/security-advisory/"
        + claim["advisory_id"]
    )
    matching = [
        c
        for c in claims
        if c["vendor"] == "arista"
        and c["advisory_id"] == claim["advisory_id"]
        and c["revision"] == claim["revision"]
        and c["publisher"] == claim["publisher"]
        and c["status"] == "fixed"
        and c["scope"] == "cve_specific"
        and c["cve_id"] == cid
        and c["product"] == binding["fixed_product"]
        and c["source"] == fixed_source
    ]
    if (
        vendor != "arista"
        or binding["fixed_product"] != "Arista EOS"
        or "fixed_product_id" in binding
        or rule is None
        or claim["source"]["source_url"] != expected_url
        or claim["status"] != "affected"
        or claim["scope"] != "cve_specific"
        or claim["product"] != rule[1]
        or row != rule[2]
        or locator != rule[3]
        or fixed_source != remediation["source"]
        or len(matching) != 1
        or remediation["product_ids"]
        or remediation["version_expressions"] != matching[0]["version_expressions"]
        or (
            claim["advisory_id"] in ARISTA_FIX_RULES
            and (
                claim["product_id"] is not None
                or matching[0]["product_id"] is not None
                or claim["family"] != "arista-eos"
                or matching[0]["family"] != "arista-eos"
                or matching[0]["version_expressions"] != ARISTA_FIXED_VERSIONS[claim["advisory_id"]]
                or remediation["category"] != "vendor_fix"
                or remediation["availability"] != "vendor_reports_fixed"
                or remediation["availability_date"] is not None
            )
        )
        or not any(
            all(
                remediation.get(key) == fixed.get(key)
                for key in (
                    "publisher_id",
                    "category",
                    "details",
                    "published_availability",
                    "availability",
                    "availability_date",
                    "source",
                )
            )
            for fixed in matching[0]["remediations"]
        )
    ):
        raise ValueError("Reviewed section remediation requires exact retained EOS/CVE linkage")


def _validate_evidence_semantics(
    report, *, publication=_UNSET, generated_at=_UNSET, _study=None, _linkage=None
):
    """Check evidence whose complete shape was validated by its enclosing boundary."""
    _publication(report, publication, generated_at)
    study = definition() if _study is None else _study
    if report["definition_sha256"] != definition_sha256(study):
        raise ValueError("Evidence definition fingerprint does not match the packaged study")
    seen = set()
    for claim in report["claims"]:
        identity = definition_sha256({k: v for k, v in claim.items() if k != "claim_id"})
        if claim["claim_id"] != identity or identity in seen:
            raise ValueError("Claim IDs must be deterministic and unique")
        seen.add(identity)
        vendor = claim["vendor"]
        _official(claim["source"]["source_url"], vendor)
        for key, code in (
            ("revision", "revision_missing"),
            ("cve_id", "cve_id_missing"),
            ("product_id", "product_id_missing"),
            ("product", "product_missing"),
            ("family", "family_unresolved"),
            ("initial_published_at", "initial_publication_date_missing"),
            ("updated_at", "update_date_missing"),
        ):
            _missing(claim["issues"], claim[key], code)
        for key in ("id", "sequence", "status"):
            _missing(claim["issues"], claim["publisher"][key], f"publisher_{key}_missing")
        if claim["publisher"].get("source") is not None:
            publisher_source = claim["publisher"]["source"]
            _official(publisher_source["source_url"], vendor)
            if any(
                publisher_source[key] != claim["source"][key]
                for key in ("source_url", "source_sha256", "retrieved_at")
            ):
                raise ValueError("Publisher metadata must share the claim source identity")
        bindings = claim["platform_bindings"]
        qualified = (
            bool(bindings)
            and all(b["basis"] != "unresolved" for b in bindings)
            and {b["platform"] for b in bindings} == set(claim["named_platforms"])
        )
        if claim["scope_level"] == "model_qualified" and not qualified:
            raise ValueError("Unresolved model bindings cannot qualify a claim")
        if not qualified and "model_binding_unresolved" not in claim["issues"]:
            raise ValueError("Unresolved model binding requires an issue code")
        for binding in bindings:
            if binding["platform"] not in claim["named_platforms"]:
                raise ValueError("A platform binding must retain its named publisher platform")
            if binding["basis"] == "unresolved":
                if binding["model"] is not None:
                    raise ValueError("Unresolved binding cannot assert a model")
            elif binding["model"] is None or binding["source"] is None:
                raise ValueError("Positive model binding requires a model and source locator")
            if binding["basis"] != "unresolved":
                targets = [
                    t
                    for t in study["targets"]
                    if t["vendor"] == vendor
                    and t["family"] == claim["family"]
                    and binding["model"] in t["models"]
                ]
                if not targets:
                    raise ValueError("Qualified model must belong to this study vendor/family")
                if binding["basis"] == "reviewed_alias" and not any(
                    a["literal"] == binding["platform"]
                    and a["model"] == binding["model"]
                    and a["source_url"] == binding["source"]["source_url"]
                    and a["source_locator"] == binding["source"]["source_locator"]
                    for target in targets
                    for a in target["aliases"]
                ):
                    raise ValueError(
                        "Reviewed alias requires an exact registered alias and locator"
                    )
            if binding["source"] is not None:
                _official(binding["source"]["source_url"], vendor)
        for remediation in claim["remediations"]:
            _official(remediation["source"]["source_url"], vendor)
            binding = remediation.get("scope_binding")
            if binding is not None:
                bound = binding["source"]
                row = bound["source_locator"]
                same_identity = all(
                    bound[key] == claim["source"][key] == remediation["source"][key]
                    for key in ("source_url", "source_sha256", "retrieved_at")
                )
                locator = remediation["source"]["source_locator"]
                if (
                    not same_identity
                    or binding["cve_id"] != claim["cve_id"]
                    or row != claim["source"]["source_locator"]
                ):
                    raise ValueError(
                        "Same-row remediation or reviewed sections require identical source and CVE scope"
                    )
                if binding["basis"] == "same_source_row":
                    if not (locator == row or locator.startswith(row + "/")):
                        raise ValueError(
                            "Same-row remediation requires identical source, row and CVE scope"
                        )
                else:
                    if _linkage is None:
                        _validate_reviewed_link(claim, remediation, binding, report["claims"])
                    else:
                        _linkage.append((claim, remediation, binding))
            product_ids = remediation["product_ids"]
            if (
                product_ids
                and claim["product_id"] is not None
                and claim["product_id"] not in product_ids
            ):
                raise ValueError("Product-bound remediation must include this publisher product ID")
            if (
                (not product_ids or claim["product_id"] is None)
                and binding is None
                and "remediation_product_scope_unresolved" not in claim["issues"]
            ):
                raise ValueError("Unscoped remediation requires an unresolved product-scope issue")
            _missing(
                claim["issues"],
                remediation["published_availability"],
                "availability_statement_missing",
            )
            _missing(
                claim["issues"], remediation["publisher_id"], "remediation_publisher_id_missing"
            )
            _missing(claim["issues"], remediation["availability_date"], "availability_date_missing")
        bundle = claim["bundle"]
        if bundle is not None:
            _official(bundle["source"]["source_url"], vendor)
            if claim["advisory_id"] not in bundle["member_advisory_ids"]:
                raise ValueError("Bundle must explicitly name this advisory as a member")
            _missing(claim["issues"], bundle["published_at"], "bundle_publication_date_missing")
        for rating in claim.get("vendor_severity", []):
            _official(rating["source"]["source_url"], vendor)
            if rating["vendor"] != vendor or rating["advisory_id"] != claim["advisory_id"]:
                raise ValueError("Vendor rating must identify this advisory")
            if (
                rating["scope"] != "advisory"
                or rating["cve_id"] is not None
                or rating["product_ids"]
            ):
                raise ValueError("Advisory rating cannot become a per-CVE/product score")
            for key in ("scheme", "namespace"):
                _missing(rating["issues"], rating[key], f"vendor_severity_{key}_missing")
        for score in claim["scores"]:
            _official(score["source"]["source_url"], vendor, reference=True)
            if score["scope"] == "cve_specific" and (
                score["cve_id"] is None or score["cve_id"] != claim["cve_id"]
            ):
                raise ValueError("CVE-specific score must identify this claim CVE")
            if score["product_ids"] and claim["product_id"] not in score["product_ids"]:
                raise ValueError("Product-bound score must include this publisher product ID")
            _missing(claim["issues"], score["value"], "score_value_missing")
            if score["scope"] == "unresolved" and "score_scope_unresolved" not in claim["issues"]:
                raise ValueError("Unresolved score scope requires an issue code")
    for row in report.get("score_availability", []):
        _official(row["source_url"], row["vendor"])
        if row["source"] is not None:
            _official(row["source"]["source_url"], row["vendor"])
            if row["source"]["source_url"] != row["source_url"]:
                raise ValueError("Score availability source differs from its representation")
        if any(a["cve_id"] != row["cve_id"] for a in row["attempts"]):
            raise ValueError("Score attempt belongs to another CVE")
    for coverage in report["coverage"]:
        _official(coverage["source_url"], coverage["vendor"])
        enumeration = coverage.get("enumeration")
        if enumeration is not None:
            if enumeration["definition_sha256"] != report["definition_sha256"]:
                raise ValueError("Enumeration must use the same study definition")
            if enumeration["window"]["start_date"] > enumeration["window"]["end_date"]:
                raise ValueError("Enumeration window end precedes start")
        _missing(coverage["issues"], coverage["total"], "publisher_total_unknown")
        _missing(coverage["issues"], coverage["observed_start"], "observation_start_unknown")
        _missing(coverage["issues"], coverage["observed_end"], "observation_end_unknown")
        if (
            coverage["observed_start"] is not None
            and coverage["observed_end"] is not None
            and coverage["observed_start"] > coverage["observed_end"]
        ):
            raise ValueError("Coverage observation end precedes its start")


def validate_comparison(report: dict, *, publication=_UNSET, generated_at=_UNSET) -> None:
    """Validate strict descriptive rows and recompute derived identities/counts."""
    _validate(report, "switching-comparison-v1.json")
    _publication(report, publication, generated_at)
    _validate_definition(report["definition"])
    from .switching_comparison import validate_semantics

    validate_semantics(report)
    for source in report["sources"]:
        # Comparison sources can contain any of the registered study vendors.
        if not any(allowed(source["source_url"], v) for v in ("cisco", "aruba", "arista")):
            try:
                _official(source["source_url"])
            except ValueError:
                _official(source["source_url"], reference=True)


def _validate_comparison_evidence(report, standalone, *, publication, generated_at):
    """Compose standalone evidence from this call's full comparison proof."""
    validate_comparison(report, publication=publication, generated_at=generated_at)
    if _fingerprint(standalone) != _fingerprint(report["inputs"]["evidence"]):
        raise ValueError("Switching asset and comparison evidence disagree")


def _latest_retained_source(db, vendor, url):
    """Select bytes by successful observation chronology, never content IDs alone."""
    events = [
        dict(r)
        for r in db.execute(
            "SELECT id AS evidence_id, observed_at AS at, 0 AS kind, id AS event_id FROM evidence WHERE source_url=?",
            (url,),
        )
    ]
    events += [
        dict(r)
        for r in db.execute(
            "SELECT evidence_id, checked_at AS at, 2 AS kind, id AS event_id FROM source_observations WHERE vendor=? AND source_url=?",
            (vendor, url),
        )
    ]
    events += [
        dict(r)
        for r in db.execute(
            "SELECT evidence_id, observed_at AS at, 1 AS kind, id AS event_id FROM revisions WHERE vendor=? AND source_url=?",
            (vendor, url),
        )
    ]
    events = [event for event in events if timestamp(event["at"]) is not None]
    # Once actual successful retrieval observations exist, parser replay
    # timestamps cannot supersede them. New raw captures still participate.
    if any(event["kind"] == 2 for event in events):
        events = [event for event in events if event["kind"] != 1]
    if not events:
        return None
    event = max(events, key=lambda e: (timestamp(e["at"]), e["kind"], e["event_id"]))
    row = dict(
        db.execute(
            "SELECT *, observed_at AS retrieved_at FROM evidence WHERE id=?",
            (event["evidence_id"],),
        ).fetchone()
    )
    observations = [e for e in events if e["kind"] == 2 and e["evidence_id"] == row["id"]]
    if observations:
        row["retrieved_at"] = max(observations, key=lambda e: (timestamp(e["at"]), e["event_id"]))[
            "at"
        ]
    return row


def inputs(db, records: list[dict]) -> dict:
    """Reconstruct latest-known claims per retained source representation.

    A core latest advisory selects the identities of interest, not a winning
    representation. Earlier alternate URLs keep their own dated revision/hash;
    these are not historical-as-of exposure assertions.
    """
    import copy

    from ..adapters.switching import bindings_resource
    from ..plugins.registry import default_registry

    selected = {
        (r["vendor"], r["advisory_id"])
        for r in records
        if r["vendor"] in {"cisco", "aruba", "arista"}
    }
    result = dict(schema_version=1, claims=[], coverage=[], issues=[])
    bundles = []
    registry = default_registry()
    entries = bindings_resource()["entries"]
    registered_urls = {(e["vendor"], e["source_url"]) for e in entries}

    def retained(extracted, row, revision):
        def stamp(value):
            if isinstance(value, dict):
                if "source_url" in value and "source_sha256" in value:
                    if (
                        value["source_url"] != row["source_url"]
                        or value["source_sha256"] != row["sha256"]
                    ):
                        raise ValueError("Research source does not match retained bytes")
                    value["retrieved_at"] = row["retrieved_at"]
                for item in value.values():
                    stamp(item)
            elif isinstance(value, list):
                for item in value:
                    stamp(item)

        stamp(extracted)
        for claim in extracted.get("claims", []):
            claim["revision"] = str(revision) if revision is not None else None
            claim.setdefault("issues", []).append(
                "latest_known_representation_not_historical_exposure"
            )
        result["claims"].extend(extracted.get("claims", []))
        bundles.extend(extracted.get("bundles", []))
        result["issues"].extend(extracted.get("issues", []))

    rows = db.execute("""SELECT r.* FROM revisions r
        WHERE r.id IN (SELECT MAX(id) FROM revisions GROUP BY vendor,advisory_id,source_url)
        ORDER BY r.vendor,r.advisory_id,r.source_url""")
    for representation in rows:
        vendor, url = representation["vendor"], representation["source_url"]
        advisory_id = representation["advisory_id"]
        if (vendor, advisory_id) not in selected or (vendor, url) in registered_urls:
            continue
        row = _latest_retained_source(db, vendor, url)
        # The representation has retained evidence through its foreign key.
        revision = db.execute(
            "SELECT * FROM revisions WHERE evidence_id=? AND vendor=? AND source_url=? AND advisory_id=? ORDER BY id DESC LIMIT 1",
            (row["id"], vendor, url, advisory_id),
        ).fetchone()
        source_issues = []
        if revision is None:
            # Generic unnormalized bytes have no verified advisory identity.
            # Only the separately reviewed exact-byte bindings permit fallback.
            source_issues.append("source_normalization_unavailable")
        else:
            try:
                extracted = registry.research_evidence(
                    row["raw"], url, vendor, json.loads(revision["normalized"])
                )
                if extracted is None:
                    source_issues.append("research_hook_unavailable")
                else:
                    retained(extracted, row, revision["id"])
                    source_issues.extend(extracted.get("issues", []))
            except (ValueError, TypeError, KeyError):
                source_issues.append("source_extraction_failed")
        result["issues"].extend(source_issues)
        result["coverage"].append(
            dict(
                vendor=vendor,
                source_url=url,
                state="partial",
                observed_start=row["retrieved_at"][:10],
                observed_end=row["retrieved_at"][:10],
                total=None,
                issues=["publisher_total_unknown", "retained_documents_not_archive_coverage"]
                + source_issues,
            )
        )
    # Reviewed source-only evidence cannot invent a normalized revision. Choose
    # successful observation/revision chronology: content IDs alone lose A→B→A.
    visited = set()
    for entry in entries:
        vendor, url = entry["vendor"], entry["source_url"]
        publisher_id = entry.get("publisher", {}).get("id")
        if "bundle" not in entry and (vendor, publisher_id) not in selected:
            continue
        if (vendor, url) in visited:
            continue
        visited.add((vendor, url))
        row = _latest_retained_source(db, vendor, url)
        if row is None:
            if "bundle" in entry:
                result["issues"].append("bundle_source_unavailable")
            continue
        revision = db.execute(
            "SELECT * FROM revisions WHERE evidence_id=? AND vendor=? AND source_url=? AND advisory_id=? ORDER BY id DESC LIMIT 1",
            (row["id"], vendor, url, publisher_id),
        ).fetchone()
        document = (
            json.loads(revision["normalized"])
            if revision
            else {"advisory_id": publisher_id or entry["bundle"]["publisher_id"]}
        )
        extracted = registry.research_evidence(row["raw"], url, vendor, document)
        if revision is None:
            for claim in extracted.get("claims", []):
                claim["issues"].append("source_normalization_unavailable")
        retained(extracted, row, revision["id"] if revision else None)
        result["coverage"].append(
            dict(
                vendor=vendor,
                source_url=url,
                state="partial",
                observed_start=row["retrieved_at"][:10],
                observed_end=row["retrieved_at"][:10],
                total=None,
                issues=["publisher_total_unknown", "retained_documents_not_archive_coverage"]
                + (
                    ["source_normalization_unavailable"]
                    if revision is None and "bundle" not in entry
                    else []
                ),
            )
        )
    expanded = []
    for claim in result["claims"]:
        members = [
            b
            for b in bundles
            if claim["advisory_id"] in b["member_advisory_ids"]
            and allowed(b["source"]["source_url"], claim["vendor"])
        ]
        for bundle in members or [None]:
            expanded.append({**copy.deepcopy(claim), "bundle": copy.deepcopy(bundle)})
    _attach_scores(expanded, score_inputs(db, records))
    result["claims"] = expanded
    result["issues"] = sorted(set(result["issues"]))
    return result


def _attach_scores(claims, score_data):
    """Select original scopes and priority first, then copy exact claim PID subsets.

    Ordinals identify original candidate occurrences in this extraction only.
    Different overlapping scopes therefore cannot share a preference result just
    because they share a URL, CVE or score value. Full ordinary metrics stay owned
    by the caller; no cache or projected object escapes into source inputs.
    """
    import copy
    from collections import defaultdict

    from ..adapters.cvss import public_metrics

    candidates, index = [], defaultdict(list)
    for entry in score_data["advisories"] + [
        {"vendor": None, "advisory_id": None, **score_data["fallback"]}
    ]:
        for score in entry["claims"]:
            ordinal = len(candidates)
            candidates.append(score)
            representation = (
                score["source"]["source_url"] if score["origin"] == "vendor_advisory" else None
            )
            for pid in set(score["product_ids"]) or {None}:
                key = (entry["vendor"], entry["advisory_id"], score["cve_id"], representation, pid)
                index[key].append(ordinal)
    ratings = defaultdict(list)
    for rating in score_data["vendor_severity"]:
        ratings[rating["vendor"], rating["advisory_id"]].append(rating)
    cache = {}
    for claim in claims:
        claim["vendor_severity"] = copy.deepcopy(ratings[claim["vendor"], claim["advisory_id"]])
        if not claim["vendor_severity"]:
            claim["issues"].append("vendor_severity_unavailable")
        keys = {
            (vendor, advisory, claim["cve_id"], representation, pid)
            for vendor, advisory in ((claim["vendor"], claim["advisory_id"]), (None, None))
            for representation in (claim["source"]["source_url"], None)
            for pid in (claim["product_id"], None)
        }
        identity = tuple(sorted(i for key in keys for i in index.get(key, ())))
        relevant = [candidates[i] for i in identity]
        if identity not in cache:
            metrics = public_metrics(relevant) + [
                {**score, "preferred": False}
                for score in relevant
                if score["validation"] == "incomplete"
            ]
            prepared = []
            for score in metrics:
                context = defaultdict(list)
                for product in score.get("product_context", []):
                    context[product["product_id"]].append(product)
                prepared.append((score, set(score["product_ids"]), context))
            cache[identity] = prepared
        claim["scores"] = []
        pid = claim["product_id"]
        for score, pids, context in cache[identity]:
            projected = score
            if pid is not None and pid in pids:
                projected = {**score, "product_ids": [pid]}
                if "product_context" in score:
                    projected["product_context"] = context.get(pid, [])
            claim["scores"].append(copy.deepcopy(projected))
        for score in relevant:
            if score["validation"] == "invalid":
                claim["issues"].append("score_invalid")
            elif score["validation"] == "incomplete":
                claim["issues"].extend(score["issues"])
                if score["value"] is None:
                    claim["issues"].append("score_value_missing")
        if not relevant:
            claim["issues"].append("score_unavailable")


def project(inputs: dict, *, publication: dict | None, generated_at: str) -> dict:
    """Allowlist every nested public field, then validate the complete contract."""
    result = _project(inputs, publication=publication, generated_at=generated_at)
    validate_evidence(result, publication=publication, generated_at=generated_at)
    return result


def _project_with_proof(inputs, *, publication, generated_at):
    result = _project(inputs, publication=publication, generated_at=generated_at)
    proof = _ValidatedEvidence(result, publication=publication, generated_at=generated_at)
    return result, proof


def _project(inputs: dict, *, publication: dict | None, generated_at: str) -> dict:
    """Construct allowlisted fields; the validating wrappers own the boundary."""
    schema = json.loads(
        files("infrastructure_impact").joinpath("schemas/switching-evidence-v1.json").read_text()
    )

    def clean(value, shape):
        if "$ref" in shape:
            shape = schema["$defs"][shape["$ref"].rsplit("/", 1)[1]]
        if "anyOf" in shape:
            if value is None:
                return None
            shape = next(s for s in shape["anyOf"] if s.get("type") != "null")
            return clean(value, shape)
        if isinstance(value, dict):
            return {
                k: clean(value[k], s) for k, s in shape.get("properties", {}).items() if k in value
            }
        if isinstance(value, list):
            return [clean(v, shape.get("items", {})) for v in value]
        if isinstance(value, str) and len(value) > 4000:
            raise ValueError("Public switching evidence text must be bounded to 4000 characters")
        return value

    result = clean(inputs, schema)
    result.update(
        schema_version=1,
        publication=publication,
        generated_at=generated_at,
        definition_sha256=definition_sha256(definition()),
    )
    result.setdefault("claims", [])
    result.setdefault("coverage", [])
    result.setdefault("issues", [])
    claims = {}
    for claim in result["claims"]:
        issues = claim.setdefault("issues", [])
        # Core advisory-v2 permits timezone-less publisher timestamps. Study
        # chronology cannot place them on a UTC day; retain the original capture
        # and report the unknown at this source-to-study boundary, never invent UTC.
        for key, code in (
            ("initial_published_at", "initial_publication_date"),
            ("updated_at", "update_date"),
        ):
            value = claim.get(key)
            if value is not None and not (
                _validators()["switching-evidence-v1.json"].format_checker.conforms(value, "date")
                or timestamp(value) is not None
            ):
                claim[key] = None
                issues.append(code + "_unusable")
        for key, code in (
            ("revision", "revision_missing"),
            ("cve_id", "cve_id_missing"),
            ("product_id", "product_id_missing"),
            ("product", "product_missing"),
            ("family", "family_unresolved"),
            ("initial_published_at", "initial_publication_date_missing"),
            ("updated_at", "update_date_missing"),
        ):
            if claim.get(key) is None:
                issues.append(code)
        sequence = claim["publisher"].get("sequence")
        if type(sequence) is int and abs(sequence) > 9007199254740991:
            # Preserve the literal decimal identity without browser rounding.
            claim["publisher"]["sequence"] = str(sequence)
            issues.append("publisher_sequence_integer_preserved_as_text")
        for key in ("id", "sequence", "status"):
            if claim["publisher"].get(key) is None:
                issues.append(f"publisher_{key}_missing")
        if not claim["platform_bindings"] or any(
            b["basis"] == "unresolved" for b in claim["platform_bindings"]
        ):
            issues.append("model_binding_unresolved")
        for remediation in claim["remediations"]:
            for key, code in (
                ("publisher_id", "remediation_publisher_id_missing"),
                ("published_availability", "availability_statement_missing"),
                ("availability_date", "availability_date_missing"),
            ):
                if remediation.get(key) is None:
                    issues.append(code)
            if (not remediation["product_ids"] or claim["product_id"] is None) and remediation.get(
                "scope_binding"
            ) is None:
                issues.append("remediation_product_scope_unresolved")
        if claim["bundle"] is not None and claim["bundle"]["published_at"] is None:
            issues.append("bundle_publication_date_missing")
        for key in ("issues", "named_platforms", "version_expressions", "conditions"):
            claim[key] = list(dict.fromkeys(claim[key]))
        claim["issues"].sort()
        claim.pop("claim_id", None)
        claim["claim_id"] = definition_sha256(claim)
        claims[claim["claim_id"]] = claim
    result["claims"] = list(claims.values())
    result["issues"] = sorted(set(result["issues"]))
    return result


def score_inputs(db, records: list[dict]) -> dict:
    """Source-led scores for every selected vendor advisory, plus CVE-only fallback."""
    from ..adapters import cvss
    from ..collection.score_enrichment import inputs as fallback_inputs

    selected = {(r["vendor"], r["advisory_id"]) for r in records}
    result = {
        "advisories": [],
        "vendor_severity": [],
        "fallback": fallback_inputs(db, [c for r in records for c in r["cves"]]),
    }
    for representation in db.execute(
        "SELECT * FROM revisions WHERE id IN (SELECT MAX(id) FROM revisions GROUP BY vendor,advisory_id,source_url) ORDER BY id"
    ):
        vendor, advisory_id, url = (
            representation["vendor"],
            representation["advisory_id"],
            representation["source_url"],
        )
        if (vendor, advisory_id) not in selected:
            continue
        row = _latest_retained_source(db, vendor, url)
        revision = db.execute(
            "SELECT * FROM revisions WHERE evidence_id=? AND vendor=? AND advisory_id=? AND source_url=? ORDER BY id DESC LIMIT 1",
            (row["id"], vendor, advisory_id, url),
        ).fetchone()
        if revision is None:
            parsed = {
                "claims": [],
                "issues": [{"code": "source_normalization_unavailable", "source_url": url}],
            }
        else:
            try:
                parsed = cvss.extract(row["raw"], url, vendor, json.loads(revision["normalized"]))
            except (ValueError, TypeError, KeyError, AttributeError):
                parsed = {
                    "claims": [],
                    "issues": [{"code": "score_extraction_failed", "source_url": url}],
                }
            for score in parsed["claims"] + parsed.get("vendor_severity", []):
                score["source"]["retrieved_at"] = row["retrieved_at"]
                score["revision"] = str(revision["id"])
        result["vendor_severity"].extend(parsed.get("vendor_severity", []))
        result["advisories"].append(
            dict(
                vendor=vendor,
                advisory_id=advisory_id,
                source_url=url,
                source=dict(
                    source_url=url,
                    source_sha256=row["sha256"],
                    retrieved_at=row["retrieved_at"],
                    source_locator="/",
                ),
                **parsed,
            )
        )
    # New successful API page events preserve A->B->A independently of content
    # IDs. Legacy retained membership is usable only with one unambiguous hash;
    # missing retrieval chronology must not silently pick an older rating.
    api_sources = {}
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='score_vendor_observations'").fetchone():
        for row in db.execute(
            "SELECT e.*,o.observed_at AS retrieved_at FROM score_vendor_observations o JOIN evidence e ON e.id=o.evidence_id WHERE o.id IN (SELECT MAX(id) FROM score_vendor_observations GROUP BY source_url)"
        ):
            api_sources[row["source_url"]] = dict(row)
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='switching_backfill_pages'").fetchone():
        legacy = {}
        for row in db.execute(
            "SELECT DISTINCT e.*,e.observed_at AS retrieved_at FROM switching_backfill_pages p JOIN switching_backfills b ON b.id=p.run_id JOIN evidence e ON e.id=p.evidence_id WHERE b.vendor='cisco' AND b.kind='openvuln'"
        ):
            legacy.setdefault(row["source_url"], {})[row["sha256"]] = dict(row)
        for url, hashes in legacy.items():
            if url not in api_sources and len(hashes) == 1:
                api_sources[url] = next(iter(hashes.values()))
    for row in api_sources.values():
        for vendor, identity in sorted(selected):
            if vendor != "cisco":
                continue
            parsed = cvss.extract(row["raw"], row["source_url"], vendor, {"advisory_id": identity})
            for rating in parsed["vendor_severity"]:
                rating["source"]["retrieved_at"] = row["retrieved_at"]
                rating["issues"].append("revision_missing")
                result["vendor_severity"].append(rating)
    return result
