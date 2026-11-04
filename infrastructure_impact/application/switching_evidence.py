"""Strict public contracts for the source-bound campus/branch switching study.

A binding records an explicit publisher statement or a reviewed literal alias;
validation never guesses applicability from an OS family or model-like string.
"""

import hashlib
import json
import re
from functools import lru_cache
from importlib.resources import files
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from ..source_policy import allowed
from .eligibility import timestamp

_SCHEMAS = ("switching-study-v1.json", "switching-evidence-v1.json", "switching-comparison-v1.json")
_UNSET = object()


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
    """
    if type(value) is not dict:
        raise TypeError("Expected a JSON object")
    return hashlib.sha256(_json(value)).hexdigest()


@lru_cache(maxsize=1)
def _validators():
    schemas = {
        name: json.loads(
            files("infrastructure_impact").joinpath("schemas", name).read_text(encoding="utf-8")
        )
        for name in _SCHEMAS
    }
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
            and not re.search(r"[\s\\\x00-\x20\x7f-\uffff]|%(?![0-9a-fA-F]{2})", value)
        )

    return {
        name: Draft202012Validator(schema, format_checker=checker, registry=registry)
        for name, schema in schemas.items()
    }


def _validate(value, schema):
    _json(value)
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
    _publication(report, publication, generated_at)
    study = definition()
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
    for coverage in report["coverage"]:
        _official(coverage["source_url"], coverage["vendor"])
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
    """Validate the envelope; Task 6 will extend the closed row/selection shapes."""
    _validate(report, "switching-comparison-v1.json")
    _publication(report, publication, generated_at)
    _validate_definition(report["definition"])
    for source in report["sources"]:
        # Comparison sources can contain any of the registered study vendors.
        if not any(allowed(source["source_url"], v) for v in ("cisco", "aruba", "arista")):
            _official(source["source_url"])
