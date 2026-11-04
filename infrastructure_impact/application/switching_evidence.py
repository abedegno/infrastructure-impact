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
            and re.fullmatch(r"[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*", value) is not None
            and not re.search(r"%(?![0-9a-fA-F]{2})", value)
            and not any(
                re.search(r"[\[\]]", part) for part in (parsed.path, parsed.query, parsed.fragment)
            )
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
                    or not (locator == row or locator.startswith(row + "/"))
                ):
                    raise ValueError(
                        "Same-row remediation requires identical source, row and CVE scope"
                    )
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
    from ..adapters.cvss import public_metrics

    score_data = score_inputs(db, records)
    for claim in expanded:
        claim["vendor_severity"] = [
            rating
            for rating in score_data["vendor_severity"]
            if rating["vendor"] == claim["vendor"] and rating["advisory_id"] == claim["advisory_id"]
        ]
        if not claim["vendor_severity"]:
            claim["issues"].append("vendor_severity_unavailable")
        candidates = [
            score
            for entry in score_data["advisories"]
            if entry["vendor"] == claim["vendor"] and entry["advisory_id"] == claim["advisory_id"]
            for score in entry["claims"]
        ]
        candidates += score_data["fallback"]["claims"]
        # Selection and diagnostics share CVE/product/representation attribution.
        relevant = [
            score
            for score in candidates
            if score["cve_id"] == claim["cve_id"]
            and (not score["product_ids"] or claim["product_id"] in score["product_ids"])
            and (
                score["origin"] != "vendor_advisory"
                or score["source"]["source_url"] == claim["source"]["source_url"]
            )
        ]
        claim["scores"] = public_metrics(relevant) + [
            {**score, "preferred": False}
            for score in relevant
            if score["validation"] == "incomplete"
        ]
        for score in relevant:
            if score["validation"] == "invalid":
                claim["issues"].append("score_invalid")
            elif score["validation"] == "incomplete":
                claim["issues"].extend(score["issues"])
                if score["value"] is None:
                    claim["issues"].append("score_value_missing")
        if not relevant:
            claim["issues"].append("score_unavailable")
    result["claims"] = expanded
    result["issues"] = sorted(set(result["issues"]))
    return result


def project(inputs: dict, *, publication: dict | None, generated_at: str) -> dict:
    """Allowlist every nested public field, then validate the complete contract."""
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
    validate_evidence(result, publication=publication, generated_at=generated_at)
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
            dict(vendor=vendor, advisory_id=advisory_id, source_url=url, **parsed)
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
