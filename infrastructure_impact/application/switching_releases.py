"""Literal publisher release context and current-claim references, never upgrade advice."""

import copy
import csv
import hashlib
import io
import json
import re

from ..references import software_releases
from ..references.registry import SOURCES
from . import switching_comparison as comparison
from . import switching_evidence as contracts

METHOD = (
    "Release and fix evidence for the selected advisory CVE cohort; releases need not have been "
    "published in the selected advisory window. Publisher-reported fixed CVEs and affected-scope "
    "linked CVEs are separate observations. Vendor-fixed context follows selected study CVEs; "
    "affected-scope links additionally require the selected affected CVE cohort. "
    "Remediation availability dates retain advisory context "
    "and never supply a software release date; only publisher release-history dates do. "
    "Fixed-only statements do not establish affectedness, "
    "model applicability, deployed exposure or an upgrade event. Exact literal identities only; "
    "no version ordering, first-fix, fix-delay or security ranking inference. Retained sources are "
    "a bounded reviewed set, not a complete vendor release archive; coverage denominators are unknown."
)
FAMILIES = {"aruba": "aruba-aoscx", "arista": "arista-eos", "cisco": "cisco-iosxe"}
PRODUCTS = {
    "aruba": {"AOS-CX", "Aruba AOS-CX", "HPE Aruba Networking AOS-CX"},
    "arista": {
        "EOS",
        "Arista EOS",
        "EOS (source platform scope applies)",
        "EOS release (source platform scope applies)",
    },
}
SOURCE_IDS = tuple(s.id for s in SOURCES.values() if s.purpose == "release_history")
ERROR_CODES = {
    "access_denied",
    "edge_access_denied",
    "rate_limited",
    "http_error",
    "network_error",
    "source_missing",
    "redirect_target_missing",
    "access_verification_required",
    "unsupported_or_invalid_document",
    "collection_error",
}


def _literal(vendor, expression):
    """Parse only typed fixed expressions, never remediation details or affected bounds."""
    if vendor == "aruba":
        match = re.fullmatch(r"(\d+\.\d+\.\d{4})(?:_aos-cx)?", expression)
    elif vendor == "arista":
        match = re.fullmatch(r"(\d+\.\d+\.\d+(?:\.\d+)?[FM]?)", expression)
        if match is None:
            match = re.fullmatch(
                r"(\d+\.\d+\.\d+(?:\.\d+)?[FM]?) and later releases? in the (\d+\.\d+)\.x train",
                expression,
            )
            if match and not match[1].startswith(match[2] + "."):
                return None
    else:
        return None
    return match[1] if match else None


def _owned_remediation(claim, remediation):
    """Exact retained source/product ownership; unrelated statements cannot conflict."""
    if remediation["category"] not in {"vendor_fix", "no_fix_planned", "none_available"} or any(
        claim["source"][key] != remediation["source"][key]
        for key in ("source_url", "source_sha256", "retrieved_at")
    ):
        return False
    products = remediation["product_ids"]
    if products and (claim["product_id"] is None or claim["product_id"] not in products):
        return False
    binding = remediation.get("scope_binding")
    if binding is not None:
        return (
            binding["cve_id"] == claim["cve_id"]
            and binding["source"] == claim["source"]
            and binding.get("fixed_product", claim["product"]) in PRODUCTS[claim["vendor"]]
        )
    if products:
        return True
    # Reviewed HTML fixed claims own their exact fixed section, without a
    # publisher product ID. This never authorizes an affected-to-fixed join.
    return (
        claim["status"] == "fixed"
        and claim["product_id"] is None
        and remediation["source"] == claim["source"]
    )


def _availability_issue(claim, version, owned, observation_end):
    """Resolve only contradictory facts about this exact release and owned scope."""
    related = [
        rem
        for rem in owned
        if not rem["version_expressions"]
        or version
        in {_literal(claim["vendor"], expression) for expression in rem["version_expressions"]}
    ]
    if any(
        rem["availability"]
        in {"planned", "unavailable", "no_fix_planned", "partial_mitigation", "not_a_fix"}
        for rem in related
    ):
        return "fixed_availability_conflicting"
    if any(
        rem["availability_date"] is not None
        and comparison.day(rem["availability_date"]) > observation_end
        for rem in related
    ):
        return "future_fix_availability_excluded"
    return None


def _claim_candidates(claim, observation_end):
    """Single builder/writer policy over already validated current claim facts."""
    if (
        claim["scope"] != "cve_specific"
        or claim["cve_id"] is None
        or claim["status"] not in {"affected", "fixed"}
        or claim["family"] != FAMILIES[claim["vendor"]]
        or claim["product"] not in PRODUCTS.get(claim["vendor"], set())
    ):
        return [], []
    if (claim["publisher"]["status"] or "").casefold() == "draft":
        return [], [("draft_fixed_context_excluded", None)]
    owned = [r for r in claim["remediations"] if _owned_remediation(claim, r)]
    if claim["status"] == "fixed":
        candidates = [
            ("vendor_fixed", expression, "explicit_fixed_claim", claim["source"], None)
            for expression in claim["version_expressions"]
        ]
    else:
        candidates = [
            (
                "affected_scope_fix",
                expression,
                rem["scope_binding"]["basis"] if "scope_binding" in rem else "explicit_product_id",
                rem["source"],
                rem["availability_date"],
            )
            for rem in owned
            if comparison._fix(claim, rem)
            for expression in rem["version_expressions"]
        ]
    eligible, diagnostics = [], []
    for candidate in candidates:
        expression = candidate[1]
        version = _literal(claim["vendor"], expression)
        issue = (
            "fixed_expression_unresolved"
            if version is None
            else _availability_issue(claim, version, owned, observation_end)
        )
        if issue is not None:
            diagnostics.append((issue, expression))
        else:
            eligible.append(candidate)
    return eligible, diagnostics


def _frames(values):
    """Close private frames before use; source identity is owned by the registry."""
    if not isinstance(values, list) or len(values) > len(SOURCE_IDS):
        raise ValueError("Expected bounded registered release inputs")
    supplied = {}
    for value in values:
        identity = value.get("source_id")
        if identity not in SOURCE_IDS or identity in supplied:
            raise ValueError("Unknown or duplicate release input source")
        spec = SOURCES[identity]
        if value.get("source_url") != spec.url or value.get("purpose") != spec.purpose:
            raise ValueError("Release source route or purpose differs from registry")
        if type(value.get("configured")) is not bool or type(value.get("enabled")) is not bool:
            raise ValueError("Release source enablement must be explicit")
        retained = value.get("retained")
        clean = None
        if retained is not None:
            doc = software_releases.validate_document(retained["document"], source_id=identity)
            digest = hashlib.sha256(
                json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            adapter = {
                "aruba": "aruba_history.py",
                "cisco": "cisco_history.py",
                "arista": "arista_history.py",
            }[doc["vendor"]]
            if (
                retained["parser_fingerprint"] != doc["parser_fingerprint"]
                or doc["parser_fingerprint"] != software_releases.fingerprint(adapter)
                or retained["normalized_sha256"] != digest
            ):
                raise ValueError("Release parser or normalized document fingerprint differs")
            clean = {
                key: copy.deepcopy(retained[key])
                for key in (
                    "sha256",
                    "normalized_sha256",
                    "parser_fingerprint",
                    "revision_id",
                    "source_observed_at",
                    "parsed_at",
                )
            }
        attempt = value.get("latest_attempt")
        if attempt is not None:
            attempt = dict(
                checked_at=attempt.get("checked_at"),
                outcome=attempt.get("outcome")
                if attempt.get("outcome") in {"ok", "error", "partial", "not_applicable"}
                else "error",
                error_code=attempt.get("error_code")
                if attempt.get("error_code") in ERROR_CODES
                else None,
            )
        public = dict(
            source_id=identity,
            source_url=spec.url,
            configured=value["configured"],
            enabled=value["enabled"],
            checked_at=value.get("checked_at"),
            latest_attempt=attempt,
            retained=clean,
            issues=doc["issues"][:] if retained is not None else [],
            availability="excluded"
            if not value["configured"] or not value["enabled"]
            else "retained"
            if retained
            else "uncollected",
        )
        supplied[identity] = (public, retained["document"] if retained is not None else None)
    return [
        supplied.get(
            identity,
            (
                dict(
                    source_id=identity,
                    source_url=SOURCES[identity].url,
                    configured=False,
                    enabled=False,
                    checked_at=None,
                    latest_attempt=None,
                    retained=None,
                    availability="uncollected",
                    issues=[],
                ),
                None,
            ),
        )
        for identity in SOURCE_IDS
    ]


def _counts(node):
    for kind, name in (
        ("vendor_fixed", "vendor_reported_fixed"),
        ("affected_scope_fix", "affected_scope"),
    ):
        refs = [r for r in node["references"] if r["kind"] == kind]
        node[name + "_cve_ids"] = sorted({r["cve_id"] for r in refs})
        node[name + "_cve_count"] = len(node[name + "_cve_ids"]) if refs else None
    node["reported_release_dates"] = sorted(
        {
            h["reported_release_date"]
            for h in node["history"]
            if h["reported_release_date"] is not None
        }
    )


def _base(publication, generated_at, observation_end, *, available=True):
    return dict(
        schema_version=1,
        publication=copy.deepcopy(publication),
        generated_at=generated_at,
        definition_sha256=contracts.definition_sha256(contracts.definition()),
        observation_end=observation_end,
        availability="available" if available else "unavailable",
        releases=[],
        bundles=[],
        platform_support=[],
        sources=[],
        diagnostics=[],
        selection=None,
        coverage=dict(
            expected_releases=None, expected_advisories=None, completeness="not_established"
        ),
        method=METHOD,
    )


def build(evidence, release_input, *, publication, generated_at, observation_end):
    """Build from validated current evidence and five registered source frames."""
    contracts.validate_evidence(evidence, publication=publication, generated_at=generated_at)
    if comparison.day(observation_end) != observation_end or not contracts.definition()[
        "start_date"
    ] <= observation_end <= comparison.day(generated_at):
        raise ValueError("Release observation end outside generation")
    result = _base(publication, generated_at, observation_end)
    nodes = {}

    def node(vendor, family, version):
        key = (vendor, family, version)
        if key not in nodes:
            nodes[key] = dict(
                release_id=contracts.definition_sha256(
                    dict(vendor=vendor, family=family, version=version)
                ),
                vendor=vendor,
                family=family,
                version=version,
                history=[],
                references=[],
                issues=[],
            )
        return nodes[key]

    def diagnostic(claim, code, expression=None):
        value = dict(code=code, claim_id=claim["claim_id"], expression=expression, source_id=None)
        if value not in result["diagnostics"]:
            result["diagnostics"].append(value)

    for source, doc in _frames(release_input):
        result["sources"].append(source)
        if doc is None or source["availability"] != "retained":
            continue
        if doc["issues"]:
            # Original reviewed exclusions remain on the closed public source above.
            result["diagnostics"].append(
                dict(
                    code="release_source_issue",
                    claim_id=None,
                    expression=None,
                    source_id=source["source_id"],
                )
            )
        for row in doc["releases"]:
            n = node(doc["vendor"], doc["family"], row["version"])
            n["history"].append(
                dict(
                    source_id=source["source_id"],
                    product=doc["product"],
                    platforms=doc["platforms"][:],
                    **{
                        k: row[k]
                        for k in (
                            "reported_release_date",
                            "publisher_reports_posted",
                            "date_basis",
                            "statement",
                        )
                    },
                    source=dict(
                        source_url=source["source_url"],
                        source_sha256=source["retained"]["sha256"],
                        retrieved_at=source["retained"]["source_observed_at"],
                        source_locator=row["source_locator"],
                    ),
                )
            )
            if row["reported_release_date"] and row["reported_release_date"] > observation_end:
                n["issues"].append("future_release_date")
            if row["publisher_reports_posted"] is not True:
                n["issues"].append("posting_not_established")
        for row in doc["bundles"]:
            result["bundles"].append(
                dict(
                    vendor=doc["vendor"],
                    family=doc["family"],
                    source_id=source["source_id"],
                    publisher_id=row["publisher_id"],
                    title=row["title"],
                    initial_published_at=row["initial_published_at"],
                    member_publication_date=row["member_publication_date"],
                    member_advisory_ids=row["member_advisory_ids"][:],
                    source=dict(
                        source_url=source["source_url"],
                        source_sha256=source["retained"]["sha256"],
                        retrieved_at=source["retained"]["source_observed_at"],
                        source_locator=row["source_locator"],
                    ),
                )
            )
        for row in doc["platform_support"]:
            result["platform_support"].append(
                dict(
                    vendor=doc["vendor"],
                    family=doc["family"],
                    source_id=source["source_id"],
                    **{k: row[k] for k in ("sku", "model_literal", "minimum_version")},
                    source=dict(
                        source_url=source["source_url"],
                        source_sha256=source["retained"]["sha256"],
                        retrieved_at=source["retained"]["source_observed_at"],
                        source_locator=row["source_locator"],
                    ),
                )
            )

    for c in evidence["claims"]:
        if c["vendor"] == "cisco" and c["bundle"] is not None:
            b = c["bundle"]
            value = dict(
                vendor="cisco",
                family="cisco-iosxe",
                source_id=None,
                publisher_id=b["publisher_id"],
                title=b["title"],
                initial_published_at=b["published_at"],
                member_publication_date=None,
                member_advisory_ids=b["member_advisory_ids"][:],
                source=copy.deepcopy(b["source"]),
            )
            if value not in result["bundles"]:
                result["bundles"].append(value)
        candidates, diagnostics = _claim_candidates(c, observation_end)
        for code, expression in diagnostics:
            diagnostic(c, code, expression)
        for kind, expression, basis, source, availability_date in candidates:
            version = _literal(c["vendor"], expression)
            if version is None:
                diagnostic(c, "fixed_expression_unresolved", expression)
                continue
            ref = dict(
                kind=kind,
                claim_id=c["claim_id"],
                advisory_id=c["advisory_id"],
                cve_id=c["cve_id"],
                initial_published_at=c["initial_published_at"],
                scope_level=c["scope_level"],
                publisher_status=c["publisher"]["status"],
                expression=expression,
                link_basis=basis,
                availability_date=availability_date,
                source=copy.deepcopy(source),
                claim_source=copy.deepcopy(c["source"]),
            )
            n = node(c["vendor"], c["family"], version)
            if ref not in n["references"]:
                n["references"].append(ref)
    for n in nodes.values():
        _counts(n)
        if len(n["reported_release_dates"]) > 1:
            n["issues"].append("conflicting_release_dates")
        if not n["reported_release_dates"]:
            n["issues"].append("release_date_unknown")
        n["issues"] = sorted(set(n["issues"]))
        n["references"].sort(key=contracts._json)
    result["releases"] = [nodes[k] for k in sorted(nodes)]
    result["diagnostics"] = sorted(
        {contracts._json(d): d for d in result["diagnostics"]}.values(), key=contracts._json
    )
    validate_report(result, publication=publication, generated_at=generated_at)
    return result


def validate_report(report, *, publication=contracts._UNSET, generated_at=contracts._UNSET):
    contracts._validate(report, "switching-release-history-v1.json")
    contracts._publication(report, publication, generated_at)
    if (
        report["definition_sha256"] != contracts.definition_sha256(contracts.definition())
        or report["method"] != METHOD
    ):
        raise ValueError("Release history definition or method differs")
    seen = set()
    for n in report["releases"]:
        if (
            n["family"] != FAMILIES[n["vendor"]]
            or n["release_id"]
            != contracts.definition_sha256({k: n[k] for k in ("vendor", "family", "version")})
            or n["release_id"] in seen
        ):
            raise ValueError("Release identity differs")
        seen.add(n["release_id"])
        check = copy.deepcopy(n)
        _counts(check)
        if check != n:
            raise ValueError("Release counts or dates differ from references")
    source_map = {s["source_id"]: s for s in report["sources"]}
    if len(source_map) != len(report["sources"]):
        raise ValueError("Duplicate release source")
    for source in report["sources"]:
        if (
            source["source_id"] not in SOURCE_IDS
            or source["source_url"] != SOURCES[source["source_id"]].url
        ):
            raise ValueError("Unregistered release source")
        if source["availability"] == "retained" and not (
            source["configured"] and source["enabled"] and source["retained"]
        ):
            raise ValueError("Retained release source is not enabled")

    def context_source(context):
        source = source_map.get(context["source_id"])
        if (
            source is None
            or source["availability"] != "retained"
            or any(
                context["source"][key] != expected
                for key, expected in (
                    ("source_url", source["source_url"]),
                    ("source_sha256", source["retained"]["sha256"]),
                    ("retrieved_at", source["retained"]["source_observed_at"]),
                )
            )
        ):
            raise ValueError("Release context source differs from registered retained input")

    for node in report["releases"]:
        for context in node["history"]:
            context_source(context)
        for ref in node["references"]:
            contracts._official(ref["source"]["source_url"], node["vendor"])
            contracts._official(ref["claim_source"]["source_url"], node["vendor"])
            if (ref["publisher_status"] or "").casefold() == "draft":
                raise ValueError("Draft release reference cannot assert a fixed fact")
            if _literal(node["vendor"], ref["expression"]) != node["version"]:
                raise ValueError("Release reference literal differs from release identity")
    for context in report["platform_support"] + report["bundles"]:
        if context["source_id"] is None:
            if context["vendor"] != "cisco":
                raise ValueError("Only typed Cisco bundle context may omit a release source")
            contracts._official(context["source"]["source_url"], "cisco")
        else:
            context_source(context)
    if report["availability"] == "unavailable" and any(
        report[k] for k in ("releases", "bundles", "platform_support", "sources")
    ):
        raise ValueError("Unavailable history cannot contain observations")
    return report


def select_report(history, study_selection):
    """Select against summary/overview row cohorts without resolving any claim IDs.

    Missing history is an unavailable envelope bound to the supplied study generation.
    History rows remain family context. References require their own original advisory
    date and scope. Vendor fixed context uses selected effective CVEs; affected-scope
    links additionally require membership in that row's affected CVE cohort.
    """
    identity = {k: study_selection[k] for k in ("publication", "generated_at")}
    if study_selection["selection"]["definition_sha256"] != contracts.definition_sha256(
        contracts.definition()
    ):
        raise ValueError("Study selection definition differs")
    if history is None:
        result = _base(
            **identity, observation_end=study_selection["observation_end"], available=False
        )
    else:
        validate_report(history, **identity)
        if history["observation_end"] != study_selection["observation_end"]:
            raise ValueError("Release and study observation bounds differ")
        result = copy.deepcopy(history)
    selection = study_selection["selection"]
    vendors = selection["effective_vendors"]
    scope = selection["scope_level"]
    window = selection["requested_window"]
    if scope not in comparison.SCOPES or any(v not in comparison.VENDORS for v in vendors):
        raise ValueError("Invalid release study scope")
    start, end = comparison._bounds(contracts.definition(), result["observation_end"], window)
    cohorts = {r["vendor"]: set(r["affected_cve_ids"]) for r in study_selection["rows"]}
    effective = set(selection["effective_cve_ids"])

    def qualifies(ref, vendor):
        value = comparison.day(ref["initial_published_at"])
        return (
            ref["cve_id"]
            in (effective if ref["kind"] == "vendor_fixed" else cohorts.get(vendor, set()))
            and (scope == "os_family" or ref["scope_level"] == "model_qualified")
            and (
                value is None
                or contracts.definition()["start_date"] <= value <= result["observation_end"]
            )
            and comparison._in_window(value, start, end, window)
        )

    selected = []
    for n in result["releases"]:
        if n["vendor"] not in vendors:
            continue
        n["references"] = [r for r in n["references"] if qualifies(r, n["vendor"])]
        _counts(n)
        if n["history"] or n["references"]:
            selected.append(n)
    result["releases"] = selected
    result["bundles"] = [b for b in result["bundles"] if b["vendor"] in vendors]
    result["platform_support"] = [b for b in result["platform_support"] if b["vendor"] in vendors]
    result["selection"] = copy.deepcopy(selection)
    validate_report(result, **identity)
    return result


def csv_export(selected):
    """Explicit release context export; blank counts denote absence of fix evidence."""
    validate_report(selected)
    out = io.StringIO(newline="")
    fields = [
        "vendor",
        "family",
        "version",
        "reported_release_dates",
        "vendor_reported_fixed_cve_count",
        "affected_scope_cve_count",
        "vendor_reported_fixed_cve_ids",
        "affected_scope_cve_ids",
        "references",
    ]
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for release in selected["releases"]:
        writer.writerow(
            {
                k: json.dumps(release[k], ensure_ascii=False, separators=(",", ":"))
                if isinstance(release[k], list)
                else release[k]
                for k in fields
            }
        )
    return out.getvalue()


def validate_current_references(report, evidence):
    """Bind every published compact reference to the writer's validated current claims."""
    current = {c["claim_id"]: c for c in evidence["claims"]}
    candidate_cache = {}
    if report["selection"] is not None:
        raise ValueError("Published release history must retain its complete reference set")
    for node in report["releases"]:
        for ref in node["references"]:
            claim = current.get(ref["claim_id"])
            if (
                claim is None
                or claim["scope"] != "cve_specific"
                or claim["cve_id"] is None
                or (claim["publisher"]["status"] or "").casefold() == "draft"
                or claim["product"] not in PRODUCTS.get(claim["vendor"], set())
            ):
                raise ValueError("Release reference lacks eligible current claim scope")
            if (
                any(
                    ref[key] != claim[key]
                    for key in ("advisory_id", "cve_id", "initial_published_at", "scope_level")
                )
                or ref["claim_source"] != claim["source"]
                or ref["publisher_status"] != claim["publisher"]["status"]
            ):
                raise ValueError("Release reference differs from current claim")
            if (
                node["vendor"] != claim["vendor"]
                or node["family"] != claim["family"]
                or _literal(claim["vendor"], ref["expression"]) != node["version"]
            ):
                raise ValueError("Release reference literal or scope differs")
            if claim["claim_id"] not in candidate_cache:
                candidate_cache[claim["claim_id"]] = _claim_candidates(
                    claim, report["observation_end"]
                )[0]
            descriptor = (
                ref["kind"],
                ref["expression"],
                ref["link_basis"],
                ref["source"],
                ref["availability_date"],
            )
            if descriptor not in candidate_cache[claim["claim_id"]]:
                raise ValueError("Release reference is not eligible current fixed evidence")
