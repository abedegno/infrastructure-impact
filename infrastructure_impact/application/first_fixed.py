"""Pure, retrospective first-fixed research; never normalized advisory claims.

The finite catalogue contains affected observations, not a release inventory.
Holding out the target advisory prevents its fixes from teaching its prediction.
"""

import json
from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ..settings import PACKAGE
from .software_versions import compare_releases, release_train, version_key

# Existing CSAF graph and advisory array bounds, applied before report fanout.
MAX_GRAPH = 20000
MAX_ROWS = 1000
RECEIPT = ("source_url", "sha256", "source_observed_at", "revision_id", "revision")
FACT = (
    "method",
    "evidence_state",
    "scope",
    "cve_ids",
    "family",
    "product",
    "product_ids",
    "train",
    "train_expression",
    "fixed_versions",
    "disposition",
    "source_locator",
)
FAMILIES = {("cisco", "Cisco IOS XE Software"): "cisco-iosxe"}


def _hash(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _bound(rows, limit=MAX_ROWS):
    if not isinstance(rows, list) or len(rows) > limit:
        raise ValueError("First-fixed input exceeds retained array bounds")
    return rows


def _identity(record):
    return {k: record.get(k) for k in ("vendor", "advisory_id")}


def _receipt(record):
    return {k: record[k] for k in RECEIPT if k in record}


def _observations(records):
    for record in _bound(records, MAX_GRAPH):
        vendor = record.get("vendor")
        for assessment in _bound(record.get("assessments", []), MAX_GRAPH):
            if assessment.get("status") != "affected":
                continue
            context = _bound(assessment.get("product_context", []))
            names = [assessment.get("product_family"), assessment.get("product")]
            names += [
                p[1]
                for p in context
                if isinstance(p, (list, tuple))
                and len(p) == 2
                and p[0] in {"product_family", "product_name"}
            ]
            families = {FAMILIES[(vendor, name)] for name in names if (vendor, name) in FAMILIES}
            if len(families) != 1:
                continue
            family = next(iter(families))
            literals = {
                p[1]
                for p in context
                if isinstance(p, (list, tuple))
                and len(p) == 2
                and p[0] in {"product_version", "service_pack"}
                and isinstance(p[1], str)
            }
            literals.update(
                v.get("expression")
                for v in _bound(assessment.get("versions", []))
                if isinstance(v, dict) and isinstance(v.get("expression"), str)
            )
            for literal in sorted(literals):
                train = release_train(vendor, literal)
                if train is not None:
                    yield record, family, train, literal, assessment.get("evidence_locator")


def build_catalogue(records: list[dict]) -> dict:
    """Aggregate literal provenance by advisory, avoiding CVE/product duplication."""
    entries = {}
    for record, family, train, literal, locator in _observations(records):
        key = (record["vendor"], family, train, literal)
        entry = entries.setdefault(
            key, dict(vendor=key[0], family=family, train=train, version=literal, provenance={})
        )
        proof = dict(_identity(record), **_receipt(record), source_locator=locator)
        # One real retained locator proves this advisory observed this literal;
        # repeat CVE/product references do not fan out the release catalogue.
        owner = _hash({k: v for k, v in proof.items() if k != "source_locator"})
        previous = entry["provenance"].get(owner)
        if previous is None or (locator or "") < (previous["source_locator"] or ""):
            entry["provenance"][owner] = proof
        if len(entries) > MAX_GRAPH or len(entry["provenance"]) > MAX_ROWS:
            raise ValueError("First-fixed catalogue exceeds retained graph bounds")
    versions = []
    for key in sorted(entries):
        entry = entries[key]
        entry["provenance"] = [entry["provenance"][p] for p in sorted(entry["provenance"])]
        versions.append(entry)
    return dict(
        fingerprint=_hash(versions),
        completeness="observed_only",
        versions=versions,
        basis="affected_version_context_only",
        release_inventory_verified=False,
    )


def _candidate(record, family, train, catalogue, generated_at):
    vendor, aid = record["vendor"], record["advisory_id"]
    observed = {v for r, f, t, v, _ in _observations([record]) if f == family and t == train}
    if not observed:
        return None
    maximum = max(observed, key=lambda v: version_key(vendor, v))
    if any(compare_releases(vendor, v, maximum) is None for v in observed):
        return None
    heldout = []
    for entry in catalogue["versions"]:
        if (entry["vendor"], entry["family"], entry["train"]) != (vendor, family, train):
            continue
        proof = [p for p in entry["provenance"] if (p["vendor"], p["advisory_id"]) != (vendor, aid)]
        if proof:
            heldout.append(dict(entry, provenance=proof))
    options = [e for e in heldout if compare_releases(vendor, maximum, e["version"]) == -1]
    if not options:
        return None
    chosen = min(options, key=lambda e: version_key(vendor, e["version"]))
    if any(compare_releases(vendor, chosen["version"], e["version"]) is None for e in options):
        return None
    # One actual observation proves existence; the full aggregated catalogue owns
    # all alternatives. Avoid repeating every advisory proof in every candidate.
    proof = min(chosen["provenance"], key=lambda p: (p.get("source_observed_at", ""), _hash(p)))
    times = [proof.get("source_observed_at", "")]
    return dict(
        method="inferred_next_release",
        evidence_state="inferred_candidate",
        family=family,
        train=train,
        fixed_versions=[chosen["version"]],
        maximum_affected=maximum,
        affected_inputs=sorted(observed),
        excluded_advisory=aid,
        catalogue_fingerprint=_hash(heldout),
        provenance=[deepcopy(proof)],
        evidence_timing="future_to_report"
        if any(t > generated_at for t in times)
        else "latest_known_retrospective",
    )


def _api_bindings(records, units, frames):
    """Bind API context through exact retained affected-query scope; compare any table."""
    from urllib.parse import parse_qs, urlsplit

    observations, facts, counts = [], [], Counter()
    for frame in _bound(frames, MAX_GRAPH):
        contexts = frame.get("advisory_context", [])
        if isinstance(contexts, dict):
            contexts = [contexts]
        source = {
            k: frame.get("source", {}).get(k)
            for k in ("url", "sha256", "retrieved_at", "evidence_id")
            if k in frame.get("source", {})
        }
        query = frame.get("query_release")
        url = urlsplit(source.get("url", ""))
        receipt_ok = (
            url.scheme == "https"
            and url.hostname == "apix.cisco.com"
            and url.path == "/security/advisories/v2/OSType/iosxe"
            and parse_qs(url.query) == {"version": [query]}
            and isinstance(source.get("sha256"), str)
            and len(source["sha256"]) == 64
            and bool(source.get("retrieved_at"))
        )
        if not contexts:
            counts["source_unavailable"] += 1
        for context in _bound(contexts):
            context = {
                k: deepcopy(context[k])
                for k in (
                    "advisory_id",
                    "source_locator",
                    "source_first_fixed",
                    "first_fixed_state",
                    "cve_refs",
                    "ownership_state",
                )
                if k in context
            }
            binding = "ownership_unresolved"
            matches, owned_records = [], []
            refs = set(context.get("cve_refs", []))
            for record in records:
                if record.get("vendor") != "cisco" or record.get("advisory_id") != context.get(
                    "advisory_id"
                ):
                    continue
                affected_cves = set()
                for assessment in record.get("assessments", []):
                    probe = dict(record, assessments=[assessment])
                    if any(
                        f == "cisco-iosxe" and v == query
                        for _, f, _, v, _ in _observations([probe])
                    ):
                        affected_cves.add(assessment.get("cve_id"))
                if not refs or refs != affected_cves:
                    continue
                owned_records.append(record)
                matches.extend(
                    u
                    for u in units
                    if u["identity"] == _identity(record)
                    and u["fact"].get("family") == "cisco-iosxe"
                    and u["fact"].get("train") == release_train("cisco", query)
                    and set(u["fact"].get("cve_ids") or []) == refs
                    and u["fact"].get("disposition") == "fixed"
                )
            if (
                receipt_ok
                and len(owned_records) == 1
                and len(matches) <= 1
                and context.get("first_fixed_state") == "present"
            ):
                record = owned_records[0]
                unit = matches[0] if matches else None
                train = release_train("cisco", query)
                values = context.get("source_first_fixed", [])
                if values and all(release_train("cisco", v) == train for v in values):
                    binding = "bound"
                    if unit and set(values) != set(unit["fact"]["fixed_versions"]):
                        binding = "conflicting"
                    fact = dict(
                        method="openvuln_api",
                        evidence_state="publisher_stated",
                        family="cisco-iosxe",
                        product=None,
                        product_ids=None,
                        scope="cve_specific" if len(refs) == 1 else "bulletin_shared",
                        cve_ids=sorted(refs),
                        train=train,
                        train_expression=train,
                        fixed_versions=values,
                        disposition="fixed",
                        source_locator=context["source_locator"],
                    )
                    facts.append(
                        dict(
                            identity=_identity(record),
                            fact=fact,
                            source=source,
                            table_source=unit["source"] if unit else {},
                            query_release=query,
                            binding_state=binding,
                        )
                    )
                    if binding == "conflicting":
                        unit.update(
                            stratum="conflict",
                            candidate=None,
                            outcome="abstain",
                            any_alternative_agreement=False,
                            exact_set_agreement=False,
                        )
            counts[binding] += 1
            observations.append(
                dict(
                    context=context,
                    source=source,
                    query_release=query,
                    parser_revision=frame.get("parser_revision"),
                    binding_state=binding,
                )
            )
    _bound(observations, MAX_GRAPH)
    _bound(facts, MAX_GRAPH)
    return observations, facts, dict(counts)


def build_report(
    records: list[dict], *, api_results: list[dict], publication: dict | None, generated_at: str
) -> dict:
    """Evaluate every supplied table row, retaining abstentions and conflicting strata."""
    catalogue = build_catalogue(records)
    units, candidates, coverage = [], [], {}
    diagnostics = {"catalogue_incomplete_observed_only"}
    if not publication or not publication.get("raw_source_manifest"):
        diagnostics.add("raw_source_manifest_not_supplied")
    for record in records:
        vendor = record["vendor"]
        cover = coverage.setdefault(vendor, Counter())
        cover["records"] += 1
        facts = _bound(record.get("first_fixed", []))
        cover["with_stated_table" if facts else "without_stated_table"] += 1
        cover["known_fixed_target_records"] += int(
            any(
                a.get("status") == "fixed"
                or any(r.get("category") == "vendor_fix" for r in a.get("remediations", []))
                for a in record.get("assessments", [])
            )
        )
        if not all(record.get(k) for k in ("source_url", "sha256", "source_observed_at")):
            diagnostics.add("missing_source_receipt")
        groups = {(f, t) for _, f, t, _, _ in _observations([record])}
        by_group = {}
        for family, train in sorted(groups):
            candidate = _candidate(record, family, train, catalogue, generated_at)
            by_group[(family, train)] = candidate
            cover["inferred_issued" if candidate else "inferred_abstain"] += 1
            candidates.append(
                dict(
                    identity=_identity(record),
                    family=family,
                    train=train,
                    candidate=candidate,
                    state="issued" if candidate else "abstain",
                )
            )
        signatures = defaultdict(set)
        for fact in facts:
            if fact.get("disposition") == "fixed":
                signatures[(fact.get("family"), fact.get("train"))].add(
                    tuple(sorted(fact.get("fixed_versions", [])))
                )
        seen = set()
        for fact in facts:
            # A shared bulletin row is one validation unit regardless of CVE count.
            signature = _hash({k: fact.get(k) for k in FACT if k != "cve_ids"})
            if signature in seen:
                continue
            seen.add(signature)
            family, train = fact.get("family"), fact.get("train")
            fixed = fact.get("fixed_versions", [])
            disposition = fact.get("disposition")
            if disposition == "migrate":
                stratum = "migration"
            elif disposition == "conflicting":
                stratum = "conflict"
            elif disposition != "fixed" or fact.get("scope") == "unresolved":
                stratum = "unknown"
            elif len(signatures[(family, train)]) > 1:
                stratum = "conflict"
            elif not fixed or any(release_train(vendor, v) != train for v in fixed):
                stratum = "unsupported"
            else:
                stratum = "eligible"
            candidate = by_group.get((family, train)) if stratum == "eligible" else None
            predicted = set(candidate["fixed_versions"]) if candidate else set()
            correct = bool(predicted.intersection(fixed))
            units.append(
                dict(
                    identity=_identity(record),
                    source=_receipt(record),
                    fact={k: deepcopy(fact[k]) for k in FACT if k in fact},
                    stratum=stratum,
                    candidate=deepcopy(candidate),
                    outcome=("correct" if correct else "mismatch") if candidate else "abstain",
                    any_alternative_agreement=correct,
                    exact_set_agreement=bool(candidate) and predicted == set(fixed),
                )
            )
            cover["stated_table_units"] += 1
    if len(units) > MAX_GRAPH or len(candidates) > MAX_GRAPH:
        raise ValueError("First-fixed report exceeds retained graph bounds")
    api_observations, api_facts, api = _api_bindings(records, units, api_results)
    if api_facts and "cisco" in coverage:
        coverage["cisco"]["openvuln_api_units"] = len(api_facts)
        coverage["cisco"]["openvuln_api_conflicts"] = sum(
            f["binding_state"] == "conflicting" for f in api_facts
        )
    counts = Counter(u["stratum"] for u in units)
    eligible = [u for u in units if u["stratum"] == "eligible"]
    validation = {
        k: counts[k] for k in ("eligible", "migration", "unknown", "conflict", "unsupported")
    }
    validation.update(
        {k: sum(u["outcome"] == k for u in eligible) for k in ("correct", "mismatch", "abstain")}
    )
    validation["issued"] = validation["correct"] + validation["mismatch"]
    validation["exact_set_correct"] = sum(u["exact_set_agreement"] for u in eligible)
    validation["any_alternative_rate"] = (
        validation["correct"] / validation["issued"] if validation["issued"] else None
    )
    validation["exact_set_rate"] = (
        validation["exact_set_correct"] / validation["issued"] if validation["issued"] else None
    )
    return dict(
        schema_version=1,
        generated_at=generated_at,
        catalogue=catalogue,
        units=units,
        candidates=candidates,
        validation=validation,
        coverage={k: dict(v) for k, v in sorted(coverage.items())},
        api_coverage=api,
        api_observations=api_observations,
        api_facts=api_facts,
        diagnostics=sorted(diagnostics),
        publication={
            **{
                k: deepcopy(publication[k])
                for k in ("id", "advisory_schema_version", "raw_source_manifest")
                if publication and k in publication
            },
            "raw_source_manifest_supplied": bool(
                publication and publication.get("raw_source_manifest")
            ),
        },
    )


def validate_report(report: dict) -> None:
    """Validate a closed local schema and independently recomputed denominators."""
    schema = json.loads((PACKAGE / "schemas" / "first-fixed-report-v1.json").read_text())
    advisory = json.loads((PACKAGE / "schemas" / "advisory-v2.json").read_text())
    registry = Registry().with_resource(advisory["$id"], Resource.from_contents(advisory))
    Draft202012Validator(schema, registry=registry).validate(report)
    for unit in report["units"]:
        candidate = unit["candidate"]
        predicted = set(candidate["fixed_versions"]) if candidate else set()
        truth = set(unit["fact"]["fixed_versions"])
        any_match = bool(predicted.intersection(truth))
        exact = bool(candidate) and predicted == truth
        outcome = ("correct" if any_match else "mismatch") if candidate else "abstain"
        if (
            unit["any_alternative_agreement"] != any_match
            or unit["exact_set_agreement"] != exact
            or unit["outcome"] != outcome
            or (candidate and unit["stratum"] != "eligible")
        ):
            raise ValueError("First-fixed accuracy disagrees with source facts")
    counts = report["validation"]
    eligible = [u for u in report["units"] if u["stratum"] == "eligible"]
    expected = {
        k: sum(u["outcome"] == k for u in eligible) for k in ("correct", "mismatch", "abstain")
    }
    expected.update(
        eligible=len(eligible),
        issued=expected["correct"] + expected["mismatch"],
        exact_set_correct=sum(u["exact_set_agreement"] for u in eligible),
    )
    for k in ("migration", "unknown", "conflict", "unsupported"):
        expected[k] = sum(u["stratum"] == k for u in report["units"])
    if any(counts[k] != v for k, v in expected.items()):
        raise ValueError("First-fixed validation denominators disagree with units")
    if report["catalogue"]["fingerprint"] != _hash(report["catalogue"]["versions"]):
        raise ValueError("First-fixed catalogue fingerprint mismatch")

    for field, numerator in (
        ("any_alternative_rate", "correct"),
        ("exact_set_rate", "exact_set_correct"),
    ):
        rate = counts[numerator] / counts["issued"] if counts["issued"] else None
        if counts[field] != rate:
            raise ValueError("First-fixed rate disagrees with denominator")
