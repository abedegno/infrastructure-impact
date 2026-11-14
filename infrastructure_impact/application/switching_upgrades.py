"""Retrospective immediate-remediation scenarios over owned affected claims.

This is a conditional greedy walk, not a universal minimum or observed operations.
"""

import copy
import json
import re
from collections import defaultdict

from jsonschema import Draft202012Validator, ValidationError

from ..settings import PACKAGE
from . import first_fixed, kev
from . import switching_comparison as comparison
from . import switching_evidence as contracts
from . import switching_releases as releases
from .eligibility import timestamp
from .software_versions import compare_releases, release_train

SCENARIOS = ("publisher_first_fixed", "known_fixed_target", "inferred_inclusive")
POLICIES = ("all_affected", "high_risk")
TRAINS = {
    "cisco": ("17.9", "17.12", "17.15"),
    "aruba": ("10.13", "10.14", "10.16"),
    "arista": ("4.32", "4.33", "4.34"),
}
METHOD = (
    "Immediate-remediation scenario: earliest comparable alternative per affected scope, "
    "then maximum same-UTC-day requirement; never a universal minimum or observed customer "
    "operations. First target counts one under an assumed below-first-target baseline; actual "
    "baseline unknown. State carries across years and selected windows. Latest known targets "
    "are retrospective and do not establish availability on initial publication day. "
    "High-risk eligibility is any preferred CVSS >=7 at the vendor tier, else official CVE/NVD "
    "only when preferred vendor metrics are absent, OR retrospective listed KEV. Provider/version "
    "facets remain separate; vendor SIR is not CVSS. Unknown eligibility remains unresolved. "
    "Supported steps in partial walks are not reliable upper or lower bounds. "
    "Numeric migration groups apply only to their explicit X.Y-and-earlier range. "
    "Conditional affectedness is not deployed exposure; coverage completeness is unknown."
)
_SCHEMA = json.loads((PACKAGE / "schemas/switching-upgrades-v1.json").read_text())
_VALIDATOR = Draft202012Validator(_SCHEMA)


def _receipt_matches(source, claim):
    return all(
        source.get(a) == claim["source"].get(b) and source.get(a) is not None
        for a, b in (
            ("source_url", "source_url"),
            ("sha256", "source_sha256"),
            ("source_observed_at", "retrieved_at"),
        )
    )


def _scope_matches(fact, claim):
    return (
        fact.get("scope") in ("cve_specific", "bulletin_shared")
        and claim["cve_id"] in (fact.get("cve_ids") or [])
        and (fact.get("product_ids") is None or claim["product_id"] in fact["product_ids"])
        and (fact.get("product") is None or fact["product"] == claim["product"])
    )


def _risk(claim, membership, evaluated_at=None):
    scores = [
        s
        for s in claim["scores"]
        if s.get("scope") == "cve_specific"
        and s.get("cve_id") == claim["cve_id"]
        and s.get("validation") == "valid"
        and s.get("system", "").upper() == "CVSS"
        and (not s.get("product_ids") or claim["product_id"] in s["product_ids"])
    ]
    vendor = [
        s for s in scores if s.get("origin") == "vendor_advisory" and s.get("preferred") is True
    ]
    tier = vendor if vendor else [s for s in scores if s.get("origin") in ("cve_record", "nvd")]
    preferred = [s for s in tier if s.get("preferred") is True]
    trusted = (
        preferred
        if evaluated_at is None
        else [
            s
            for s in preferred
            if timestamp((s.get("source") or {}).get("retrieved_at")) is not None
            and timestamp(s["source"]["retrieved_at"]) <= timestamp(evaluated_at)
        ]
    )
    bands = {comparison.severity_band(s.get("version"), s.get("value")) for s in trusted}
    high = bool(bands & {"High", "Critical"})
    state = (
        True
        if high or membership == "listed"
        else (False if bands and "Unknown" not in bands and membership == "not_listed" else None)
    )
    facets = [
        {k: copy.deepcopy(s.get(k)) for k in ("origin", "provider", "version", "value", "source")}
        for s in preferred
    ]
    return state, facets


def _minimum(vendor, alternatives, train):
    if not alternatives or any(release_train(vendor, v) != train for v in alternatives):
        return None
    result = alternatives[0]
    for value in alternatives[1:]:
        order = compare_releases(vendor, value, result)
        if order is None:
            return None
        if order < 0:
            result = value
    return result


def _scoped_inference(claims, ff):
    """Group current source/CVE/train leaves before invoking the owned holdout reducer."""
    owners = defaultdict(list)
    for claim in claims:
        if claim["vendor"] != "cisco":
            continue
        source = claim["source"]
        key = (
            claim["advisory_id"],
            claim["cve_id"],
            claim["family"],
            source["source_url"],
            source["source_sha256"],
            source["retrieved_at"],
        )
        owners[key].append(claim)
    groups = []
    for identity, owner_claims in owners.items():
        bindings = [(claim, *_affected_trains(claim)) for claim in owner_claims]
        trains = set().union(*(trains for _, trains, _ in bindings))
        for train in sorted(trains):
            # Unknown train scope can overlap any train in this owned source/CVE.
            group = [
                claim
                for claim, trains, binding in bindings
                if train in trains or not trains or binding["partial"]
            ]
            groups.append((identity, train, group))
    result = defaultdict(list)
    for (aid, cve, family, url, sha, retrieved), train, group in groups:
        versions = _complete_affected_versions(group, train)
        if versions is None:
            for claim in group:
                result[claim["claim_id"]].append(dict(train=train, candidate=None))
            continue
        scope = dict(scope="cve_specific", cve_ids=[cve], product=None, product_ids=None)
        record = dict(
            vendor="cisco",
            advisory_id=aid,
            source_url=url,
            sha256=sha,
            source_observed_at=retrieved,
            assessments=[
                dict(
                    status="affected",
                    cve_id=cve,
                    product_family="Cisco IOS XE Software",
                    product_context=[],
                    evidence_locator=group[0]["source"]["source_locator"],
                    versions=[dict(expression=v) for v in versions],
                )
            ],
        )
        candidate = first_fixed._candidate(
            record, family, train, ff["catalogue"], ff["generated_at"], scope
        )
        if candidate:
            value = dict(
                identity=dict(vendor="cisco", advisory_id=aid),
                family=family,
                train=train,
                input_scope=scope,
                candidate=candidate,
                affected_claim_ids=sorted(c["claim_id"] for c in group),
            )
            value["group"] = dict(
                maximum_affected=candidate["maximum_affected"],
                affected_inputs=candidate["affected_inputs"],
                affected_claim_ids=value["affected_claim_ids"],
                catalogue_fingerprint=candidate["catalogue_fingerprint"],
            )
            value["group"]["group_id"] = contracts.definition_sha256(value["group"])
            for claim in group:
                result[claim["claim_id"]].append(value)
    return result


def _complete_affected_versions(group, train):
    """Withhold inference unless every owned expression permits a literal maximum.

    Train-only annotations accompanying a literal leaf add no affected bound.
    Ranges and unsupported leaves are retained as blockers, never silently dropped.
    """
    versions = set()
    for claim in group:
        trains, binding = _affected_trains(claim)
        if not trains or binding["partial"]:
            return None
        literals = {v for v in claim["version_expressions"] if release_train("cisco", v) == train}
        for expression in claim["version_expressions"]:
            literal_train = release_train("cisco", expression)
            if literal_train is not None:
                if literal_train == train:
                    versions.add(expression)
                continue
            # A standalone train expression is not a finite affected maximum.
            if re.fullmatch(r"[0-9]+\.[0-9]+", expression) and expression == train and literals:
                continue
            return None
    return sorted(versions) if versions else None


def _affected_trains(claim):
    """Interpret only closed typed literal/range forms, never free-form prose."""
    vendor, expressions = claim["vendor"], claim["version_expressions"]
    trains, bases = set(), set()
    unresolved = False
    unsupported = False
    for expression in expressions:
        train = release_train(vendor, expression)
        if train:
            trains.add(train)
            bases.add("exact_literals")
            continue
        train_only = re.fullmatch(r"([0-9]+\.[0-9]+)", expression)
        if train_only:
            trains.add(train_only[1])
            bases.add("explicit_train")
            continue
        excluded = re.fullmatch(r"([0-9]+\.[0-9]+)(?:\.[0-9]+)?[A-Za-z]+", expression)
        if vendor == "cisco" and excluded:
            trains.add(excluded[1])
            bases.add("unsupported_literal_train")
            unsupported = True
            continue
        bounds = re.fullmatch(
            r"vers:semver/>=?([0-9]+\.[0-9]+\.[0-9]+)\|<=?([0-9]+\.[0-9]+\.[0-9]+)", expression
        )
        if bounds:
            left, right = (release_train(vendor, value) for value in bounds.groups())
            if left is not None and left == right:
                trains.add(left)
                bases.add("same_train_bounded_range")
            else:
                unresolved = True
            continue
        wrapped = re.fullmatch(
            r"EOS version ?([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?[FM]?)", expression
        )
        if vendor == "arista" and wrapped:
            trains.add(release_train(vendor, wrapped[1]))
            bases.add("typed_eos_version")
            continue
        old = re.fullmatch(
            r"([0-9]+\.[0-9]+)\.xxxx - versions prior to ?([0-9]+\.[0-9]+\.[0-9]+)", expression
        )
        if vendor == "aruba" and old and release_train(vendor, old[2]) == old[1]:
            trains.add(old[1])
            bases.add("explicit_train_range")
            continue
        unresolved = True
    basis = next(iter(bases)) if len(bases) == 1 else "mixed_typed_forms" if bases else "unresolved"
    return trains, dict(
        basis=basis,
        expressions=copy.deepcopy(expressions),
        partial=unresolved,
        unsupported=unsupported,
    )


def _migration_applies(unit, train):
    """Only the publisher's closed numeric 'X.Y and earlier' group is ordered."""
    fact = unit["fact"]
    match = re.fullmatch(r"([0-9]+)\.([0-9]+) and earlier", fact.get("train_expression") or "")
    if (
        fact.get("disposition") != "migrate"
        or not match
        or not re.fullmatch(r"[0-9]+\.[0-9]+", train)
    ):
        return False
    return tuple(map(int, train.split("."))) <= tuple(map(int, match.groups()))


def _constraints(claim, ff, membership, end, inferred):
    vendor = claim["vendor"]
    owned = [
        u
        for u in ff["units"]
        if u["identity"] == {"vendor": vendor, "advisory_id": claim["advisory_id"]}
        and _receipt_matches(u["source"], claim)
        and u["fact"].get("family") == claim["family"]
        and _scope_matches(u["fact"], claim)
    ]
    api_units = []
    for item in ff["api_facts"]:
        if (
            vendor != "cisco"
            or item["identity"] != {"vendor": vendor, "advisory_id": claim["advisory_id"]}
            or not _scope_matches(item["fact"], claim)
        ):
            continue
        # API-only facts have no retained advisory receipt. Re-prove the exact
        # affected query in the current claim; family/CVE matching alone is insufficient.
        if not (
            _receipt_matches(item["table_source"], claim)
            or item["query_release"] in claim["version_expressions"]
        ):
            continue
        src = item["source"]
        api_units.append(
            dict(
                identity=item["identity"],
                fact=item["fact"],
                source=dict(
                    source_url=src["url"],
                    sha256=src["sha256"],
                    source_observed_at=src["retrieved_at"],
                ),
                stratum="eligible" if item["binding_state"] == "bound" else "conflict",
                api=True,
            )
        )
    owned.extend(api_units)
    candidates, issues = releases._claim_candidates(claim, end)
    known = defaultdict(list)
    for _, expression, _, source, _ in candidates:
        literal = releases._literal(vendor, expression)
        known[release_train(vendor, literal)].append((literal, source))
    literal_trains, train_binding = _affected_trains(claim)
    trains = literal_trains or (
        set(known) | {u["fact"].get("train") for u in owned} | {c["train"] for c in inferred}
    ) - {None}
    trains = trains or set(TRAINS[vendor])
    for train in sorted(t for t in trains if t):
        units = [u for u in owned if u["fact"].get("train") == train]
        if not units:
            units = [
                u for u in owned if u["fact"].get("train") is None and _migration_applies(u, train)
            ]
        for scenario in SCENARIOS:
            alternatives, proof, reasons = [], [], []
            derivation = None
            # Stated same-source/train ownership does not depend on ordering
            # the affected leaf. Only inferred/unknown paths need that ordering.
            stated_target = bool(units) and all(
                u["stratum"] == "eligible" and u["fact"].get("train") == train for u in units
            )
            if train_binding["unsupported"] and not stated_target:
                reasons.append("unsupported_affected_release_variant")
            if train_binding["partial"] and any(
                e.startswith("vers:") for e in train_binding["expressions"]
            ):
                reasons.append("affected_train_scope_unresolved")
            conflict = any(u["stratum"] != "eligible" for u in units)
            if conflict:
                reasons.extend(
                    "first_fixed_" + u["stratum"] for u in units if u["stratum"] != "eligible"
                )
            else:
                for u in units:
                    alternatives.extend(u["fact"]["fixed_versions"])
                    src = u["source"]
                    proof.append(
                        dict(
                            method=u["fact"]["method"],
                            kind="publisher_api_first_fixed"
                            if u.get("api")
                            else "publisher_first_fixed",
                            source=dict(
                                source_url=src["source_url"],
                                source_sha256=src["sha256"],
                                retrieved_at=src["source_observed_at"],
                                source_locator=u["fact"]["source_locator"],
                            ),
                            locator=u["fact"]["source_locator"],
                            fingerprint=contracts.definition_sha256(u),
                        )
                    )
            if not units and scenario != "publisher_first_fixed":
                alternatives.extend(v for v, _ in known.get(train, []))
                proof.extend(
                    dict(
                        method="affected_scope_link",
                        kind="known_fixed_target",
                        source=copy.deepcopy(s),
                        locator=s["source_locator"],
                        fingerprint=contracts.definition_sha256(s),
                    )
                    for _, s in known.get(train, [])
                )
            if not alternatives and not conflict and scenario == "inferred_inclusive":
                for candidate in inferred:
                    c = candidate["candidate"]
                    if candidate["train"] == train and c is None:
                        reasons.append("inference_group_incomplete")
                        continue
                    if (
                        candidate["train"] == train
                        and c["evidence_timing"] == "latest_known_retrospective"
                    ):
                        alternatives.extend(c["fixed_versions"])
                        derivation = dict(
                            maximum_affected=c["maximum_affected"],
                            group_id=candidate["group"]["group_id"],
                        )
                        for heldout in c["provenance"]:
                            proof.append(
                                dict(
                                    method="inferred_next_release",
                                    kind="inferred_candidate",
                                    source=dict(
                                        source_url=heldout["source_url"],
                                        source_sha256=heldout["sha256"],
                                        retrieved_at=heldout["source_observed_at"],
                                        source_locator=heldout.get("source_locator"),
                                    ),
                                    locator=heldout.get("source_locator")
                                    or "first_fixed.candidates",
                                    fingerprint=contracts.definition_sha256(candidate),
                                )
                            )
            alternatives = sorted(set(alternatives))
            target = _minimum(vendor, alternatives, train)
            if target is None:
                reasons.append(
                    "unsupported_or_incomparable_target" if alternatives else "missing_owned_target"
                )
                reasons.extend(code for code, _ in issues)
            receipts = [claim["source"], *(p["source"] for p in proof)]
            for receipt in receipts:
                observed = timestamp(receipt.get("retrieved_at"))
                if observed is None:
                    reasons.append("unknown_source_receipt_time")
                elif observed > timestamp(ff["generated_at"]):
                    reasons.append("future_source_receipt")
            date = comparison.day(claim["initial_published_at"])
            if date is None:
                reasons.append("unknown_initial_publication")
            if date is not None and date > end:
                reasons.append("future_initial_publication")
            yield dict(
                claim_id=claim["claim_id"],
                claim_sha256=contracts.definition_sha256(claim),
                vendor=vendor,
                family=claim["family"],
                train=train,
                advisory_id=claim["advisory_id"],
                cve_id=claim["cve_id"],
                source=copy.deepcopy(claim["source"]),
                scope_level=claim["scope_level"],
                date=date,
                scenario=scenario,
                alternatives=alternatives,
                target=target,
                issues=sorted(set(reasons)),
                proof=proof,
                train_binding=copy.deepcopy(train_binding),
                inference=derivation,
                high_risk=_risk(claim, membership, ff["generated_at"])[0],
                severity_facets=_risk(claim, membership, ff["generated_at"])[1],
                kev_membership=membership,
            )


def _rows(constraints, *, end, vendors, window="all"):
    start, stop = comparison._bounds(contracts.definition(), end, window)
    first_year, last_year = int(contracts.definition()["start_date"][:4]), int(end[:4])
    result = []
    for vendor in vendors:
        trains = sorted(
            set(TRAINS[vendor]) | {c["train"] for c in constraints if c["vendor"] == vendor}
        )
        for train in trains:
            for scenario in SCENARIOS:
                source = [
                    c
                    for c in constraints
                    if (c["vendor"], c["train"], c["scenario"]) == (vendor, train, scenario)
                ]
                for policy in POLICIES:
                    state = None
                    tainted = False
                    for year in range(first_year, last_year + 1):
                        year_start = state
                        relevant = [
                            c for c in source if c["date"] is None or int(c["date"][:4]) == year
                        ]
                        relevant = [
                            c
                            for c in relevant
                            if (policy == "all_affected" or c["high_risk"] is not False)
                            and (
                                c["date"] is None
                                or (window != "undated" and (stop is None or c["date"] <= stop))
                            )
                        ]
                        unresolved, events, days = [], [], defaultdict(list)
                        for c in relevant:
                            reasons = list(c["issues"])
                            if policy == "high_risk" and c["high_risk"] is None:
                                reasons.append("unknown_high_risk_eligibility")
                            if reasons:
                                unresolved.append(
                                    dict(claim_id=c["claim_id"], issues=sorted(set(reasons)))
                                )
                                tainted = True
                            elif c["date"] <= end:
                                days[c["date"]].append(c)
                        start_state = year_start
                        for date, group in sorted(days.items()):
                            targets = [c["target"] for c in group]
                            target = targets[0]
                            comparables = True
                            for value in targets[1:]:
                                relation = compare_releases(vendor, value, target)
                                if relation is None:
                                    comparables = False
                                    break
                                if relation > 0:
                                    target = value
                            order = 1 if state is None else compare_releases(vendor, target, state)
                            if not comparables or order is None:
                                unresolved.extend(
                                    dict(claim_id=c["claim_id"], issues=["incomparable_walk_state"])
                                    for c in group
                                )
                                tainted = True
                                continue
                            if order > 0:
                                previous = state
                                state = target
                                if comparison._in_window(date, start, stop, window):
                                    events.append(
                                        dict(
                                            date=date,
                                            previous=previous,
                                            target=target,
                                            claim_ids=sorted({c["claim_id"] for c in group}),
                                        )
                                    )
                            if start is not None and date < start:
                                start_state = state
                        selected = [
                            c
                            for c in relevant
                            if comparison._in_window(c["date"], start, stop, window)
                        ]
                        if (
                            window != "undated"
                            and start is not None
                            and (year < int(start[:4]) or year > int(stop[:4]))
                        ):
                            continue
                        selected_ids = {c["claim_id"] for c in selected}
                        unresolved = [u for u in unresolved if u["claim_id"] in selected_ids]
                        count = len(events) if selected and not unresolved and not tainted else None
                        result.append(
                            dict(
                                vendor=vendor,
                                family=releases.FAMILIES[vendor],
                                train=train,
                                year=year,
                                scenario=scenario,
                                policy=policy,
                                event_count=count,
                                supported_event_count=len(events),
                                events=events,
                                unresolved=unresolved,
                                affected_claim_ids=sorted(selected_ids),
                                start_version=start_state,
                                end_version=state,
                                coverage="partial"
                                if tainted
                                else ("observed_constraints_only" if selected else "unknown"),
                                baseline="assumed_below_first_target_actual_unknown",
                                partial_year=year == last_year,
                            )
                        )
    return result


def eligible_claims_for(evidence):
    """Shared exact ownership membership for native and compiled requirements."""
    return [
        claim
        for claim in evidence["claims"]
        if claim["status"] == "affected"
        and claim["scope"] == "cve_specific"
        and claim["family"] == releases.FAMILIES.get(claim["vendor"])
        and (claim["publisher"]["status"] or "").casefold() != "draft"
    ]


def prepare_report(
    evidence, first_fixed_report, release_history, kev_selection, *, publication, generated_at
):
    """Validate complete owned groups, then yield requirements without a global matrix."""
    contracts.validate_evidence(evidence, publication=publication, generated_at=generated_at)
    first_fixed.validate_report(first_fixed_report)
    if first_fixed_report["generated_at"] != generated_at or first_fixed_report["publication"].get(
        "id"
    ) != (publication or {}).get("id"):
        raise ValueError("First-fixed generation differs")
    kev.validate_report(kev_selection)
    if kev_selection["publication"] != publication or kev_selection["generated_at"] != generated_at:
        raise ValueError("KEV generation differs")
    if release_history is not None:
        releases.validate_report(
            release_history, publication=publication, generated_at=generated_at
        )
        releases.validate_current_references(release_history, evidence)
    end = comparison.day(generated_at)
    selected_kev = kev.select_report(
        kev_selection,
        sorted({c["cve_id"] for c in evidence["claims"] if c["cve_id"]}),
        evaluated_at=generated_at,
    )
    eligible_claims = eligible_claims_for(evidence)
    inference = _scoped_inference(eligible_claims, first_fixed_report)
    # Index source facts once, without copying the validated catalogue.
    facts = defaultdict(lambda: dict(units=[], api_facts=[], generated_at=generated_at))
    for kind in ("units", "api_facts"):
        for fact in first_fixed_report[kind]:
            identity = fact["identity"]
            facts[identity["vendor"], identity["advisory_id"]][kind].append(fact)

    def constraints():
        for claim in eligible_claims:
            yield from _constraints(
                claim,
                facts[claim["vendor"], claim["advisory_id"]],
                selected_kev["selection"]["membership"].get(claim["cve_id"], "unknown"),
                end,
                inference.get(claim["claim_id"], []),
            )

    source_groups = []
    claim_index = defaultdict(list)
    for claim in eligible_claims:
        claim_index[claim["vendor"], claim["advisory_id"]].append(claim)
    for unit in first_fixed_report["units"]:
        fact, identity = unit["fact"], unit["identity"]
        if fact.get("train") is not None or not any(
            _receipt_matches(unit["source"], claim) and _scope_matches(fact, claim)
            for claim in claim_index[identity["vendor"], identity["advisory_id"]]
        ):
            continue
        receipt = unit["source"]
        group = dict(
            vendor=identity["vendor"],
            advisory_id=identity["advisory_id"],
            cve_ids=copy.deepcopy(fact.get("cve_ids") or []),
            product=fact.get("product"),
            product_ids=copy.deepcopy(fact.get("product_ids")),
            train_expression=fact.get("train_expression"),
            disposition=fact["disposition"],
            method=fact["method"],
            source=dict(
                source_url=receipt["source_url"],
                source_sha256=receipt["sha256"],
                retrieved_at=receipt["source_observed_at"],
                source_locator=fact["source_locator"],
            ),
        )
        group["group_id"] = contracts.definition_sha256(group)
        source_groups.append(group)
    report = dict(
        schema_version=1,
        publication=copy.deepcopy(publication),
        generated_at=generated_at,
        observation_end=end,
        definition_sha256=contracts.definition_sha256(contracts.definition()),
        evidence_sha256=contracts.definition_sha256(evidence),
        selection=None,
        method=METHOD,
        severity_provider="preferred_vendor_else_official_cve_nvd_any_high_or_critical",
        kev_basis="retrospective_membership_at_generation",
        kev_context={
            key: copy.deepcopy(selected_kev[key])
            for key in ("evaluated_at", "source", "catalogue", "policy")
        },
        source_groups=source_groups,
        inference_groups=list(
            {
                value["group"]["group_id"]: value["group"]
                for values in inference.values()
                for value in values
                if value.get("group")
            }.values()
        ),
    )
    return report, constraints()


def build_report(
    evidence, first_fixed_report, release_history, kev_selection, *, publication, generated_at
):
    report, requirements = prepare_report(
        evidence,
        first_fixed_report,
        release_history,
        kev_selection,
        publication=publication,
        generated_at=generated_at,
    )
    report["constraints"] = list(requirements)
    used = {c["inference"]["group_id"] for c in report["constraints"] if c["inference"]}
    report["inference_groups"] = [g for g in report["inference_groups"] if g["group_id"] in used]
    report["rows"] = _rows(
        report["constraints"], end=report["observation_end"], vendors=list(TRAINS)
    )
    validate_report(report)
    return report


def validate_report(report):
    size = 0
    for chunk in json.JSONEncoder(ensure_ascii=False, separators=(",", ":")).iterencode(report):
        size += len(chunk.encode())
        if size > 128_000_000:
            raise ValueError("Upgrade report exceeds existing selected export byte bound")
    try:
        _VALIDATOR.validate(report)
    except ValidationError as error:
        raise ValueError(
            "Invalid upgrade report at " + "/".join(map(str, error.absolute_schema_path))
        ) from None
    if report["definition_sha256"] != contracts.definition_sha256(contracts.definition()):
        raise ValueError("Upgrade definition differs")
    if report["observation_end"] != comparison.day(report["generated_at"]):
        raise ValueError("Upgrade observation end differs from generation")
    groups = {g["group_id"]: g for g in report["inference_groups"]}
    if len(groups) != len(report["inference_groups"]):
        raise ValueError("Duplicate inference group")
    for identity, group in groups.items():
        if identity != contracts.definition_sha256(
            {k: v for k, v in group.items() if k != "group_id"}
        ):
            raise ValueError("Inference group fingerprint differs")
    if report["kev_context"]["evaluated_at"] != report["generated_at"]:
        raise ValueError("KEV evaluation differs from upgrade generation")
    seen = set()
    for c in report["constraints"]:
        if (
            report["kev_context"]["source"]["availability"] != "available"
            and c["kev_membership"] != "unknown"
        ):
            raise ValueError("Unavailable KEV cannot establish membership")
        if c["inference"] is not None:
            group = groups.get(c["inference"]["group_id"])
            if (
                not group
                or c["claim_id"] not in group["affected_claim_ids"]
                or c["inference"]["maximum_affected"] != group["maximum_affected"]
            ):
                raise ValueError("Inference group ownership differs")
        key = (c["claim_id"], c["train"], c["scenario"])
        if key in seen or c["family"] != releases.FAMILIES[c["vendor"]]:
            raise ValueError("Duplicate or mismatched constraint identity")
        seen.add(key)
        if c["target"] is None and not c["issues"]:
            raise ValueError("Missing target must remain unresolved")
        if c["date"] is None and "unknown_initial_publication" not in c["issues"]:
            raise ValueError("Unknown publication must remain unresolved")
        if c["target"] != _minimum(c["vendor"], c["alternatives"], c["train"]):
            raise ValueError("Constraint target differs from alternatives")
        if c["target"] is not None and not c["proof"]:
            raise ValueError("Target lacks provenance")
        if c["vendor"] != "cisco" and any(p["kind"] == "inferred_candidate" for p in c["proof"]):
            raise ValueError("Peer inference is unsupported")
    selection = report["selection"]
    expected = _rows(
        report["constraints"],
        end=report["observation_end"],
        vendors=selection["effective_vendors"] if selection else list(TRAINS),
        window=selection["requested_window"] if selection else "all",
    )
    if report["rows"] != expected:
        raise ValueError("Upgrade rows differ from owned constraints")


def select_report(report, study_selection):
    validate_report(report)
    if report["selection"] is not None:
        raise ValueError("Select from the complete upgrade report")
    contracts.validate_comparison(
        study_selection, publication=report["publication"], generated_at=report["generated_at"]
    )
    if not isinstance(study_selection["inputs"], dict):
        raise ValueError("Full study inputs required for exact claim selection")
    ev = study_selection["inputs"]["evidence"]
    if (
        contracts.definition_sha256(ev) != report["evidence_sha256"]
        or study_selection["observation_end"] != report["observation_end"]
    ):
        raise ValueError("Study evidence or observation bounds differ")
    selection = study_selection["selection"]
    if selection["definition_sha256"] != report["definition_sha256"]:
        raise ValueError("Study definition differs")
    # Resolve all-history membership first. Windowing follows the full chronological walk.
    full = comparison.select_report(
        study_selection,
        vendor=selection["requested_vendor"],
        scope_level=selection["scope_level"],
        cve_ids=selection["requested_cve_ids"],
        window="all",
        evaluated_at=study_selection["evaluated_at"],
    )
    ids = {i for r in full["rows"] for i in r["claim_ids"]}
    claims = {c["claim_id"]: c for c in ev["claims"]}
    out = copy.deepcopy(report)
    out["selection"] = copy.deepcopy(selection)
    out["constraints"] = [c for c in out["constraints"] if c["claim_id"] in ids]
    pairs = {(c["vendor"], c["advisory_id"], c["cve_id"]) for c in out["constraints"]}
    out["source_groups"] = [
        g
        for g in out["source_groups"]
        if any((g["vendor"], g["advisory_id"], cid) in pairs for cid in g["cve_ids"])
    ]
    for c in out["constraints"]:
        claim = claims[c["claim_id"]]
        if (
            contracts.definition_sha256(claim) != c["claim_sha256"]
            or any(
                claim[key] != c[key]
                for key in ("vendor", "family", "advisory_id", "cve_id", "source", "scope_level")
            )
            or comparison.day(claim["initial_published_at"]) != c["date"]
        ):
            raise ValueError("Constraint claim binding differs")
        risk, facets = _risk(claim, c["kev_membership"], out["generated_at"])
        if risk != c["high_risk"] or facets != c["severity_facets"]:
            raise ValueError("Constraint risk differs from current attributed metrics")
    out["rows"] = _rows(
        out["constraints"],
        end=out["observation_end"],
        vendors=selection["effective_vendors"],
        window=selection["requested_window"],
    )
    validate_report(out)
    return out


def csv_export(report, *, max_bytes=128_000_000):
    """Use normal scalar/blank-null cells and the shared spreadsheet-safe policy."""
    from ..exports import csv_table

    validate_report(report)
    fields = list(_SCHEMA["$defs"]["row"]["properties"])

    def rows():
        for row in report["rows"]:
            yield {
                key: json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                if isinstance(value, (list, dict))
                else value
                for key, value in row.items()
            }

    return csv_table(fields, rows, max_bytes=max_bytes)
