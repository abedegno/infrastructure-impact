"""Optional source-owned analysis. Native inference precedes bounded public compilation.

Only fixed public fact tables are interned; transport remains ordinary publication
v1/v2 JSON. Full native upgrade matrices and first-fixed catalogues stay offline.
"""

import copy
import json

from jsonschema import Draft202012Validator, ValidationError

from .. import publication_codec as codec
from ..settings import PACKAGE
from . import switching_comparison as comparison
from . import switching_evidence as contracts
from . import switching_upgrades as upgrades

_SCHEMA = json.loads((PACKAGE / "schemas/switching-analysis-v1.json").read_text())
_VALIDATOR = Draft202012Validator(_SCHEMA)


def _validate_shape(value, definition):
    try:
        _VALIDATOR.evolve(
            schema={"$ref": "#/$defs/" + definition, "$defs": _SCHEMA["$defs"]}
        ).validate(value)
    except ValidationError as error:
        raise ValueError("Invalid analysis DTO: " + error.message) from None


SHARED = ("source", "proof", "severity_facets", "train_binding")
OWNER = (
    "claim_id",
    "claim_sha256",
    "vendor",
    "family",
    "advisory_id",
    "cve_id",
    "scope_level",
    "date",
    "high_risk",
    "kev_membership",
)


def _hash(value):
    return contracts.definition_sha256(value if isinstance(value, dict) else {"items": value})


def _intern(table, value, budget):
    key = _hash(value)
    if key not in table:
        codec.charge_value(value, budget)
        budget.charge(len(key) + 4, len(key) + 4)
        table[key] = copy.deepcopy(value)
    return key


def _pack(header, constraints, *, max_bytes=codec.MAX_SELECTED):
    budget = codec.Budget(max_bytes)
    codec.charge_value(header, budget)
    out = dict(
        copy.deepcopy(header),
        representation="compact-requirements",
        members={},
        facts={},
        requirements=[],
    )
    for c in constraints:
        member = {k: c[k] for k in OWNER}
        for k in ("source", "severity_facets"):
            member[k + "_ref"] = _intern(out["facts"], c[k], budget)
        cid = c["claim_id"]
        if cid in out["members"] and out["members"][cid] != member:
            raise ValueError("Conflicting requirement ownership")
        if cid not in out["members"]:
            codec.charge_value(member, budget)
            out["members"][cid] = member
        value = {k: copy.deepcopy(v) for k, v in c.items() if k not in OWNER + SHARED}
        value["claim_id"] = cid
        for k in ("proof", "train_binding"):
            value[k + "_ref"] = _intern(out["facts"], c[k], budget)
        codec.charge_value(value, budget)
        out["requirements"].append(value)
    used = {r["inference"]["group_id"] for r in out["requirements"] if r["inference"]}
    out["inference_groups"] = [g for g in out["inference_groups"] if g["group_id"] in used]
    out["membership_sha256"] = _hash(out["members"])
    out["membership_count"] = len(out["members"])
    out["content_sha256"] = _hash(out)
    codec.charge_value(out, codec.Budget(max_bytes))
    return out


def compile_requirements(
    evidence,
    first_fixed_report,
    release_history,
    kev_selection,
    *,
    publication,
    generated_at,
    max_bytes=codec.MAX_SELECTED,
):
    header, requirements = upgrades.prepare_report(
        evidence,
        first_fixed_report,
        release_history,
        kev_selection,
        publication=publication,
        generated_at=generated_at,
    )
    result = _pack(header, requirements, max_bytes=max_bytes)
    validate_requirements(result, evidence=evidence)
    return result


def _expand(report, requirement):
    member = report["members"][requirement["claim_id"]]
    c = {k: v for k, v in member.items() if not k.endswith("_ref")}
    c.update({k: v for k, v in requirement.items() if not k.endswith("_ref")})
    for k in SHARED:
        owner = member if k in ("source", "severity_facets") else requirement
        c[k] = report["facts"][owner[k + "_ref"]]
    return c


def validate_requirements(report, *, evidence=None):
    codec.charge_value(report, codec.Budget(codec.MAX_SELECTED))
    _validate_shape(report, "compact")
    if report["observation_end"] != comparison.day(report["generated_at"]):
        raise ValueError("Compact observation bounds differ")
    if report["kev_context"]["evaluated_at"] != report["generated_at"]:
        raise ValueError("Compact KEV evaluation differs")
    if report["representation"] != "compact-requirements" or report["selection"] is not None:
        raise ValueError("Complete compact requirements required")
    if report["content_sha256"] != _hash(
        {k: v for k, v in report.items() if k != "content_sha256"}
    ):
        raise ValueError("Compact content fingerprint differs")
    if report["membership_sha256"] != _hash(report["members"]) or report["membership_count"] != len(
        report["members"]
    ):
        raise ValueError("Compact membership differs")
    if report["definition_sha256"] != _hash(contracts.definition()):
        raise ValueError("Compact definition differs")
    for key, fact in report["facts"].items():
        if key != _hash(fact):
            raise ValueError("Compact fact fingerprint differs")
    groups = {g["group_id"]: g for g in report["inference_groups"]}
    if len(groups) != len(report["inference_groups"]) or any(
        key != _hash({k: v for k, v in group.items() if k != "group_id"})
        for key, group in groups.items()
    ):
        raise ValueError("Compact inference ownership differs")
    seen, scenario_membership = set(), {}
    for r in report["requirements"]:
        try:
            c = _expand(report, r)
        except KeyError:
            raise ValueError("Compact reference closure differs") from None
        _validate_shape(c, "upgrade_constraint")
        if c["inference"] is not None:
            group = groups.get(c["inference"]["group_id"])
            if (
                not group
                or c["claim_id"] not in group["affected_claim_ids"]
                or c["inference"]["maximum_affected"] != group["maximum_affected"]
            ):
                raise ValueError("Compact inference membership differs")
        if c["target"] is not None and not c["proof"]:
            raise ValueError("Compact target lacks source proof")
        if c["date"] is None and "unknown_initial_publication" not in c["issues"]:
            raise ValueError("Compact unknown date lost")
        identity = c["claim_id"], c["train"], c["scenario"]
        if identity in seen:
            raise ValueError("Duplicate compact requirement")
        seen.add(identity)
        scenario_membership.setdefault(identity[:2], set()).add(c["scenario"])
        if c["target"] != upgrades._minimum(c["vendor"], c["alternatives"], c["train"]):
            raise ValueError("Compact target differs")
        if c["target"] is None and not c["issues"]:
            raise ValueError("Missing compact target cannot be resolved")
    if any(values != set(upgrades.SCENARIOS) for values in scenario_membership.values()):
        raise ValueError("Compact complete scenario ownership differs")
    if {identity[0] for identity in seen} != set(report["members"]) or any(
        cid != m["claim_id"] for cid, m in report["members"].items()
    ):
        raise ValueError("Compact member reference closure differs")
    if evidence is not None:
        contracts.validate_evidence(
            evidence, publication=report["publication"], generated_at=report["generated_at"]
        )
        if _hash(evidence) != report["evidence_sha256"]:
            raise ValueError("Compact current evidence differs")
        if set(report["members"]) != {
            c["claim_id"] for c in upgrades.eligible_claims_for(evidence)
        }:
            raise ValueError("Compact complete owned membership differs")
        claims = {c["claim_id"]: c for c in evidence["claims"]}
        for cid, m in report["members"].items():
            c = claims.get(cid)
            if c is None or _hash(c) != m["claim_sha256"]:
                raise ValueError("Compact current claim differs")
            if any(
                c[k] != m[k] for k in ("vendor", "family", "advisory_id", "cve_id", "scope_level")
            ):
                raise ValueError("Compact ownership differs")
            if comparison.day(c["initial_published_at"]) != m["date"]:
                raise ValueError("Compact initial date differs")
            risk, facets = upgrades._risk(c, m["kev_membership"], report["generated_at"])
            if (
                risk != m["high_risk"]
                or facets != report["facts"][m["severity_facets_ref"]]
                or c["source"] != report["facts"][m["source_ref"]]
            ):
                raise ValueError("Compact attributed source/risk differs")


def _identity(report, study):
    for key in ("publication", "generated_at", "observation_end"):
        if report[key] != study[key]:
            raise ValueError("Analysis selection identity differs")
    if report["definition_sha256"] != study["selection"]["definition_sha256"]:
        raise ValueError("Analysis selection definition differs")


def select_upgrades(report, study_selection, *, max_bytes=codec.MAX_SELECTED):
    selection = study_selection["selection"]
    comparison._selection_evaluation(
        selection["requested_vendor"],
        selection["scope_level"],
        selection["requested_cve_ids"],
        study_selection["generated_at"],
    )
    expected_vendors = (
        [selection["requested_vendor"]]
        if selection["requested_vendor"]
        else list(comparison.VENDORS)
    )
    if selection["effective_vendors"] != expected_vendors:
        raise ValueError("Analysis selected vendors differ")
    base = dict(
        schema_version=1,
        publication=copy.deepcopy(study_selection["publication"]),
        generated_at=study_selection["generated_at"],
        observation_end=study_selection["observation_end"],
        definition_sha256=selection["definition_sha256"],
        selection=copy.deepcopy(selection),
    )
    if report is None:
        return dict(base, availability="unavailable", requirements=None, rows=[])
    _identity(report, study_selection)
    validate_requirements(report)
    requested = selection["requested_cve_ids"]
    members = {
        cid
        for cid, m in report["members"].items()
        if m["vendor"] in selection["effective_vendors"]
        and (selection["scope_level"] == "os_family" or m["scope_level"] == "model_qualified")
        and (requested is None or m["cve_id"] in requested)
        and (
            m["date"] is None
            or contracts.definition()["start_date"] <= m["date"] <= report["observation_end"]
        )
    }
    budget = codec.Budget(512_000_000)
    codec.charge_value(report, budget)
    constraints = []
    for r in report["requirements"]:
        if r["claim_id"] in members:
            c = _expand(report, r)
            codec.charge_value(c, budget)
            constraints.append(c)
    pairs = {(c["vendor"], c["advisory_id"], c["cve_id"]) for c in constraints}
    header = {
        k: v
        for k, v in report.items()
        if k
        not in (
            "representation",
            "members",
            "facts",
            "requirements",
            "membership_sha256",
            "membership_count",
            "content_sha256",
        )
    }
    header["source_groups"] = [
        g
        for g in header["source_groups"]
        if any((g["vendor"], g["advisory_id"], cid) in pairs for cid in g["cve_ids"])
    ]
    compact = _pack(header, constraints, max_bytes=max_bytes)
    rows = upgrades._rows(
        constraints,
        end=report["observation_end"],
        vendors=selection["effective_vendors"],
        window=selection["requested_window"],
    )
    result = dict(base, availability="available", requirements=compact, rows=rows)
    codec.charge_value(result, budget)
    codec.charge_value(result, codec.Budget(max_bytes))
    return result


def project_native(report, study_selection):
    """Offline oracle verifies actual membership/risk/proofs before public projection."""
    selected = upgrades.select_report(report, study_selection)
    header = {k: v for k, v in selected.items() if k not in ("constraints", "rows")}
    header["selection"] = None
    compiled = _pack(header, selected["constraints"])
    return select_upgrades(compiled, study_selection)


def _csv_json(value):
    """Exact binary64 JSON numbers match the existing browser identity tokens.

    Only nested analysis CSV cells use this spelling; numeric values, source
    receipts and ordinary report JSON remain untouched. Object order is retained.
    """
    from decimal import Decimal

    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + _csv_json(v) for k, v in value.items()
            )
            + "}"
        )
    if isinstance(value, list):
        return "[" + ",".join(_csv_json(v) for v in value) + "]"
    if type(value) is float:
        return (
            str(int(value))
            if value.is_integer()
            else format(Decimal.from_float(value), "f").rstrip("0")
        )
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def csv_export(report, *, max_bytes=codec.MAX_SELECTED):
    from ..exports import csv_table

    _validate_shape(report, "selected_upgrades")
    fields = list(upgrades._SCHEMA["$defs"]["row"]["properties"])

    def rows():
        for row in report["rows"]:
            yield {k: _csv_json(v) if isinstance(v, (list, dict)) else v for k, v in row.items()}

    return csv_table(fields, rows, max_bytes=max_bytes)


# The exact public facets consumed by model coverage and KEV reconciliation.
# No scores, versions, remediations, source bodies, catalogue, or private notes.
CLAIM_FIELDS = (
    "claim_id",
    "vendor",
    "family",
    "advisory_id",
    "cve_id",
    "status",
    "scope",
    "scope_level",
    "initial_published_at",
    "publisher",
    "product_id",
    "product",
    "named_platforms",
    "platform_bindings",
    "conditional_affected",
    "source",
    "bundle",
)


def study_claim_facets(evidence):
    """All facets admissible by the frozen study's exact vendor/family pairs.

    No status, date, CVE, scope or model filter belongs here. Full evidence and
    its digest remain native authority, including every out-of-study claim.
    """
    pairs = {(target["vendor"], target["family"]) for target in contracts.definition()["targets"]}
    return (claim for claim in evidence["claims"] if (claim["vendor"], claim["family"]) in pairs)


def build_report(records, retained, study, *, release_history=None, source_frame=None):
    from . import first_fixed
    from . import switching_disclosure as disclosure
    from . import switching_kev_reconciliation as reconciliation

    source_frame = {} if source_frame is None else source_frame
    if not isinstance(source_frame, dict):
        raise ValueError("Optional analysis source input must be an object")
    if set(source_frame) - {"api_results", "policy_source", "calibration_records"}:
        raise ValueError("Unknown optional analysis source input")
    contracts.validate_comparison(study)
    if (
        study["selection"]["requested_vendor"] is not None
        or study["selection"]["requested_cve_ids"] is not None
        or study["selection"]["requested_window"] != "all"
        or study["selection"]["scope_level"] != "os_family"
    ):
        raise ValueError("Compile analysis from complete accepted study")
    evidence, kev = study["inputs"]["evidence"], study["inputs"]["kev"]
    identity = dict(publication=study["publication"], generated_at=study["generated_at"])
    from ..domain import validate_advisory

    if not isinstance(source_frame.get("api_results", []), list):
        raise ValueError("Acknowledged API results must be an explicit list")
    calibration = source_frame.get("calibration_records", [])
    if not isinstance(calibration, list):
        raise ValueError("Calibration records must be an explicit list")
    for record in calibration:
        validate_advisory(record)
    ff = first_fixed.build_report(
        records + calibration, api_results=source_frame.get("api_results", []), **identity
    )
    requirements = compile_requirements(evidence, ff, release_history, kev, **identity)
    inventory = reconciliation.build_inventory(
        [r for r in records if r["vendor"] in comparison.VENDORS],
        [r for r in retained if r["vendor"] in comparison.VENDORS],
        study_definition=study["definition"],
        **identity,
    )
    gap = reconciliation.build_report(
        kev,
        study["definition"],
        evidence,
        inventory,
        evaluated_at=study["generated_at"],
        selection=study,
        **identity,
    )
    claims, budget = {}, codec.Budget(codec.MAX_SELECTED)
    for c in study_claim_facets(evidence):
        value = {k: copy.deepcopy(c.get(k)) for k in CLAIM_FIELDS}
        value["disclosure_severity"] = disclosure.severity_facets([c])
        value["issues"] = [i for i in c["issues"] if i.startswith("cisco_model_")]
        value["claim_sha256"] = _hash(c)
        codec.charge_value(value, budget)
        claims[c["claim_id"]] = value
    out = dict(
        schema_version=1,
        representation="compiled-analysis",
        **identity,
        definition_sha256=evidence["definition_sha256"],
        observation_end=study["observation_end"],
        requirements=requirements,
        claims=claims,
        release_history=copy.deepcopy(release_history),
        disclosure=disclosure.build_report(
            records,
            study,
            evidence=evidence,
            policy_source=source_frame.get("policy_source"),
            bundle_history=release_history,
            **identity,
        ),
        kev_reconciliation=gap,
    )
    out["content_sha256"] = _hash(out)
    validate_report(out, evidence=evidence, records=records, retained=retained)
    return out


def validate_report(
    report, *, evidence=None, records=None, retained=None, publication=None, generated_at=None
):
    from . import switching_disclosure as disclosure
    from . import switching_kev_reconciliation as reconciliation

    codec.charge_value(report, codec.Budget(codec.MAX_SELECTED))
    _validate_shape(report, "compiled")
    if report["release_history"] is not None:
        upgrades.releases.validate_report(
            report["release_history"],
            publication=copy.deepcopy(report["publication"]),
            generated_at=report["generated_at"],
        )
        if evidence is not None:
            upgrades.releases.validate_current_references(report["release_history"], evidence)
    if set(report) != {
        "schema_version",
        "representation",
        "publication",
        "generated_at",
        "definition_sha256",
        "observation_end",
        "requirements",
        "claims",
        "disclosure",
        "kev_reconciliation",
        "release_history",
        "content_sha256",
    }:
        raise ValueError("Invalid compiled analysis fields")
    if report["content_sha256"] != _hash(
        {k: v for k, v in report.items() if k != "content_sha256"}
    ):
        raise ValueError("Analysis content fingerprint differs")
    if publication is not None and report["publication"] != publication:
        raise ValueError("Analysis publication differs")
    if generated_at is not None and report["generated_at"] != generated_at:
        raise ValueError("Analysis generation differs")
    for child in ("requirements", "disclosure", "kev_reconciliation"):
        for key in ("publication", "generated_at", "definition_sha256", "observation_end"):
            if report[child][key] != report[key]:
                raise ValueError("Analysis child identity differs")
    validate_requirements(report["requirements"], evidence=evidence)
    disclosure.validate_report(report["disclosure"])
    reconciliation.validate_report(report["kev_reconciliation"])
    _validate_child_ownership(report, evidence=evidence, records=records, retained=retained)
    if evidence is not None:
        expected = {c["claim_id"]: c for c in study_claim_facets(evidence)}
        if set(expected) != set(report["claims"]):
            raise ValueError("Analysis complete membership differs")
        for cid, c in report["claims"].items():
            if c["issues"] != [i for i in expected[cid]["issues"] if i.startswith("cisco_model_")]:
                raise ValueError("Analysis model diagnostic ownership differs")
            if c["disclosure_severity"] != disclosure.severity_facets([expected[cid]]):
                raise ValueError("Analysis disclosure facet ownership differs")
            if c["claim_sha256"] != _hash(expected[cid]) or any(
                c[k] != expected[cid].get(k) for k in CLAIM_FIELDS
            ):
                raise ValueError("Analysis source membership differs")


def _validate_child_ownership(report, *, evidence=None, records=None, retained=None):
    """Prove child membership against compact claims and native record authorities.

    Readers authenticate the compiled root's transport first. The publication gate
    additionally supplies the complete current/retained source records; an evidence
    validation cannot silently accept record references without that authority.
    """
    from collections import defaultdict

    from . import switching_disclosure as disclosure
    from . import switching_kev_reconciliation as reconciliation

    context = selection_context(report, {})
    for name in ("disclosure", "kev_reconciliation"):
        if report[name]["selection"] != context["selection"]:
            raise ValueError("Analysis child complete selection differs")
    owned_pairs = defaultdict(list)
    for claim in _selected_claims(report, context["selection"]):
        if comparison._explicit(claim):
            owned_pairs[disclosure._key(claim)].append(claim)
    pairs = report["disclosure"]["pairs"]
    if {disclosure._key(p) for p in pairs} != set(owned_pairs):
        raise ValueError("Disclosure child source pair ownership differs")
    for pair in pairs:
        claims = owned_pairs[disclosure._key(pair)]
        severity = {contracts._json(f): f for c in claims for f in c["disclosure_severity"]}
        if (
            pair["severity"] != [severity[k] for k in sorted(severity)]
            or pair["claim_ids"] != sorted(c["claim_id"] for c in claims)
            or pair["source"] != claims[0]["source"]
            or any(pair["initial_published_at"] != c["initial_published_at"] for c in claims)
            or pair["product_ids"]
            != sorted({c["product_id"] for c in claims if c["product_id"] is not None})
            or pair["models"]
            != sorted(
                {
                    b["model"]
                    for c in claims
                    for b in c["platform_bindings"]
                    if b["model"] is not None
                }
            )
        ):
            raise ValueError("Disclosure child claim/source ownership differs")
    entries = report["kev_reconciliation"]["entries"]
    if (records is None) != (retained is None):
        raise ValueError("Both current and retained record authorities are required")
    inventory = None
    if records is not None:
        inventory = reconciliation.build_inventory(
            [r for r in records if r["vendor"] in comparison.VENDORS],
            [r for r in retained if r["vendor"] in comparison.VENDORS],
            publication=report["publication"],
            generated_at=report["generated_at"],
            study_definition=contracts.definition(),
        )
        current = {disclosure._source_key(r): r for r in records}
        for fact in report["disclosure"]["advisory_facts"]:
            key = (
                fact["vendor"],
                fact["advisory_id"],
                fact["source"]["source_url"],
                fact["source"]["source_sha256"],
            )
            source = current.get(key)
            if (
                source is None
                or fact["metadata"] != source.get("disclosure_metadata")
                or fact["source"]["retrieved_at"] != source["source_observed_at"]
                or fact["source"]["source_locator"] != "advisory"
            ):
                raise ValueError("Disclosure child current record source differs")
    elif evidence is not None and (
        report["disclosure"]["advisory_facts"]
        or any(e["current_records"] or e["retained_records"] for e in entries)
    ):
        raise ValueError("Child source references require authoritative current/retained records")
    claim_index = defaultdict(list)
    for claim in report["claims"].values():
        claim_index[claim["vendor"], claim["family"], claim["cve_id"]].append(claim)
    record_indexes = {name: defaultdict(list) for name in ("current_records", "retained_records")}
    if inventory is not None:
        for name, index in record_indexes.items():
            for record in inventory[name]:
                for cid in record["cve_ids"]:
                    index[record["vendor"], cid].append(record)
    for entry in entries:
        mapping = entry["mapping"]
        claims = claim_index[mapping["vendor"], mapping["family"], entry["cve_id"]]
        if entry["current_claims"] != [reconciliation._claim_ref(c) for c in claims]:
            raise ValueError("KEV child current claim/source ownership differs")
        if inventory is not None:
            for name, index in record_indexes.items():
                if entry[name] != index[mapping["vendor"], entry["cve_id"]]:
                    raise ValueError("KEV child current/retained record ownership differs")


def _selected_claims(report, selection, *, window=True):
    definition = contracts.definition()
    start, end = comparison._bounds(
        definition, report["observation_end"], selection["requested_window"]
    )
    requested = selection["requested_cve_ids"]
    return [
        c
        for c in report["claims"].values()
        if c["vendor"] in selection["effective_vendors"]
        and c["family"] == upgrades.releases.FAMILIES[c["vendor"]]
        and (selection["scope_level"] == "os_family" or c["scope_level"] == "model_qualified")
        and (requested is None or c["cve_id"] in requested)
        and (
            comparison.day(c["initial_published_at"]) is None
            or definition["start_date"]
            <= comparison.day(c["initial_published_at"])
            <= report["observation_end"]
        )
        and (
            not window
            or comparison._in_window(
                comparison.day(c["initial_published_at"]), start, end, selection["requested_window"]
            )
        )
    ]


def _disclosure_selected(report, selection, selected):
    from collections import Counter

    from . import switching_disclosure as disclosure

    ids = {c["claim_id"] for c in selected}
    out = copy.deepcopy(report)
    out["selection"] = copy.deepcopy(selection)
    out["pairs"] = [p for p in out["pairs"] if ids.intersection(p["claim_ids"])]
    for p in out["pairs"]:
        p["claim_ids"] = sorted(ids.intersection(p["claim_ids"]))
        owned = [c for c in selected if c["claim_id"] in p["claim_ids"]]
        p["product_ids"] = sorted({c["product_id"] for c in owned if c["product_id"] is not None})
        p["models"] = sorted(
            {b["model"] for c in owned for b in c["platform_bindings"] if b["model"] is not None}
        )
        facets = {contracts._json(f): f for c in owned for f in c["disclosure_severity"]}
        p["severity"] = [facets[k] for k in sorted(facets)]
        p["source"] = copy.deepcopy(owned[0]["source"])
    facts = {p["fact_id"] for p in out["pairs"]}
    out["advisory_facts"] = [f for f in out["advisory_facts"] if f["id"] in facts]
    bundles = []
    for b in out["bundles"]:
        if (
            b["kind"] == "explicit_publisher_bundle"
            and b["upstream"] is None
            and not any(
                c["bundle"] is not None
                and c["bundle"]["publisher_id"] == b["publisher_id"]
                and c["bundle"]["source"] == b["source"]
                for c in selected
                if comparison._explicit(c)
            )
        ):
            continue
        members = [
            p
            for p in out["pairs"]
            if p["vendor"] == b["vendor"]
            and p["family"] == b["family"]
            and p["advisory_id"] in b["member_advisory_ids"]
        ]
        if members:
            b["selected_advisory_ids"] = sorted({p["advisory_id"] for p in members})
            b["selected_cve_ids"] = sorted({p["cve_id"] for p in members})
            bundles.append(b)
    out["bundles"] = bundles
    fact_index = {f["id"]: f for f in out["advisory_facts"]}
    for p in out["pairs"]:
        meta = fact_index.get(p["fact_id"], {}).get("metadata")
        has_bundle = (meta is not None and meta["bundle"] is not None) or any(
            p["vendor"] == b["vendor"]
            and p["family"] == b["family"]
            and p["advisory_id"] in b["selected_advisory_ids"]
            and p["cve_id"] in b["selected_cve_ids"]
            for b in bundles
        )
        p["missing"] = [m for m in p["missing"] if m != "explicit_bundle_unavailable"]
        if not has_bundle:
            p["missing"].append("explicit_bundle_unavailable")
    pairs = out["pairs"]
    out["periods"] = {
        period: disclosure._summary([p for p in pairs if p["date_period"] == period])
        for period in ("pre_july", "from_july", "unknown")
    }
    out["years"] = {
        year: disclosure._summary(
            [
                p
                for p in pairs
                if (comparison.day(p["initial_published_at"]) or "unknown")[:4] == year
            ]
        )
        for year in sorted(
            {
                comparison.day(p["initial_published_at"])[:4]
                for p in pairs
                if comparison.day(p["initial_published_at"])
            }
        )
    }
    out["year_periods"] = disclosure._year_periods(pairs)
    out["coverage"] = dict(
        selected_affected_claims=len({cid for p in pairs for cid in p["claim_ids"]}),
        owned_source_pairs=len(pairs),
        metadata_advisories=len(out["advisory_facts"]),
        missing_counts=dict(sorted(Counter(m for p in pairs for m in p["missing"]).items())),
        unsupported_advisory_types=sorted(
            {
                f["metadata"]["advisory_type"]
                for f in out["advisory_facts"]
                if f["metadata"]["advisory_type"] == "unknown"
            }
        ),
    )
    disclosure.validate_report(out)
    return out


def _kev_selected(report, selection):
    from . import switching_kev_reconciliation as reconciliation

    out = copy.deepcopy(report["kev_reconciliation"])
    out["selection"] = copy.deepcopy(selection)
    entries = []
    for e in out["entries"]:
        vendor = e["mapping"]["vendor"]
        if vendor is not None and vendor not in selection["effective_vendors"]:
            continue
        claims = [
            c
            for c in report["claims"].values()
            if c["vendor"] == vendor
            and c["family"] == e["mapping"]["family"]
            and c["cve_id"] == e["cve_id"]
        ]
        state, reasons = (
            reconciliation._state(
                claims,
                e["current_records"],
                e["retained_records"],
                selection,
                contracts.definition(),
                report["observation_end"],
            )
            if vendor
            else ("unknown", ["exact_pair_unmapped"])
        )
        e["claim_state"] = state
        e["in_requested_cve_filter"] = (
            selection["requested_cve_ids"] is None or e["cve_id"] in selection["requested_cve_ids"]
        )
        e["in_effective_study_cohort"] = e["cve_id"] in selection["effective_cve_ids"]
        if not e["in_requested_cve_filter"]:
            reasons.append("outside_explicit_cve_filter")
        if not e["in_effective_study_cohort"]:
            reasons.append("outside_effective_study_cohort")
        e["reason_codes"] = sorted(set(reasons))
        entries.append(e)
    out["entries"] = entries
    out["summary"] = reconciliation._summary(entries)
    reconciliation.validate_report(out)
    return out


def select_report(report, study_selection, *, max_bytes=codec.MAX_SELECTED):
    from . import switching_model_coverage as models

    if report is None:
        return dict(
            schema_version=1,
            publication=copy.deepcopy(study_selection["publication"]),
            generated_at=study_selection["generated_at"],
            selection=copy.deepcopy(study_selection["selection"]),
            availability="unavailable",
            upgrades=select_upgrades(None, study_selection),
            disclosure=None,
            model_coverage=None,
            kev_reconciliation=None,
            release_history=upgrades.releases.select_report(None, dict(study_selection, rows=[])),
        )
    _identity(report, study_selection)
    validate_report(report)
    selection = study_selection["selection"]
    context = selection_context(
        report,
        dict(
            vendor=selection["requested_vendor"],
            scope_level=selection["scope_level"],
            window=selection["requested_window"],
            cve_ids=selection["requested_cve_ids"],
        ),
    )
    if context["selection"] != selection:
        raise ValueError("Analysis accepted cohort differs")
    selected = _selected_claims(report, selection)
    out = dict(
        schema_version=1,
        publication=copy.deepcopy(report["publication"]),
        generated_at=report["generated_at"],
        selection=copy.deepcopy(study_selection["selection"]),
        availability="available",
        upgrades=select_upgrades(report["requirements"], study_selection, max_bytes=max_bytes),
        disclosure=_disclosure_selected(
            report["disclosure"], study_selection["selection"], selected
        ),
        model_coverage=models.from_selected(
            selected,
            study_selection,
            publication=copy.deepcopy(report["publication"]),
            generated_at=report["generated_at"],
        ),
        kev_reconciliation=_kev_selected(report, study_selection["selection"]),
        release_history=upgrades.releases.select_report(report["release_history"], context),
    )
    codec.charge_value(out, codec.Budget(max_bytes))
    _validate_shape(out, "selected")
    return out


def selection_context(report, options):
    """Trusted compact adapter: accepted source membership replaces full claim hydration."""
    options = dict(vendor=None, scope_level="os_family", window="all", cve_ids=None, **{}) | options
    if set(options) != {"vendor", "scope_level", "window", "cve_ids"}:
        raise ValueError("Unknown analysis selection option")
    comparison._selection_evaluation(
        options["vendor"], options["scope_level"], options["cve_ids"], report["generated_at"]
    )
    comparison._bounds(contracts.definition(), report["observation_end"], options["window"])
    vendors = [options["vendor"]] if options["vendor"] else list(comparison.VENDORS)
    selection = dict(
        requested_vendor=options["vendor"],
        effective_vendors=vendors,
        scope_level=options["scope_level"],
        requested_window=options["window"],
        effective_windows=[f"{v}:{options['scope_level']}:{options['window']}" for v in vendors],
        requested_cve_ids=sorted(options["cve_ids"]) if options["cve_ids"] is not None else None,
        effective_cve_ids=[],
        definition_sha256=report["definition_sha256"],
    )
    if "claims" in report:
        selection["effective_cve_ids"] = sorted(
            {c["cve_id"] for c in _selected_claims(report, selection) if c["cve_id"] is not None}
        )
    return {
        k: copy.deepcopy(report[k]) for k in ("publication", "generated_at", "observation_end")
    } | dict(
        selection=selection,
        definition=contracts.definition(),
        rows=[
            dict(
                vendor=v,
                affected_cve_ids=sorted(
                    {
                        c["cve_id"]
                        for c in _selected_claims(report, selection)
                        if c["vendor"] == v and comparison._explicit(c)
                    }
                ),
            )
            for v in vendors
        ]
        if "claims" in report
        else [],
    )


def analysis_csv_export(report, *, max_bytes=codec.MAX_SELECTED):
    """Typed sections, with scalar blanks for unknown values and nested JSON cells."""
    from ..exports import csv_table

    _validate_shape(report, "selected")
    fields = ["row_type", "vendor", "cve_id", "year", "event_count", "payload"]

    def rows():
        sections = [("upgrade", report["upgrades"]["rows"])]
        if report["availability"] == "available":
            sections.extend(
                [
                    ("disclosure", report["disclosure"]["pairs"]),
                    ("kev_reconciliation", report["kev_reconciliation"]["entries"]),
                    ("model_coverage", report["model_coverage"]["models"]),
                    ("release_history", report["release_history"]["releases"]),
                ]
            )
        for kind, values in sections:
            for value in values:
                yield dict(
                    row_type=kind,
                    **{k: value.get(k) for k in fields[1:-1]},
                    payload=_csv_json(value),
                )

    return csv_table(fields, rows, max_bytes=max_bytes)
