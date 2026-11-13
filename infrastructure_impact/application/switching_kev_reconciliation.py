"""Pure exact-label KEV source candidates, separate from study affected totals.

Inputs are a native evidence envelope and full selected comparison report. The
inventory factory reduces already collected records; it never acquires evidence.
"""

import json
from collections import Counter
from copy import deepcopy

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from ..settings import PACKAGE
from . import kev
from . import switching_comparison as comparison
from . import switching_evidence as contracts

MAPPING_VERSION = "switching-kev-exact-pairs-v1"
CISCO_LABELS = (
    "Cisco IOS XE Web UI",
    "IOS Software and Cisco IOS XE Software",
    "IOS XE Software",
    "IOS XE Web UI",
    "IOS and IOS XE",
    "IOS and IOS XE Software",
    "IOS, IOS XR, and IOS XE",
    "IOS, XR, and XE Software",
)
RULES = {("Arista", "Extensible Operating System"): ("arista-eos-1", "arista", "arista-eos")}
RULES.update(
    {
        ("Cisco", label): (f"cisco-iosxe-{i}", "cisco", "cisco-iosxe")
        for i, label in enumerate(CISCO_LABELS, 1)
    }
)
# Load the bundled contract at module import; reducer calls perform no file I/O.
_SCHEMA = json.loads((PACKAGE / "schemas/switching-kev-reconciliation-v1.json").read_text())
_VALIDATOR = Draft202012Validator(_SCHEMA, format_checker=FormatChecker())
_INVENTORY_VALIDATOR = _VALIDATOR.evolve(schema=_SCHEMA["$defs"]["inventory"])


def _validate(value, *, inventory=False):
    try:
        (_INVENTORY_VALIDATOR if inventory else _VALIDATOR).validate(value)
    except ValidationError as error:
        raise ValueError(f"Invalid KEV reconciliation: {error.message}") from error


STATES = (
    "no_observed_vendor_record",
    "observed_no_study_claim",
    "retained_only",
    "draft_only",
    "affected_scope_unresolved",
    "documented_unaffected_for_selected_scope",
    "documented_affected",
    "conflicting_representations",
    "outside_study_window",
    "unknown",
)
LIMITATIONS = [
    "Exact publisher pairs establish family source candidates, never product affectedness.",
    "Mixed-OS labels require vendor evidence for IOS XE applicability.",
    "Candidate CVEs are not added to study affected totals; scopes are nonadditive.",
    "No matching AOS-CX pair does not establish absence of exploited AOS-CX vulnerabilities.",
    "CISA dateAdded, CVE year and catalogue release are not publisher initial dates.",
    "Catalogue membership is retrospective; historical membership dates are not reconstructed.",
    "Missing records and unresolved literal model bindings do not establish exposure.",
]


def build_inventory(
    current_records, retained_records, *, publication, generated_at, study_definition
):
    """Reduce normalized v2 records; callers pass current and retained lists separately.

    Rebind only this local analysis envelope, preserving original capture references.
    Retained records default to disposition ``retained``; an existing disposition
    string is retained as audit context, never interpreted as an exposure claim.
    """

    def reduce(record, disposition):
        return dict(
            vendor=record["vendor"],
            advisory_id=record["advisory_id"],
            cve_ids=sorted(set(record["cves"])),
            document_status=record.get("document_status"),
            disposition=record.get("disposition", disposition),
            revision_id=record.get("revision_id"),
            evidence_id=record.get("evidence_id"),
            source=dict(
                source_url=record["source_url"],
                source_sha256=record["sha256"],
                retrieved_at=record["source_observed_at"],
                source_locator="advisory",
            ),
        )

    result = dict(
        publication=deepcopy(publication),
        generated_at=generated_at,
        definition_sha256=contracts.definition_sha256(study_definition),
        current_records=[reduce(r, "current") for r in current_records],
        retained_records=[reduce(r, "retained") for r in retained_records],
    )
    _validate(result, inventory=True)
    return result


def _claim_ref(c):
    return dict(
        claim_id=c["claim_id"],
        advisory_id=c["advisory_id"],
        status=c["status"],
        publisher_status=c["publisher"]["status"],
        scope=c["scope"],
        scope_level=c["scope_level"],
        initial_published_at=c["initial_published_at"],
        models=sorted({b["model"] for b in c["platform_bindings"] if b["model"] is not None}),
        conditional_affected=c.get("conditional_affected"),
        source=deepcopy(c["source"]),
    )


def _state(claims, current, retained, selection, definition, observation_end):
    if not claims:
        if current:
            return (
                "draft_only"
                if all((r["document_status"] or "").lower() == "draft" for r in current)
                else "observed_no_study_claim"
            ), []
        return ("retained_only" if retained else "no_observed_vendor_record"), []
    final = [c for c in claims if (c["publisher"]["status"] or "").lower() != "draft"]
    if not final:
        return "draft_only", []
    start, end = comparison._bounds(definition, observation_end, selection["requested_window"])
    dated = [c for c in final if comparison.day(c["initial_published_at"]) is not None]
    window = selection["requested_window"]
    eligible = [
        c
        for c in final
        if (comparison.day(c["initial_published_at"]) is None and window == "undated")
        or (
            comparison.day(c["initial_published_at"]) is not None
            and definition["start_date"]
            <= comparison.day(c["initial_published_at"])
            <= observation_end
            and comparison._in_window(comparison.day(c["initial_published_at"]), start, end, window)
        )
    ]
    if not eligible:
        if len(dated) != len(final):
            return "unknown", ["publisher_initial_date_missing"]
        return "outside_study_window", ["publisher_initial_date_outside_window"]
    # An undated bucket is descriptive, not proof of chronology/eligibility.
    if not any(c["initial_published_at"] is not None for c in eligible):
        return "unknown", ["publisher_initial_date_missing"]
    selected = [
        c
        for c in eligible
        if selection["scope_level"] == "os_family" or c["scope_level"] == "model_qualified"
    ]
    if not selected:
        return (
            "affected_scope_unresolved"
            if any(comparison._explicit(c) for c in eligible)
            else "unknown"
        ), ["selected_model_binding_unresolved"]
    scopes = {}
    for c in selected:
        key = (c["product_id"], c["product"], tuple(sorted(c["named_platforms"])))
        scopes.setdefault(key, set()).add(c["status"])
    if any(c["status"] == "conflicting" for c in selected) or any(
        {"affected", "unaffected"} <= statuses for statuses in scopes.values()
    ):
        return "conflicting_representations", []
    if any(comparison._explicit(c) for c in selected):
        return "documented_affected", []
    if all(c["status"] == "unaffected" and c["scope"] == "cve_specific" for c in selected):
        return "documented_unaffected_for_selected_scope", []
    return "unknown", ["vendor_claim_not_explicit_affected_or_unaffected"]


def _summary(entries):
    mapped = [e for e in entries if e["mapping"]["status"] == "mapped"]
    return dict(
        candidate_cves=len({e["cve_id"] for e in mapped}),
        entry_count=len(entries),
        unmapped_entries=sum(e["mapping"]["status"] == "unmapped" for e in entries),
        unknown_membership_entries=sum(e["membership"] == "unknown" for e in entries),
        state_counts=dict(sorted(Counter(e["claim_state"] for e in mapped).items())),
        completeness="not_established",
    )


def build_report(
    kev_report,
    study_definition,
    current_claims,
    retained_dispositions,
    *,
    publication,
    generated_at,
    evaluated_at,
    selection,
):
    """Reconcile captured labels with validated current vendor claims, without I/O.

    ``selection`` is a full native selected comparison report, not a list of CVEs.
    Its effective cohort is reported separately from the explicit requested filter.
    All inputs must be rebound to the same new local generation before calling.
    """
    kev._timestamp(generated_at)
    kev._timestamp(evaluated_at)
    contracts.validate_evidence(current_claims, publication=publication, generated_at=generated_at)
    kev.validate_report(kev_report)
    contracts.validate_comparison(selection, publication=publication, generated_at=generated_at)
    _validate(retained_dispositions, inventory=True)
    digest = contracts.definition_sha256(study_definition)
    for value in (kev_report, current_claims, retained_dispositions, selection):
        if value["publication"] != publication or value["generated_at"] != generated_at:
            raise ValueError("Reconciliation generation identity mismatch")
    if (
        current_claims["definition_sha256"] != digest
        or retained_dispositions["definition_sha256"] != digest
        or selection["selection"]["definition_sha256"] != digest
        or selection["definition"] != study_definition
    ):
        raise ValueError("Reconciliation definition identity mismatch")
    if (
        selection["inputs"] is None
        or selection["inputs"]["evidence"] != current_claims
        or selection["inputs"]["kev"] != kev_report
    ):
        raise ValueError("Reconciliation selection input identity mismatch")
    selected = deepcopy(selection["selection"])
    catalogue = kev.select_report(
        kev_report, sorted(kev_report["entries"]), evaluated_at=evaluated_at
    )
    target_pairs = {(t["vendor"], t["family"]) for t in study_definition["targets"]}
    entries = []
    for cid, row in sorted(catalogue["entries"].items()):
        rule = RULES.get((row["vendorProject"], row["product"]))
        if rule and (
            rule[1] not in selected["effective_vendors"] or (rule[1], rule[2]) not in target_pairs
        ):
            continue
        mapping = dict(
            status="mapped" if rule else "unmapped",
            rule_id=rule[0] if rule else None,
            vendor=rule[1] if rule else None,
            family=rule[2] if rule else None,
        )
        claims = [
            c
            for c in current_claims["claims"]
            if rule and c["cve_id"] == cid and c["vendor"] == rule[1] and c["family"] == rule[2]
        ]

        def records(key):
            return [
                deepcopy(r)
                for r in retained_dispositions[key]
                if rule and r["vendor"] == rule[1] and cid in r["cve_ids"]
            ]

        current, retained = records("current_records"), records("retained_records")
        state, reasons = (
            _state(
                claims, current, retained, selected, study_definition, selection["observation_end"]
            )
            if rule
            else ("unknown", ["exact_pair_unmapped"])
        )
        requested = selected["requested_cve_ids"]
        if requested is not None and cid not in requested:
            reasons.append("outside_explicit_cve_filter")
        if cid not in selected["effective_cve_ids"]:
            reasons.append("outside_effective_study_cohort")
        entries.append(
            dict(
                cve_id=cid,
                vendorProject=row["vendorProject"],
                product=row["product"],
                mapping=mapping,
                membership=catalogue["selection"]["membership"][cid],
                historically_listed=cid in catalogue["listed_cve_ids"],
                claim_state=state,
                current_claims=[_claim_ref(c) for c in claims],
                current_records=current,
                retained_records=retained,
                reason_codes=sorted(set(reasons)),
                in_requested_cve_filter=requested is None or cid in requested,
                in_effective_study_cohort=cid in selected["effective_cve_ids"],
            )
        )
    complete = set(catalogue["entries"]) == set(catalogue["listed_cve_ids"])
    observations = {}
    for family in sorted({t["family"] for t in study_definition["targets"]}):
        observations[family] = (
            "matching_catalogue_pair_observed"
            if any(
                RULES.get((r["vendorProject"], r["product"]), (None, None, None))[2] == family
                for r in catalogue["entries"].values()
            )
            else "catalogue_details_incomplete"
            if not complete or not catalogue["catalogue"]
            else "no_matching_catalogue_pair_observed"
        )
    result = dict(
        schema_version=1,
        publication=deepcopy(publication),
        generated_at=generated_at,
        evaluated_at=evaluated_at,
        definition_sha256=digest,
        mapping_version=MAPPING_VERSION,
        selection=selected,
        observation_end=selection["observation_end"],
        source=deepcopy(catalogue["source"]),
        catalogue=deepcopy(catalogue["catalogue"]),
        availability=catalogue["source"]["availability"],
        entries=entries,
        family_observations=observations,
        summary=_summary(entries),
        limitations=LIMITATIONS.copy(),
    )
    validate_report(result)
    return result


def validate_report(report):
    """Closed public schema plus mapping, cohort, distinct-count and identity checks."""
    _validate(report)
    if report["summary"] != _summary(report["entries"]):
        raise ValueError("Reconciliation summary mismatch")
    if report["selection"]["definition_sha256"] != report["definition_sha256"]:
        raise ValueError("Reconciliation definition identity mismatch")
    ids = [e["cve_id"] for e in report["entries"]]
    if ids != sorted(set(ids)):
        raise ValueError("Reconciliation entries must be sorted and unique")
    if (
        report["source"]["availability"] != report["availability"]
        or kev._availability(report, kev._timestamp(report["evaluated_at"]))
        != report["availability"]
    ):
        raise ValueError("Reconciliation availability mismatch")
    for entry in report["entries"]:
        rule = RULES.get((entry["vendorProject"], entry["product"]))
        expected = dict(
            status="mapped" if rule else "unmapped",
            rule_id=rule[0] if rule else None,
            vendor=rule[1] if rule else None,
            family=rule[2] if rule else None,
        )
        if entry["mapping"] != expected:
            raise ValueError("Reconciliation exact mapping mismatch")
        cid = entry["cve_id"]
        requested = report["selection"]["requested_cve_ids"]
        if entry["in_effective_study_cohort"] != (
            cid in report["selection"]["effective_cve_ids"]
        ) or entry["in_requested_cve_filter"] != (requested is None or cid in requested):
            raise ValueError("Reconciliation cohort mismatch")
        if entry["membership"] != (
            "listed" if report["availability"] == "available" else "unknown"
        ):
            raise ValueError("Reconciliation membership mismatch")
