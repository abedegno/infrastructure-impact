"""Strict scope contracts for public, source-bound CVE research dossiers."""

import json
from collections.abc import Iterable
from copy import deepcopy
from functools import lru_cache
from hashlib import sha256

from jsonschema import Draft202012Validator

from ..domain import validator as advisory_validator
from ..settings import PACKAGE

LIMITS = {
    "inventory_verified": False,
    "independent_human_review_completed": False,
    "independent_release_availability_verified": False,
    "earliest_disclosure_established": False,
    "vendor_rate": None,
    "verified_fix_delay_days": None,
    "concealment_established": False,
}
SELECTION_LIMITATION = (
    "Retrospective purposive selection of retained publisher statements; "
    "not representative sampling or a verified inventory."
)


@lru_cache(maxsize=2)
def _validator(name):
    schema = json.loads((PACKAGE / "schemas" / f"{name}-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=advisory_validator().format_checker)


def fingerprint(value: dict) -> str:
    """Hash all fields as sorted-key, compact, finite UTF-8 JSON."""
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()


def _scope_definition(value: dict | None = None) -> dict:
    """Copy and validate scope, including bindings independent of current evidence."""
    value = (
        deepcopy(value)
        if value is not None
        else json.loads((PACKAGE / "resources/research-dossiers.json").read_text())
    )
    _validator("research-dossier-definition").validate(value)
    pilot = json.loads((PACKAGE / "resources/build-pilot.json").read_text())
    cases = json.loads((PACKAGE / "resources/disclosure-cases.json").read_text())
    targets = {target["id"]: target for target in pilot["targets"]}
    cases = {case["id"]: case for case in cases["cases"]}
    identities, cves = set(), set()
    for entry in value["entries"]:
        if entry["id"] in identities or entry["cve_id"] in cves:
            raise ValueError("Dossier IDs and CVEs must be unique")
        identities.add(entry["id"])
        cves.add(entry["cve_id"])
        for target_id in entry["build_target_ids"]:
            if target_id not in targets or targets[target_id]["cve_id"] != entry["cve_id"]:
                raise ValueError("Dossier build target must exist and bind the same CVE")
        for case_id in entry["case_ids"]:
            if case_id not in cases or entry["cve_id"] not in cases[case_id]["cve_ids"]:
                raise ValueError("Dossier case must exist and contain the same CVE")
    return value


def definition(value: dict | None = None) -> dict:
    """Return an independent, validated bundled or caller-supplied scope."""
    return _scope_definition(value)


def validate_report(report: dict) -> None:
    """Reject unreviewed fields and attempts to unlock public conclusions."""
    _validator("research-dossiers").validate(report)


def research_dossiers(data: dict, definition: dict | None = None) -> dict:
    """Stage declared scope without evidence; projection is added separately."""
    spec = _scope_definition(definition)
    pilot = json.loads((PACKAGE / "resources/build-pilot.json").read_text())
    dossiers = []
    for entry in spec["entries"]:
        dossiers.append(
            dict(
                id=entry["id"],
                cve_id=entry["cve_id"],
                scope=dict(
                    build_target_ids=entry["build_target_ids"],
                    case_ids=entry["case_ids"],
                    comparison_role=pilot["role"] if entry["build_target_ids"] else None,
                    selected_vendor=None,
                    selection_limitation=SELECTION_LIMITATION,
                ),
                comparison_targets=[],
                chronology=dict(
                    publisher_claims=[], local_observations=[], documentation_claims=[]
                ),
                disclosure_context=[],
                evidence_gaps=[],
                sources=[],
            )
        )
    report = dict(
        schema_version=1,
        definition_version=spec["version"],
        definition_sha256=fingerprint(spec),
        vendors=deepcopy(data.get("vendors", {})),
        limits=dict(LIMITS),
        dossiers=dossiers,
        method="Declared CVE research scope with no projected evidence. Retrospective purposive "
        "selection cannot establish prior affectedness, historical availability, first "
        "disclosure, vendor rates, verified fix delays or concealment.",
    )
    validate_report(report)
    return report


def select_research_dossiers(
    report: dict | None, cohort: Iterable[str], vendor: str | None = None
) -> dict | None:
    """Preserve absent old-generation reports; selection is integrated separately."""
    if report is None:
        return None
    raise NotImplementedError("Research dossier selection is not integrated yet")
