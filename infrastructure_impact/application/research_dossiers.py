"""Strict scope contracts for public, source-bound CVE research dossiers."""

import json
from collections.abc import Iterable
from copy import deepcopy
from functools import lru_cache
from hashlib import sha256

from jsonschema import Draft202012Validator

from ..domain import validator as advisory_validator
from ..settings import PACKAGE
from .build_pilot import matches_target_reference

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


def _pick(value, keys):
    """Copy only named public properties, including nested scalar lists."""
    return {key: deepcopy(value[key]) for key in keys if key in value}


def _distinct(rows):
    seen = set()
    result = []
    for row in rows:
        key = fingerprint(row)
        if key not in seen:
            seen.add(key)
            result.append(row)
    return result


def _precision(value):
    if value is None:
        return "unsupplied"
    checker = advisory_validator().format_checker
    for label, format_name in (
        ("date", "date"),
        ("instant", "date-time"),
        ("local_datetime", "local-date-time"),
    ):
        if checker.conforms(value, format_name):
            return label
    return "unparsed"


def _check(value, include_url=False):
    result = dict(
        outcome=value.get("outcome", "not_checked"),
        checked_at=value.get("checked_at"),
        error_code=value.get("error_code"),
    )
    if include_url and "source_url" in value:
        result["source_url"] = value["source_url"]
    return result


class _Evidence:
    """Per-dossier source union and chronology; input dictionaries are never retained."""

    def __init__(self):
        self.sources = {}
        self.chronology = dict(publisher_claims=[], local_observations=[], documentation_claims=[])

    def source(self, vendor, reference, locator=None):
        url = reference["source_url"]
        digest = reference.get("source_sha256", reference.get("sha256"))
        identity = fingerprint([vendor, url, digest])
        row = self.sources.setdefault(
            identity,
            dict(
                id=identity,
                vendor=vendor,
                source_url=url,
                source_sha256=digest,
                locators=[],
                observations=[],
            ),
        )
        if locator not in row["locators"]:
            row["locators"].append(locator)
        observed = reference.get("source_observed_at", reference.get("observed_at"))
        if observed is not None and observed not in row["observations"]:
            row["observations"].append(observed)
        for key in ("adapter_version", "revision_id", "evidence_id"):
            if reference.get(key) is not None:
                row.setdefault(key, reference[key])
        return identity

    def publisher(self, source_id, field, value, locator=None, kind=None):
        row = dict(
            source_id=source_id,
            field=field,
            value=value,
            precision=_precision(value),
            locator=locator,
        )
        if kind is not None:
            row["kind"] = kind
        self.chronology["publisher_claims"].append(row)

    def capture(self, source_id, reference, locator=None, kind="source_capture", **extra):
        value = reference.get("source_observed_at", reference.get("observed_at"))
        if value is not None:
            self.chronology["local_observations"].append(
                dict(
                    source_id=source_id,
                    value=value,
                    precision="instant",
                    kind=kind,
                    locator=locator,
                    **_pick(reference, ("revision_id", "evidence_id")),
                    **extra,
                )
            )

    def record(self, vendor, record, locator=None):
        identity = self.source(vendor, record, locator)
        for field in ("published_at", "updated_at", "reported_fix_date"):
            self.publisher(identity, field, record.get(field), locator)
        self.capture(identity, record, locator)
        return identity

    def finish(self):
        for source in self.sources.values():
            source["locators"].sort(key=lambda value: (value is not None, value or ""))
            source["observations"].sort()
        return (
            [self.sources[key] for key in sorted(self.sources)],
            {key: _distinct(rows) for key, rows in self.chronology.items()},
        )


def _resolve(data, target, reference, cve_id):
    for record in data.get("records", []):
        if (
            record["source_url"] != reference["source_url"]
            or record["sha256"] != reference["source_sha256"]
        ):
            continue
        for claim in record.get("assessments", []):
            locators = [
                claim.get("evidence_locator"),
                *(e.get("source_locator") for e in claim.get("exposure", [])),
            ]
            if (
                claim["cve_id"] == cve_id
                and matches_target_reference(record, claim, target)
                and reference.get("locator") in locators
            ):
                yield record, claim


def _statement(claim, source_id):
    row = _pick(
        claim,
        (
            "product_id",
            "product",
            "product_family",
            "product_context",
            "status",
            "scope",
            "source_statuses",
            "platforms",
            "evidence_locator",
        ),
    )
    row["source_id"] = source_id
    for key, properties in (
        (
            "versions",
            ("version", "expression", "status", "lessThan", "lessThanOrEqual", "versionType"),
        ),
        (
            "remediations",
            (
                "category",
                "details",
                "availability",
                "source_locator",
                "date",
                "url",
                "restart_required",
                "entitlements",
                "source_scope",
            ),
        ),
        ("exposure", ("category", "details", "source_locator")),
    ):
        row[key] = [_pick(item, properties) for item in claim.get(key, [])]
    return row


def _target(data, target, pilot, cve_id, evidence, gaps):
    fields, statements = [], []
    anchors = {
        (id(record), id(claim))
        for field in pilot["fields"]
        if field["field"] == "firmware_reference"
        for reference in field["evidence"]
        for record, claim in _resolve(data, target, reference, cve_id)
        if claim.get("evidence_locator") == reference.get("locator")
    }
    for field in pilot["fields"]:
        references = []
        for reference in field["evidence"]:
            matches = [
                (record, claim)
                for record, claim in _resolve(data, target, reference, cve_id)
                if (id(record), id(claim)) in anchors
            ]
            if not matches:
                continue
            record = matches[0][0]
            source_id = evidence.record(target["vendor"], record, reference.get("locator"))
            evidence.source(target["vendor"], reference, reference.get("locator"))
            evidence.capture(source_id, reference, reference.get("locator"))
            references.append(
                dict(
                    source_id=source_id,
                    locator=reference.get("locator"),
                    observed_at=reference.get("observed_at"),
                )
            )
            if field["field"] == "firmware_reference":
                for record, claim in matches:
                    if claim.get("evidence_locator") == reference.get("locator"):
                        statements.append(
                            _statement(
                                claim,
                                evidence.record(
                                    target["vendor"], record, claim.get("evidence_locator")
                                ),
                            )
                        )
        # Aggregated text can contain a distinct contribution from each pilot
        # reference. Never retain it when any contributing reference is missing.
        known = (
            field["state"] == "publisher_statement"
            and bool(references)
            and len(references) == len(field["evidence"])
        )
        fields.append(
            dict(
                field=field["field"],
                state="publisher_statement" if known else "unknown",
                value=field["value"] if known else None,
                evidence=_distinct(references) if known else [],
            )
        )
        if not known:
            gaps.append(
                dict(
                    owner_kind="target",
                    owner_id=target["id"],
                    field_or_question=field["field"],
                    evidence_sought=f"Retained evidence for {field['field']} on "
                    f"{target['product_literal']} {target['firmware_build']}",
                    access_state="not_established",
                )
            )
    return dict(
        target_id=target["id"],
        vendor=target["vendor"],
        product=target["product_literal"],
        firmware_build=target["firmware_build"],
        statements=_distinct(statements),
        fields=fields,
        source_check=_check(pilot.get("source_check", {})),
    )


def _case(data, declared, case, cve_id, evidence, gaps):
    vendor = declared["vendor"]
    urls = set(declared["advisory_urls"] + declared["release_source_leads"])
    source_ids, current_refs = set(), []
    earlier = []
    for doc in case.get("earlier_dated_vendor_documents", []):
        if cve_id not in doc["cve_ids"] or doc["source_url"] not in urls:
            continue
        sid = evidence.source(vendor, doc)
        source_ids.add(sid)
        current_refs.append(doc)
        evidence.capture(sid, doc)
        evidence.publisher(sid, "published_at", doc.get("publisher_published_at"))
        earlier.append(
            dict(
                source_id=sid,
                **_pick(
                    doc,
                    ("publisher_published_at", "date_basis", "product_labels", "interpretation"),
                ),
            )
        )
    for history in case.get("publisher_document_histories", []):
        if history["vendor"] != vendor or history["source_url"] not in urls:
            continue
        # A shared document's undifferentiated initial entry is contextual, while
        # CVE-specific edits are projected only for this dossier.
        events = [
            event
            for event in history["events"]
            if not event["cve_ids"] or cve_id in event["cve_ids"]
        ]
        if not events:
            continue
        current_refs.append(history)
        sid = evidence.source(vendor, history)
        source_ids.add(sid)
        evidence.capture(sid, history)
        for event in events:
            locator = event.get("source_locator")
            evidence.source(vendor, history, locator)
            value = event["publisher_date"]
            evidence.chronology["documentation_claims"].append(
                dict(
                    source_id=sid,
                    value=value,
                    precision=_precision(value),
                    kind=event["kind"],
                    locator=locator,
                )
            )
    for ref in case.get("evidence", []):
        if ref["source_url"] not in urls:
            continue
        records = [
            record
            for record in data.get("records", [])
            if record["vendor"] == vendor
            and record["source_url"] == ref["source_url"]
            and record["sha256"] == ref["source_sha256"]
            and record.get("document_status") != "draft"
            and cve_id in record["cves"]
        ]
        # Single-CVE case evidence is already scoped. Shared-case references need
        # a retained CVE binding rather than inheriting the other CVE's evidence.
        if not records and len(declared["cve_ids"]) > 1:
            continue
        sid = evidence.source(vendor, ref)
        source_ids.add(sid)
        current_refs.append(ref)
        if records:
            for record in records:
                evidence.record(vendor, record)
        else:
            evidence.capture(sid, ref)
            for source_field, field in (
                ("publisher_published_at", "published_at"),
                ("publisher_reported_fix_date", "reported_fix_date"),
            ):
                if source_field in ref:
                    evidence.publisher(sid, field, ref[source_field])
    checks = [
        _check(check, True)
        for check in case.get("source_checks", [])
        if check.get("source_url") in urls
    ]
    remaining = list(case.get("missing_evidence", declared["missing_evidence"]))
    alternatives = list(case.get("alternative_explanations", declared["alternative_explanations"]))
    disposition = None
    for review in data.get("disclosure_review", {}).get("cases", []):
        if (
            review["vendor"] != vendor
            or declared["id"] not in review.get("related_case_ids", [])
            or cve_id not in review["cve_ids"]
        ):
            continue
        # Re-run the existing byte-set guard, never inherit a nested disposition.
        # The review's source set must still be retained by this case.
        review_urls = {ref["source_url"] for ref in review.get("evidence", [])}
        if not review_urls & {ref["source_url"] for ref in current_refs}:
            continue
        from .investigations import investigation

        candidate = investigation(
            dict(**_pick(review, ("vendor", "kind", "cve_ids", "details")), evidence=current_refs)
        )
        if candidate is not None:
            disposition = _pick(
                candidate,
                (
                    "id",
                    "version",
                    "reviewed_at",
                    "review_method",
                    "source_state",
                    "disposition",
                    "summary",
                    "search_scope",
                    "remaining_evidence",
                    "uncollected_search_leads",
                    "independent_human_review_completed",
                    "concealment",
                ),
            )
            disposition["source_ids"] = sorted(source_ids)
            remaining.extend(candidate["remaining_evidence"])
            if set(review["cve_ids"]) == {cve_id}:
                alternatives.extend(review.get("alternative_explanations", []))
            break
    for question in dict.fromkeys(remaining):
        gaps.append(
            dict(
                owner_kind="case",
                owner_id=declared["id"],
                field_or_question=question,
                evidence_sought=question,
                access_state="not_established",
            )
        )
    retained_urls = {evidence.sources[sid]["source_url"] for sid in source_ids}
    lead_urls = list(declared["release_source_leads"])
    if disposition:
        lead_urls.extend(disposition["uncollected_search_leads"])
    for url in dict.fromkeys(lead_urls):
        if url in retained_urls:
            continue
        check = next((row for row in checks if row["source_url"] == url), None)
        gaps.append(
            dict(
                owner_kind="case",
                owner_id=declared["id"],
                field_or_question="Uncollected source lead",
                evidence_sought=url,
                access_state=check["outcome"]
                if check and check["outcome"] != "success"
                else "uncollected_lead",
            )
        )
    return dict(
        case_id=declared["id"],
        vendor=vendor,
        status=case.get("status", "incomplete_evidence"),
        product_scope=declared["product_scope"],
        question=declared["question"],
        source_ids=sorted(source_ids),
        investigation=disposition,
        earlier_documents=earlier,
        source_checks=_distinct(checks),
        missing_evidence=list(dict.fromkeys(remaining)),
        alternative_explanations=list(dict.fromkeys(alternatives)),
        release_source_state=case.get(
            "release_source_state",
            "leads_only_not_verified" if declared["release_source_leads"] else "not_identified",
        ),
    )


def _timeline(data, cve_id, bindings, evidence):
    timeline = data.get("timeline", {})
    for event in timeline.get("events", []):
        if (
            event["cve_id"] != cve_id
            or (event["vendor"], event["source_url"]) not in bindings
            or event.get("document_status") == "draft"
        ):
            continue
        sid = evidence.source(event["vendor"], event)
        evidence.capture(
            sid,
            event,
            kind=event["kind"],
            **_pick(event, ("event_id", "history_truncated", "events_truncated")),
            **{
                key: timeline[key]
                for key in ("history_truncated", "events_truncated")
                if key in timeline and key not in event
            },
        )
        for source_field, field in (
            ("publisher_published_at", "published_at"),
            ("publisher_updated_at", "updated_at"),
            ("publisher_reported_fix_date", "reported_fix_date"),
        ):
            if source_field in event:
                evidence.publisher(sid, field, event[source_field], kind=event["kind"])


def research_dossiers(data: dict, definition: dict | None = None) -> dict:
    """Derive qualified evidence from retained public inputs without side effects."""
    from .build_pilot import build_pilot

    spec = _scope_definition(definition)
    pilot = json.loads((PACKAGE / "resources/build-pilot.json").read_text())
    declared_targets = {target["id"]: target for target in pilot["targets"]}
    declared_cases = {
        case["id"]: case
        for case in json.loads((PACKAGE / "resources/disclosure-cases.json").read_text())["cases"]
    }
    fallback = build_pilot({"records": []})
    pilots = {
        target["id"]: target
        for target in data.get("product_cohorts", {}).get("build_pilot", fallback)["targets"]
    }
    fallback_targets = {target["id"]: target for target in fallback["targets"]}
    cases = {case["id"]: case for case in data.get("casefiles", {}).get("cases", [])}
    dossiers = []
    for entry in spec["entries"]:
        evidence, gaps, targets, contexts, bindings = _Evidence(), [], [], [], set()
        for target_id in entry["build_target_ids"]:
            target = declared_targets[target_id]
            current = pilots.get(target_id, fallback_targets[target_id])
            if current["vendor"] != target["vendor"]:
                current = fallback_targets[target_id]
            row = _target(data, target, current, entry["cve_id"], evidence, gaps)
            targets.append(row)
            if row["statements"]:
                bindings.add((target["vendor"], target["source_url"]))
        for case_id in entry["case_ids"]:
            declared = declared_cases[case_id]
            case = cases.get(case_id, {})
            if case and (
                case["vendor"] != declared["vendor"] or entry["cve_id"] not in case["cve_ids"]
            ):
                case = {}
            contexts.append(_case(data, declared, case, entry["cve_id"], evidence, gaps))
            bindings.update(
                (declared["vendor"], url)
                for url in declared["advisory_urls"] + declared["release_source_leads"]
            )
        _timeline(data, entry["cve_id"], bindings, evidence)
        sources, chronology = evidence.finish()
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
                comparison_targets=targets,
                chronology=chronology,
                disclosure_context=contexts,
                evidence_gaps=_distinct(gaps),
                sources=sources,
            )
        )
    report = dict(
        schema_version=1,
        definition_version=spec["version"],
        definition_sha256=fingerprint(spec),
        vendors=deepcopy(data.get("vendors", {})),
        limits=dict(LIMITS),
        dossiers=dossiers,
        method="Qualified retained publisher statements and source-bound case context. "
        "Publisher dates, local observations and documentation claims retain separate meanings. "
        "Retrospective purposive selection cannot establish prior affectedness, historical "
        "availability, first disclosure, vendor rates, verified fix delays or concealment.",
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
