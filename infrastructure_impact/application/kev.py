"""Pure, generation-bound KEV membership reports; no product-impact inference."""

import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from ..references.registry import KEV_ATTRIBUTION_URL, KEV_URL
from ..settings import PACKAGE

POLICY = dict(
    max_bytes=8_000_000, max_entries=20_000, fresh_for_seconds=129600, future_tolerance_seconds=300
)
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)


class KevUnavailable(ValueError):
    code = "kev_unavailable"


def _timestamp(value):
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ValueError("KEV timestamps require a valid date, time and timezone")
    return datetime.fromisoformat(value.upper().replace("Z", "+00:00"))


def _ids(values):
    return sorted({value for value in values if isinstance(value, str) and CVE.fullmatch(value)})


@lru_cache(maxsize=1)
def _validator():
    schema = json.loads((PACKAGE / "schemas/kev-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    checker = FormatChecker()

    @checker.checks("date-time", raises=ValueError)
    def timestamp_format(value):
        if isinstance(value, str):
            _timestamp(value)
        return True

    return Draft202012Validator(schema, format_checker=checker)


def validate_report(report: dict) -> None:
    """Validate the strict public shape and its internal membership identities."""
    try:
        _validator().validate(report)
    except ValidationError as error:
        raise ValueError(f"Invalid KEV report: {error.message}") from error
    index = report["listed_cve_ids"]
    listed = set(index)
    selection = report["selection"]
    requested = selection["requested_cve_ids"]
    effective = selection["effective_cve_ids"]
    if index != sorted(index) or requested != sorted(requested) or effective != sorted(effective):
        raise ValueError("KEV identity lists must be sorted and unique")
    if report["catalogue"] and report["catalogue"]["count"] != len(index):
        raise ValueError("KEV complete index must match retained catalogue count")
    if any(cid not in listed or entry["cveID"] != cid for cid, entry in report["entries"].items()):
        raise ValueError("KEV detailed identities must agree with the complete index")
    if set(selection["membership"]) != set(requested):
        raise ValueError("KEV membership must cover exactly the requested identities")
    availability = report["source"]["availability"]
    if availability != _availability(report, _timestamp(report["evaluated_at"])):
        raise ValueError("KEV availability must agree with verification at evaluation time")
    membership = {
        cid: ("listed" if cid in listed else "not_listed")
        if availability == "available"
        else "unknown"
        for cid in requested
    }
    if selection["membership"] != membership:
        raise ValueError("KEV membership must agree with availability and the complete index")
    expected = (
        [cid for cid in requested if selection["membership"][cid] == "listed"]
        if selection["kev_only"]
        else requested
    )
    if effective != expected or (
        selection["kev_only"] and report["source"]["availability"] != "available"
    ):
        raise ValueError("KEV effective identities must agree with selection")


def _availability(report, evaluated):
    source = report["source"]
    if source["configured"] is None:
        return "missing"
    if not source["configured"]:
        return "not_configured"
    if not source["enabled"]:
        return "disabled"
    if not report["catalogue"] or not source["checked_at"] or not source["latest_attempt"]:
        return "missing"
    try:
        checked = _timestamp(source["checked_at"])
        _timestamp(source["latest_attempt"]["checked_at"])
    except (ValueError, TypeError):
        return "missing"
    if source["latest_attempt"]["outcome"] != "ok":
        return "failed"
    age = (evaluated - checked).total_seconds()
    if age < -POLICY["future_tolerance_seconds"]:
        return "future"
    if age > POLICY["fresh_for_seconds"]:
        return "stale"
    return "available"


def _empty(generated_at, publication, *, configured, enabled):
    return dict(
        schema_version=1,
        publication=deepcopy(publication),
        generated_at=generated_at,
        evaluated_at=generated_at,
        source=dict(
            id="cisa-kev",
            retrieval_url=KEV_URL,
            catalogue_url=KEV_ATTRIBUTION_URL,
            configured=configured,
            enabled=enabled,
            availability="missing",
            latest_attempt=None,
            checked_at=None,
        ),
        catalogue=None,
        policy=dict(POLICY),
        listed_cve_ids=[],
        entries={},
        selection=dict(requested_cve_ids=[], effective_cve_ids=[], kev_only=False, membership={}),
    )


def build_report(
    source_input: dict, scope: list[str], *, publication: dict | None, generated_at: str
) -> dict:
    """Expose validated retained content, with details bounded by publication scope."""
    _timestamp(generated_at)
    configured = source_input.get("configured", False)
    enabled = source_input.get("enabled", configured)
    if type(configured) is not bool or type(enabled) is not bool:
        raise ValueError("Collected KEV configured and enabled flags must be booleans")
    report = _empty(
        generated_at,
        publication,
        configured=configured,
        enabled=enabled,
    )
    report["source"].update(
        checked_at=source_input.get("checked_at"),
        latest_attempt=deepcopy(source_input.get("latest_attempt")),
    )
    retained = source_input.get("retained")
    if retained is not None:
        catalogue = retained["catalogue"]
        if set(catalogue) != {
            "parser_version",
            "catalogue_version",
            "released_at",
            "count",
            "entries",
        }:
            raise ValueError("Invalid normalized KEV catalogue fields")
        report["catalogue"] = dict(
            version=catalogue["catalogue_version"],
            released_at=catalogue["released_at"],
            count=catalogue["count"],
            parser_version=catalogue["parser_version"],
            **{
                key: retained[key]
                for key in ("sha256", "revision_id", "source_observed_at", "parsed_at")
            },
        )
        report["entries"] = deepcopy(catalogue["entries"])
        report["listed_cve_ids"] = sorted(catalogue["entries"])
    # Validate the complete normalized catalogue, including entries outside scope.
    report["source"]["availability"] = _availability(report, _timestamp(generated_at))
    validate_report(report)
    cohort = set(_ids(scope))
    report["entries"] = {cid: entry for cid, entry in report["entries"].items() if cid in cohort}
    report = select_report(report, scope, evaluated_at=generated_at)
    validate_report(report)
    return report


def select_report(
    report: dict | None,
    requested: list[str],
    *,
    kev_only: bool = False,
    evaluated_at: str | None = None,
) -> dict:
    """Re-evaluate freshness without changing the publication's evidence or identity."""
    evaluation = (
        evaluated_at if evaluated_at is not None else datetime.now(timezone.utc).isoformat()
    )
    evaluated = _timestamp(evaluation)
    selected = (
        deepcopy(report)
        if report is not None
        else _empty(evaluation, None, configured=None, enabled=None)
    )
    availability = _availability(selected, evaluated)
    if kev_only and availability != "available":
        raise KevUnavailable("KEV membership is unavailable for a filtered selection")
    ids = _ids(requested)
    listed = set(selected["listed_cve_ids"])
    membership = {
        cid: ("listed" if cid in listed else "not_listed")
        if availability == "available"
        else "unknown"
        for cid in ids
    }
    selected["evaluated_at"] = evaluation
    selected["source"]["availability"] = availability
    selected["selection"] = dict(
        requested_cve_ids=ids,
        effective_cve_ids=[cid for cid in ids if membership[cid] == "listed"]
        if kev_only
        else ids.copy(),
        kev_only=kev_only,
        membership=membership,
    )
    return selected
