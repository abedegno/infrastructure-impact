"""Customer view composed only from selected public study and release facts."""

import copy
import json

from ..exports import SWITCHING_FIELDS, _switching_csv_rows, csv_table
from . import switching_evidence as contracts
from . import switching_releases

LIMITATIONS = [
    "Study counts, source-specific severity and KEV retain the selected study denominator; "
    "release context does not add affected CVEs or remediation events.",
    "History is evidence for the selected advisory CVE cohort; software releases need not "
    "have been published in that advisory window.",
    "Vendor-reported fixed CVEs and affected-scope-linked CVEs are separate observations. "
    "Fixed-only context does not establish affectedness, model applicability or an upgrade event.",
    "Only reported_release_dates are software dates. Remediation availability, advisory notice "
    "and bundle member publication dates retain their original meanings.",
    "Missing release links or unavailable history are unknown evidence, not zero fixes. "
    "The reviewed sources are incomplete and release coverage denominators remain unknown.",
    "SKU minimum versions and bundle membership are literal context; no version ordering, "
    "model applicability, deployed exposure, fix delay or security ranking is inferred.",
]


def validate(envelope):
    """Closed public DTOs must share generation, study definition, bounds and selection."""
    contracts._validate(envelope, "customer-comparison-v1.json")
    study, history = envelope["study"], envelope["release_history"]
    identity = {k: envelope[k] for k in ("publication", "generated_at")}
    contracts._publication(study, **identity)
    switching_releases.validate_report(history, **identity)
    if (
        history["selection"] != study["selection"]
        or history["observation_end"] != study["observation_end"]
        or history["definition_sha256"] != study["selection"]["definition_sha256"]
        or contracts.definition_sha256(study["definition"]) != history["definition_sha256"]
    ):
        raise ValueError("Customer study and history selection differ")
    return envelope


def build(study_summary, selected_history):
    """Preserve validated selection facts; never select again or derive another denominator."""
    result = dict(
        schema_version=1,
        publication=study_summary["publication"],
        generated_at=study_summary["generated_at"],
        study=study_summary,
        release_history=selected_history,
        limitations=LIMITATIONS,
    )
    validate(result)
    return copy.deepcopy(result)


CUSTOMER_FIELDS = [
    "row_type",
    "study_representation",
    "study_schema_version",
    *SWITCHING_FIELDS,
    "family",
    "release_id",
    "version",
    "reported_release_dates",
    "vendor_reported_fixed_cve_count",
    "affected_scope_cve_count",
    "vendor_reported_fixed_cve_ids",
    "affected_scope_cve_ids",
    "reference_kind",
    "advisory_id",
    "cve_id",
    "claim_id",
    "source_id",
    "coverage_kind",
    "details",
    "limitations",
]


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _csv_rows(envelope):
    study, history = envelope["study"], envelope["release_history"]
    common = dict(
        study_representation=study["representation"],
        study_schema_version=study["schema_version"],
        publication_id=(envelope["publication"] or {}).get("id"),
        publication_generated_at=envelope["generated_at"],
        totals_basis="repeated_totals_nonadditive",
        scope_level=study["selection"]["scope_level"],
        window=study["selection"]["requested_window"],
        limitations=_json(envelope["limitations"]),
    )

    def row(kind, **values):
        return {**common, "row_type": kind, **values}

    study_rows = {item["vendor"]: item for item in study["rows"]}
    for values in _switching_csv_rows(study):
        facets = dict(zip(SWITCHING_FIELDS, values))
        yield row("study_summary", **facets, details=_json(study_rows[facets["vendor"]]))
    for release in history["releases"]:
        release_fields = {
            key: _json(release[key]) if isinstance(release[key], list) else release[key]
            for key in (
                "vendor",
                "family",
                "release_id",
                "version",
                "reported_release_dates",
                "vendor_reported_fixed_cve_count",
                "affected_scope_cve_count",
                "vendor_reported_fixed_cve_ids",
                "affected_scope_cve_ids",
            )
        }
        for ref in release["references"] or [None]:
            yield row(
                "release_reference",
                **release_fields,
                reference_kind=ref["kind"] if ref else "history_context",
                **{key: ref[key] if ref else None for key in ("advisory_id", "cve_id", "claim_id")},
                details=_json(
                    dict(reference=ref, history=release["history"], issues=release["issues"])
                ),
            )
    for bundle in history["bundles"]:
        yield row("bundle_context", vendor=bundle["vendor"], details=_json(bundle))
    for support in history["platform_support"]:
        yield row(
            "platform_support",
            vendor=support["vendor"],
            source_id=support["source_id"],
            details=_json(support),
        )
    for selected in study["rows"]:
        for source in selected["coverage"]["sources"]:
            yield row(
                "source_coverage",
                vendor=selected["vendor"],
                coverage_kind="study",
                details=_json(source),
            )
    for source in study.get("sources", []):
        yield row("source_coverage", coverage_kind="study_claim", details=_json(source))
    for source in history["sources"]:
        yield row(
            "source_coverage",
            source_id=source["source_id"],
            coverage_kind="release_history",
            details=_json(source),
        )
    # Include the unavailable/unknown coverage state even when no sources or releases exist.
    yield row(
        "source_coverage",
        coverage_kind="release_history_summary",
        details=_json(
            dict(
                availability=history["availability"],
                coverage=history["coverage"],
                diagnostics=history["diagnostics"],
                method=history["method"],
            )
        ),
    )


def csv_export(envelope, *, max_bytes=None):
    """JSON-equivalent facts with typed, nonadditive rows and spreadsheet-safe cells."""
    validate(envelope)
    return csv_table(CUSTOMER_FIELDS, lambda: _csv_rows(envelope), max_bytes=max_bytes)
