"""Derived, generation-bound inventories; observed versions are not denominators."""

import json
from copy import deepcopy
from decimal import Decimal

from ..exports import csv_table
from .release_catalogue import CAVEAT, _original, _releases
from .release_reliability import validate_report

FIELDS = [
    "row_type",
    "publication_id",
    "generated_at",
    "catalogue_sha256",
    "vendor",
    "train",
    "model",
    "year",
    "metric",
    "payload",
]


def build_coverage(report):
    """Explain the accepted facts' date, provenance and scope gaps without new claims."""
    validate_report(report)
    result = {
        key: deepcopy(report[key])
        for key in (
            "publication",
            "generated_at",
            "dataset_observed_at",
            "catalogue_sha256",
            "availability",
        )
    }
    result.update(
        config=deepcopy(report["config"]),
        method=deepcopy(report["method"]),
        schema_version=1,
        review_status=report["validation"]["review_status"],
        sources=deepcopy((report["catalogue"] or {}).get("sources", [])),
        trains=[],
        limitations=[
            CAVEAT,
            "Inventory lists contain observed versions, not a complete release denominator.",
            "Undated versions cannot be allocated to a calendar year.",
            "Dates and original evidence resolve gaps only for the explicitly stated model.",
            "Independent human review pending.",
        ],
    )
    if report["availability"] == "unavailable":
        return result
    sources = {s["source_id"]: s for s in result["sources"]}
    cat = report["catalogue"]
    for train in report["config"]["trains"]:

        def same(fact):
            return (fact["vendor"], fact["train"], fact.get("family", train["family"])) == (
                train["vendor"],
                train["train"],
                train["family"],
            )

        releases = _releases(cat, train)
        notices = [n for n in cat["notices"] if same(n)]
        models = []
        for model in train["platforms"]:
            scoped = [r for r in releases if model in r["platforms_stated"]]
            known = {r["version"] for r in scoped}
            dated = {r["version"] for r in scoped if r["release_date"]}
            original = {r["version"] for r in scoped if r["release_date"] and _original(r, sources)}
            announced = {r["version"] for r in scoped if r["announcement_date"]}
            models.append(
                dict(
                    model=model,
                    observed_versions=sorted(known),
                    dated_original_versions=sorted(original),
                    dated_research_only_versions=sorted(dated - original),
                    undated_versions=sorted(known - dated),
                    announcement_only_versions=sorted(announced - dated),
                )
            )
        result["trains"].append(
            dict(
                vendor=train["vendor"],
                family=train["family"],
                train=train["train"],
                models=models,
                unbound_versions=sorted(
                    {r["version"] for r in releases if not r["platforms_stated"]}
                ),
                outside_cohort_versions=sorted(
                    {
                        r["version"]
                        for r in releases
                        if r["platforms_stated"]
                        and not set(r["platforms_stated"]) & set(train["platforms"])
                    }
                ),
                notice_date_unknown_ids=sorted(
                    {n["notice_id"] for n in notices if n["notice_date"] is None}
                ),
                notice_model_unresolved_ids=sorted(
                    {n["notice_id"] for n in notices if not n["platforms_stated"]}
                ),
                release_evidence=deepcopy([r for r in cat["releases"] if same(r)]),
                notice_evidence=deepcopy(notices),
                statement_evidence=deepcopy([f for f in cat["statements"] if same(f)]),
                coverage_judgements=deepcopy([f for f in cat["coverage"] if same(f)]),
                respin_evidence=deepcopy([f for f in report["respins"] if same(f)]),
                periods=deepcopy(
                    [
                        a
                        for a in report["annual"]
                        if a["vendor"] == train["vendor"] and a["train"] == train["train"]
                    ]
                ),
            )
        )
    return result


def csv_export(coverage, *, max_bytes=None):
    """Export the derived view with source references and spreadsheet-safe cells."""
    identity = dict(
        publication_id=(coverage["publication"] or {}).get("id"),
        generated_at=coverage["generated_at"],
        catalogue_sha256=coverage["catalogue_sha256"],
    )

    def payload(value):
        # Match the project's exact finite-number CSV tokens across Python/JS.
        if isinstance(value, dict):
            return (
                "{"
                + ",".join(
                    json.dumps(k, ensure_ascii=False) + ":" + payload(value[k])
                    for k in sorted(value)
                )
                + "}"
            )
        if isinstance(value, list):
            return "[" + ",".join(payload(v) for v in value) + "]"
        if type(value) is float:
            if value.is_integer():
                return str(int(value))
            return format(Decimal.from_float(value), "f").rstrip("0")
        return json.dumps(value, ensure_ascii=False, allow_nan=False)

    def rows():
        yield identity | dict(
            row_type="context",
            payload=payload(
                {k: v for k, v in coverage.items() if k not in {"sources", "trains", "limitations"}}
            ),
        )
        for train in coverage["trains"]:
            row = identity | dict(vendor=train["vendor"], train=train["train"])
            for model in train["models"]:
                yield row | dict(
                    row_type="model_inventory", model=model["model"], payload=payload(model)
                )
            for period in train["periods"]:
                for metric, fact in period["metrics"].items():
                    yield row | dict(
                        row_type="period_metric",
                        year=period["year"],
                        metric=metric,
                        payload=payload(
                            {k: v for k, v in period.items() if k != "metrics"}
                            | {"metric": metric, **fact}
                        ),
                    )
            yield row | dict(
                row_type="train_gaps",
                payload=payload(
                    {
                        k: v
                        for k, v in train.items()
                        if k
                        not in {
                            "models",
                            "periods",
                            "release_evidence",
                            "notice_evidence",
                            "statement_evidence",
                            "coverage_judgements",
                            "respin_evidence",
                        }
                    }
                ),
            )
            for kind in (
                "release_evidence",
                "notice_evidence",
                "statement_evidence",
                "coverage_judgements",
                "respin_evidence",
            ):
                for fact in train[kind]:
                    yield row | dict(
                        row_type="coverage_judgement" if kind == "coverage_judgements" else kind,
                        payload=payload(fact),
                    )
        for source in coverage["sources"]:
            yield identity | dict(
                row_type="source", vendor=source["vendor"], payload=payload(source)
            )
        for limitation in coverage["limitations"]:
            yield identity | dict(row_type="limitation", payload=limitation)

    return csv_table(FIELDS, rows, max_bytes=max_bytes)
