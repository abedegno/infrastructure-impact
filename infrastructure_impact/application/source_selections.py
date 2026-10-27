"""Public representation-choice metadata linked to current published evidence."""

import json
from functools import lru_cache

from jsonschema import Draft202012Validator, FormatChecker

from ..settings import PACKAGE
from ..source_policy import allowed


@lru_cache(maxsize=1)
def validator():
    schema = json.loads((PACKAGE / "schemas/source-selection-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def public_selections(values, records):
    """Only official representation metadata linked to a published selected capture."""
    import re

    known = {(r["vendor"], r["source_url"], r["sha256"]) for r in records}
    result = []
    for value in values:
        vendor = value.get("vendor")
        views = value.get("views", [])
        selected = [v for v in views if v.get("selected") is True]
        if (
            len(selected) != 1
            or (vendor, selected[0].get("source_url"), selected[0].get("source_sha256"))
            not in known
        ):
            continue
        if not allowed(value.get("requested_url", ""), vendor):
            continue
        if any(
            not allowed(v.get("source_url", ""), vendor)
            or not re.fullmatch(r"[a-f0-9]{64}", v.get("source_sha256", ""))
            for v in views
        ):
            continue
        issues = value.get("unavailable", [])
        if any(not allowed(v.get("source_url", ""), vendor) for v in issues):
            continue
        result.append(
            {
                **{
                    k: value[k]
                    for k in ("vendor", "requested_url", "selected_at", "reason", "meaning")
                },
                "views": [
                    {
                        k: view[k]
                        for k in (
                            "source_url",
                            "source_sha256",
                            "source_observed_at",
                            "source_format",
                            "adapter_version",
                            "normalized_statements",
                            "selected",
                        )
                    }
                    for view in views
                ],
                "unavailable": [
                    {k: issue[k] for k in ("source_url", "error_code")} for issue in issues
                ],
            }
        )
    for row in result:
        validator().validate(row)
    return result
