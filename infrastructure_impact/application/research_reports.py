"""Validation for the public family, readiness and fix-lead contracts."""

import json
from functools import lru_cache

from jsonschema import Draft202012Validator, FormatChecker

from ..settings import PACKAGE

REPORTS = ("family_completeness", "comparison_readiness", "fix_leads", "component_studies")


@lru_cache(maxsize=4)
def validator(name):
    if name not in REPORTS:
        raise ValueError("Unknown research report")
    schema = json.loads((PACKAGE / "schemas" / (name.replace("_", "-") + "-v1.json")).read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate(data):
    for name in REPORTS:
        validator(name).validate(data[name])
