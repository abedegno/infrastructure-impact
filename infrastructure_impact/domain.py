"""The normalized advisory contract and cross-field invariants."""

import json
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA_PATH = Path(__file__).parent / "schemas/advisory-v2.json"


class NormalizationError(ValueError):
    """A source adapter violated a shared normalization contract."""


@lru_cache(maxsize=1)
def validator():
    schema = json.loads(SCHEMA_PATH.read_text())
    Draft202012Validator.check_schema(schema)
    formats = FormatChecker()

    @formats.checks("date", raises=ValueError)
    def is_date(value):
        return not isinstance(value, str) or date.fromisoformat(value) is not None

    @formats.checks("date-time", raises=ValueError)
    def is_datetime(value):
        if not isinstance(value, str):
            return True
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return "T" in value and parsed.tzinfo is not None

    @formats.checks("local-date-time", raises=ValueError)
    def is_local_datetime(value):
        if not isinstance(value, str):
            return True
        parsed = datetime.fromisoformat(value)
        return "T" in value and parsed.tzinfo is None

    return Draft202012Validator(schema, format_checker=formats)


def validate_advisory(document, *, vendor=None, source_url=None):
    error = next(validator().iter_errors(document), None)
    if error:
        location = "/" + "/".join(str(part) for part in error.absolute_path)
        raise NormalizationError(f"Normalized advisory {location}: {error.message}")
    if vendor is not None and document["vendor"] != vendor:
        raise NormalizationError("Plugin returned a different vendor identity")
    if source_url is not None and document["source_url"] != source_url:
        raise NormalizationError("Plugin returned a different source URL")
    url = urlsplit(document["source_url"])
    if not url.hostname or url.username or url.password or url.scheme != "https":
        raise NormalizationError("Source must be an absolute HTTPS URL without credentials")
    seen = set()
    for assessment in document["assessments"]:
        if assessment["cve_id"] not in document["cves"]:
            raise NormalizationError("Assessment CVE outside advisory scope")
        key = assessment["cve_id"], assessment["product_id"]
        if key in seen:
            raise NormalizationError(
                "Duplicate CVE/product identity; resolve or retain a conflicting status"
            )
        seen.add(key)
    return document


@lru_cache(maxsize=1)
def component_inventory_validator():
    schema = json.loads((SCHEMA_PATH.parent / "component-inventory-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_component_inventory(document):
    error = next(component_inventory_validator().iter_errors(document), None)
    if error:
        location = "/" + "/".join(str(part) for part in error.absolute_path)
        # Source text or private extension values must not enter collector logs.
        raise NormalizationError(f"Component reference {location}: invalid {error.validator}")
    return document
