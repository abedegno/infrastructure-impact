"""Strict, bounded CISA KEV catalogue parsing; no vendor affectedness inference."""

import re
from datetime import date, datetime

from ..application.strict_json import loads

MAX_BYTES = 8_000_000
MAX_ENTRIES = 20_000
REQUIRED = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
)
OPTIONAL_STRINGS = ("knownRansomwareCampaignUse", "forensicTriage", "notes")


def parse(raw: bytes) -> dict:
    data = loads(raw, budget=MAX_BYTES, label="KEV catalogue")
    if not isinstance(data, dict):
        raise ValueError("KEV catalogue must be an object")
    rows = data.get("vulnerabilities")
    version = data.get("catalogVersion")
    released = data.get("dateReleased")
    if (
        not isinstance(rows, list)
        or not 1 <= len(rows) <= MAX_ENTRIES
        or type(data.get("count")) is not int
        or data["count"] != len(rows)
        or not isinstance(version, str)
        or not version.strip()
    ):
        raise ValueError("Expected complete, nonempty KEV catalogue with a version and exact count")
    if not isinstance(released, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
        released,
    ):
        raise ValueError("KEV release timestamp must include a timezone")
    datetime.fromisoformat(released.replace("Z", "+00:00"))
    entries = {}
    for row in rows:
        if not isinstance(row, dict) or any(
            not isinstance(row.get(field), str) or not row[field].strip() for field in REQUIRED
        ):
            raise ValueError("KEV entries require eight nonempty publisher string fields")
        cid = row["cveID"]
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cid) or cid in entries:
            raise ValueError("Invalid or duplicate KEV CVE identity")
        for field in ("dateAdded", "dueDate"):
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", row[field]):
                raise ValueError("KEV entry dates must use YYYY-MM-DD")
            date.fromisoformat(row[field])
        entry = {field: row[field] for field in REQUIRED}
        for field in OPTIONAL_STRINGS:
            value = row.get(field)
            if value is not None and not isinstance(value, str):
                raise ValueError("KEV optional publisher fields must be strings or null")
            entry[field] = value
        cwes = row.get("cwes", [])
        if not isinstance(cwes, list) or any(not isinstance(cwe, str) for cwe in cwes):
            raise ValueError("KEV cwes must be a string list")
        entry["cwes"] = cwes
        entries[cid] = entry
    return {
        "parser_version": 1,
        "catalogue_version": version,
        "released_at": released,
        "count": len(entries),
        "entries": dict(sorted(entries.items())),
    }
