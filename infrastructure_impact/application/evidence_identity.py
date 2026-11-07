"""Projection-independent, typed identities for retained advisory records."""

import json
import math
import re
from hashlib import sha256


def canonical_json(value) -> bytes:
    """Finite JSON only; compact UTF-8 bytes preserve scalar JSON types."""

    def check(item):
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float and math.isfinite(item):
            return
        if type(item) is list:
            for child in item:
                check(child)
            return
        if type(item) is dict and all(type(k) is str for k in item):
            for child in item.values():
                check(child)
            return
        raise ValueError("Identity requires finite JSON values and string object keys")

    check(value)
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise ValueError("Identity requires UTF-8 JSON") from error


def record_identity(record: dict) -> dict:
    """Validated literal target reference, preserving JSON scalar identity types."""
    if type(record) is not dict:
        raise ValueError("Record identity requires an object")
    keys = ("vendor", "advisory_id", "revision_id", "source_url", "sha256")
    identity = {k: record.get(k) for k in keys}
    if any(
        type(identity[k]) is not str or not identity[k]
        for k in ("vendor", "advisory_id", "source_url", "sha256")
    ):
        raise ValueError("Record identity requires vendor, advisory, source URL and SHA")
    if not re.fullmatch("[a-f0-9]{64}", identity["sha256"]):
        raise ValueError("Record identity requires a SHA-256 digest")
    revision = identity["revision_id"]
    if not (
        (type(revision) is int and revision > 0)
        or (type(revision) is str and 1 <= len(revision) <= 128)
    ):
        raise ValueError("Record identity requires a typed revision ID")
    return identity


def record_key(record: dict) -> str:
    """Hash retained identity, never mutable claims or observation-time analysis."""
    return sha256(canonical_json(record_identity(record))).hexdigest()
