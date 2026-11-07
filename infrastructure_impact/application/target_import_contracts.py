"""Finite, closed, bounded operational receipts for exact-target imports."""

import json
from hashlib import sha256
from pathlib import Path

from ..collection.target_import_profiles import _validate_schema
from ..collection.target_import_profiles import profile as installed_profile
from ..plugins.registry import default_registry
from .evidence_identity import canonical_json

MAX_RECEIPT_BYTES = 2_000_000
BINDING_FIELDS = (
    "baseline_fingerprint",
    "manifest_fingerprint",
    "source_config_fingerprint",
    "normalizer_fingerprints",
)


def binding_fingerprint(value: dict) -> str:
    """Observation time is deliberately outside the accepted logical binding."""
    return sha256(canonical_json({k: value[k] for k in BINDING_FIELDS})).hexdigest()


def _bytes(value):
    try:
        encoded = canonical_json(value) + b"\n"
    except (TypeError, RecursionError, UnicodeError) as error:
        raise ValueError("invalid_target_import_receipt") from error
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ValueError("target_import_receipt_size")
    return encoded


def _validate(value, kind, selected=None):
    _validate_schema(value, kind)
    if selected is None:
        selected = installed_profile(value["profile_id"])
    if (
        value["profile_id"] != selected.profile_id
        or value["profile_version"] != selected.version
        or value["manifest_fingerprint"] != selected.fingerprint
        or value["normalizer_fingerprints"]
        != {v: default_registry().fingerprint(v) for v in {t.vendor for t in selected.targets}}
        or value["fingerprint"] != binding_fingerprint(value)
        or len(value["targets"]) != len(selected.targets)
    ):
        raise ValueError(f"invalid_target_import_{kind}_binding")
    for actual, expected in zip(value["targets"], selected.targets):
        facts = expected.metadata()
        if kind == "result":
            facts = {k: facts[k] for k in ("vendor", "advisory_id", "fetch_url", "source_sha256")}
        if any(actual[k] != v for k, v in facts.items()):
            raise ValueError(f"invalid_target_import_{kind}_target")
        if kind == "result" and (
            (actual["status"] == "failed") != (actual["failure_code"] is not None)
        ):
            raise ValueError("invalid_target_import_result_status")
    if kind == "result":
        if value.get("candidate") is not None:
            from .import_candidate import validate_result

            validate_result({**value["checks"], "candidate": value["candidate"]})
        for status in ("imported", "unchanged"):
            if value["counters"][status] != sum(t["status"] == status for t in value["targets"]):
                raise ValueError("invalid_target_import_result_counters")
    return value


def validate_preview(value: dict, selected):
    """Validate the complete receipt and return an isolated finite JSON value."""
    encoded = _bytes(value)
    _validate(value, "preview", selected)
    return json.loads(encoded)


def preview_bytes(value: dict, *, selected=None) -> bytes:
    encoded = _bytes(value)
    _validate(value, "preview", selected)
    return encoded


def result_bytes(value: dict, *, selected=None) -> bytes:
    encoded = _bytes(value)
    _validate(value, "result", selected)
    return encoded


def load_preview(path: Path, profile) -> dict:
    """Read at most the receipt bound plus one; reject duplicate/invalid JSON."""

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("invalid_target_import_preview_duplicate_key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("invalid_target_import_preview_constant")

    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_RECEIPT_BYTES + 1)
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("target_import_receipt_size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        return validate_preview(value, profile)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("invalid_target_import_preview") from error
