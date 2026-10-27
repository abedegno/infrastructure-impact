"""Offline proposal checks; neither a device inventory nor exposure adjudication."""

import json
import os
import re
import stat
from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha256
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from ..settings import PACKAGE
from ..source_policy import allowed
from .eligibility import timestamp

FIELDS = (
    "firmware_reference",
    "component_version",
    "package_patch_id",
    "hardware_model",
    "image_digest",
    "service_configuration",
    "historical_support_window",
    "historical_download_availability",
    "build_component_binding",
)
MAX_PROPOSAL_BYTES = 250_000
MAX_ARTIFACT_BYTES = 32_000_000
MAX_TOTAL_BYTES = 128_000_000


def template(vendor, product, firmware_build, component, role):
    """A blank proposal, independent of the bundled pilot and vendor catalogue."""
    value = dict(
        schema_version=1,
        kind="build_inventory_proposal",
        target=dict(
            vendor=vendor,
            product=product,
            firmware_build=firmware_build,
            component=component,
            role=role,
        ),
        artifacts=[],
        claims=[dict(field=f, state="unknown", value=None, evidence=[]) for f in FIELDS],
    )
    validate(value)
    return value


@lru_cache(maxsize=1)
def validator():
    schema = json.loads((PACKAGE / "schemas/build-inventory-submission-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def loads(raw):
    """Reject ambiguous duplicate keys and non-finite JSON before schema checks."""
    if len(raw) > MAX_PROPOSAL_BYTES:
        raise ValueError("Inventory proposal exceeds 250 KB")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key in inventory proposal")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("Inventory proposal requires finite JSON")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (RecursionError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Invalid inventory proposal JSON") from None


def validate(value, now=None):
    error = next(validator().iter_errors(value), None)
    if error:
        # Never echo submitted values or local paths in machine-readable audit logs.
        raise ValueError("Invalid inventory proposal fields or bounds")
    json.dumps(value, allow_nan=False)
    from ..plugins.registry import default_registry

    vendor = value["target"]["vendor"]
    if vendor not in default_registry().names():
        raise ValueError("Inventory target requires an installed vendor plugin")
    artifacts = {}
    files = set()
    for artifact in value["artifacts"]:
        if artifact["id"] in artifacts or artifact["file_name"] in files:
            raise ValueError("Duplicate inventory artifact identity or file name")
        artifacts[artifact["id"]] = artifact
        files.add(artifact["file_name"])
        source = artifact["source_url"]
        if artifact["kind"] == "device_export":
            if source is not None:
                raise ValueError(
                    "Device exports require a null source URL; keep device locations private"
                )
        elif source is None or not allowed(source, vendor):
            raise ValueError("Publisher artifacts require this vendor's official HTTPS policy")
        observed = timestamp(artifact["observed_at"])
        if not observed or observed > (now or datetime.now(timezone.utc)):
            raise ValueError("Artifact capture time must be a past timezone-qualified timestamp")
        if artifact["redistribution"] == "permission_confirmed" and not artifact["rights_basis"]:
            raise ValueError("Declared redistribution permission requires a reviewable basis")
    seen, used = set(), set()
    for claim in value["claims"]:
        if claim["field"] in seen:
            raise ValueError("Duplicate inventory claim field")
        seen.add(claim["field"])
        if claim["state"] == "unknown":
            if claim["value"] is not None or claim["evidence"]:
                raise ValueError("Unknown inventory claims require null values and no evidence")
        elif claim["value"] is None or not claim["evidence"]:
            raise ValueError("Documented inventory claims require a value and exact evidence")
        refs = [e["artifact_id"] for e in claim["evidence"]]
        if any(ref not in artifacts for ref in refs):
            raise ValueError("Inventory claim refers to an unknown artifact")
        used.update(refs)
        if claim["field"] == "firmware_reference" and claim["value"] is not None:
            if claim["value"] != value["target"]["firmware_build"]:
                raise ValueError("Firmware reference must match the exact target build")
        if claim["field"] == "image_digest" and claim["value"] is not None:
            if not re.fullmatch(r"(?:sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})", claim["value"]):
                raise ValueError("Image digest requires an explicit SHA-256 or SHA-512 algorithm")
    if seen != set(FIELDS):
        raise ValueError("Inventory proposal must account for every required field")
    if used != artifacts.keys():
        raise ValueError("Unreferenced artifacts must be excluded from the inventory proposal")
    return value


def audit(value, evidence_dir=None, now=None):
    """Hash only named regular files under an explicitly supplied evidence directory."""
    validate(value, now=now)
    if value["artifacts"] and evidence_dir is None:
        raise ValueError("Artifact checks require an explicit evidence directory")
    root = Path(evidence_dir).resolve() if evidence_dir is not None else None
    total = 0
    for artifact in value["artifacts"]:
        path = root / artifact["file_name"]
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise ValueError(
                "Inventory artifacts must be readable regular files, without symlinks"
            ) from None
        digest, size = sha256(), 0
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(
                    "Inventory artifacts must be regular local files, without symlinks"
                )
            if metadata.st_size > MAX_ARTIFACT_BYTES:
                raise ValueError("Inventory artifact exceeds 32 MB; use a scoped evidence export")
            while chunk := stream.read(1_000_000):
                size += len(chunk)
                total += len(chunk)
                if size > MAX_ARTIFACT_BYTES or total > MAX_TOTAL_BYTES:
                    raise ValueError("Inventory evidence exceeds its byte budget")
                digest.update(chunk)
        if digest.hexdigest() != artifact["sha256"]:
            raise ValueError("Inventory artifact bytes do not match the submitted fingerprint")
    unknown = [c["field"] for c in value["claims"] if c["state"] == "unknown"]
    restricted = sum(a["redistribution"] != "permission_confirmed" for a in value["artifacts"])
    return dict(
        schema_version=1,
        proposal_sha256=sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest(),
        status="requires_maintainer_review",
        checked_artifacts=len(value["artifacts"]),
        checked_bytes=total,
        undocumented_fields=unknown,
        all_required_fields_documented=not unknown,
        artifacts_without_declared_redistribution_permission=restricted,
        inventory_verified=False,
        independent_human_review_completed=False,
        metric_eligibility_changed=False,
        assessments_changed=False,
        evidence_published=False,
        limitations=[
            "Local byte equality verifies the submitted file, not publisher authenticity or semantic claims.",
            "Target labels and evidence locators require review against exact build, hardware, role and period.",
            "A source archive or version string does not establish shipped binaries, backports or CVE applicability.",
            "Declared permissions are unverified; no evidence or proposal is automatically published.",
            "Complete fields do not establish inventory completeness, independent review or comparable denominators.",
        ],
    )
