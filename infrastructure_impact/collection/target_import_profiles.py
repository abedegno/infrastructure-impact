"""Closed, reviewed import metadata; discovery URLs are provenance only."""

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from hashlib import sha256
from importlib.resources import files
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators

from ..application.evidence_identity import canonical_json
from ..source_policy import allowed

PROFILE_ID = "campus-switching-public-gap-2026-11-07-v1"
LIMITS = {
    "max_document_bytes": 3_000_000,
    "max_input_bytes": 40_000_000,
    "max_received_bytes": 80_000_000,
    "max_attempts_per_target": 2,
    "max_http_attempts": 348,
    "min_request_interval_seconds": 1,
    "allow_redirects": False,
    "max_receipt_bytes": 2_000_000,
}


@lru_cache(maxsize=3)
def _validator(kind):
    schema = json.loads(
        files("infrastructure_impact")
        .joinpath(f"schemas/target-import-{kind}-v1.json")
        .read_text(encoding="utf-8")
    )
    strict = validators.extend(
        Draft202012Validator,
        type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
            "integer", lambda checker, item: type(item) is int
        ),
    )
    return strict(schema, format_checker=FormatChecker())


def _validate_times(value):
    # jsonschema's RFC3339 checker is optional; do not add a runtime dependency.
    if type(value) is dict:
        for key, child in value.items():
            if key in {"observed_at", "source_observed_at", "retained_collection_checked_at"}:
                if (
                    type(child) is not str
                    or not re.fullmatch(
                        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                        r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
                        child,
                    )
                    or datetime.fromisoformat(child.replace("Z", "+00:00")).tzinfo is None
                ):
                    raise ValueError("invalid_target_import_timestamp")
            _validate_times(child)
    elif type(value) is list:
        for child in value:
            _validate_times(child)


def _validate_schema(value, kind):
    """Use strict scalar integers, finite UTF-8 JSON, and local schemas only."""
    try:
        canonical_json(value)
        _validator(kind).validate(value)
        _validate_times(value)
    except (ValidationError, TypeError, RecursionError, UnicodeError) as error:
        raise ValueError(f"invalid_target_import_{kind}") from error


@dataclass(frozen=True)
class TargetImportTarget:
    vendor: str
    advisory_id: str
    fetch_url: str
    discovery_url: str
    source_sha256: str
    cve_ids: tuple[str, ...]
    source_observed_at: str
    retained_collection_checked_at: str

    def __post_init__(self):
        if type(self.cve_ids) is not tuple:
            raise ValueError("invalid_target_import_target")
        target_schema = {
            "format": "impact-target-import-manifest",
            "schema_version": 1,
            "profile_id": "validation",
            "version": "1",
            "expected_target_count": 1,
            **LIMITS,
            "targets": [self.metadata()],
        }
        _validate_schema(target_schema, "manifest")
        if tuple(sorted(self.cve_ids)) != self.cve_ids or any(
            not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve) for cve in self.cve_ids
        ):
            raise ValueError("noncanonical_target_import_cves")
        for url in (self.fetch_url, self.discovery_url):
            parsed = urlsplit(url)
            if not allowed(url, self.vendor) or parsed.query or parsed.fragment:
                raise ValueError("invalid_target_import_url")
        if self.vendor == "cisco":
            base = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
            if not re.fullmatch(r"cisco-sa-[A-Za-z0-9_-]+", self.advisory_id):
                raise ValueError("invalid_target_import_identity")
            if self.discovery_url not in (
                base + self.advisory_id,
                base.replace("sec.cloudapps.cisco.com", "tools.cisco.com") + self.advisory_id,
            ) or self.fetch_url != (
                base + self.advisory_id + "/csaf/" + self.advisory_id + ".json"
            ):
                raise ValueError("invalid_target_import_route")
        else:
            match = re.fullmatch(r"ARUBA-PSA-([0-9]{4})-([0-9]{3})", self.advisory_id)
            if not match:
                raise ValueError("invalid_target_import_identity")
            year, number = match.groups()
            url = (
                f"https://csaf.arubanetworking.hpe.com/{year}/"
                f"hpe_aruba_networking_-_{year}-{number}.txt"
            )
            if self.fetch_url != url or self.discovery_url != url:
                raise ValueError("invalid_target_import_route")

    def metadata(self):
        return {
            "vendor": self.vendor,
            "advisory_id": self.advisory_id,
            "fetch_url": self.fetch_url,
            "discovery_url": self.discovery_url,
            "source_sha256": self.source_sha256,
            "cve_ids": list(self.cve_ids),
            "source_observed_at": self.source_observed_at,
            "retained_collection_checked_at": self.retained_collection_checked_at,
        }


@dataclass(frozen=True)
class TargetImportProfile:
    profile_id: str
    version: str
    targets: tuple[TargetImportTarget, ...]
    expected_target_count: int
    max_document_bytes: int = 3_000_000
    max_input_bytes: int = 40_000_000
    max_received_bytes: int = 80_000_000
    max_attempts_per_target: int = 2
    max_http_attempts: int = 348
    min_request_interval_seconds: int = 1
    allow_redirects: bool = False
    max_receipt_bytes: int = 2_000_000

    def __post_init__(self):
        if type(self.targets) is not tuple or not all(
            type(t) is TargetImportTarget for t in self.targets
        ):
            raise ValueError("invalid_target_import_targets")
        _validate_schema(self.metadata(), "manifest")
        keys = [(t.vendor, t.advisory_id) for t in self.targets]
        if (
            len(self.targets) != self.expected_target_count
            or keys != sorted(keys)
            or len(set(keys)) != len(keys)
            or len({t.fetch_url for t in self.targets}) != len(keys)
        ):
            raise ValueError("invalid_target_import_target_set")
        if self.profile_id == PROFILE_ID and (
            self.expected_target_count != 174
            or Counter(t.vendor for t in self.targets) != {"cisco": 173, "aruba": 1}
        ):
            raise ValueError("invalid_installed_target_import_scope")

    def metadata(self):
        return {
            "format": "impact-target-import-manifest",
            "schema_version": 1,
            "profile_id": self.profile_id,
            "version": self.version,
            "expected_target_count": self.expected_target_count,
            **{k: getattr(self, k) for k in LIMITS},
            "targets": [t.metadata() for t in self.targets],
        }

    @property
    def fingerprint(self):
        return sha256(canonical_json(self.metadata())).hexdigest()

    @property
    def allowed_urls(self):
        return frozenset(t.fetch_url for t in self.targets)


def from_manifest(value: dict) -> TargetImportProfile:
    """Validate authored/installed facts; this is not an operator manifest input."""
    _validate_schema(value, "manifest")
    targets = tuple(
        sorted(
            (
                TargetImportTarget(**(t | {"cve_ids": tuple(sorted(t["cve_ids"]))}))
                for t in value["targets"]
            ),
            key=lambda t: (t.vendor, t.advisory_id),
        )
    )
    return TargetImportProfile(
        value["profile_id"],
        value["version"],
        targets,
        value["expected_target_count"],
        **{k: value[k] for k in LIMITS},
    )


def profile(profile_id: str) -> TargetImportProfile:
    if type(profile_id) is not str or profile_id != PROFILE_ID:
        raise ValueError("unknown_target_import_profile")
    resource = files("infrastructure_impact").joinpath(
        f"resources/target-imports/{profile_id}.json"
    )
    return from_manifest(json.loads(resource.read_text(encoding="utf-8")))
