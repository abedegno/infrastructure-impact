"""Installed, hash-pinned public analysis configuration; never operator input paths."""

import re
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from importlib.resources import files

from .strict_json import loads

PROFILE_ID = "campus-switching-openvuln-2026-11-14-v1"
INPUT_SHA256 = "e8cc5e131c3c2bd835185795357044f427ec9c796f708a98eb652f9831289356"
MAX_RESOURCE_BYTES = 1_000_000
_POLICY_URL = "https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure"
_API_URL = "https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version="
_ISSUES = frozenset(
    {
        "ownership_unresolved",
        "empty_first_fixed",
        "unsupported_ordering_literal",
        "other_train_alternative",
    }
)


def _require(condition):
    if not condition:
        raise ValueError("invalid_switching_analysis_profile")


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names.split()))


def _literal(value, pattern, limit=128):
    _require(type(value) is str and len(value) <= limit and re.fullmatch(pattern, value))


def _receipt(value, url):
    _keys(value, "url sha256 retrieved_at")
    _require(value["url"] == url)
    _literal(value["sha256"], r"[0-9a-f]{64}")
    at = value["retrieved_at"]
    _literal(
        at,
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
    )
    _require(datetime.fromisoformat(at.replace("Z", "+00:00")).tzinfo is not None)


def _validate(value):
    # This is a closed profile of unresolved public API metadata. Supporting owned
    # facts or calibration later requires an independently reviewed profile revision.
    _keys(value, "policy_source api_results calibration_records")
    _receipt(value["policy_source"], _POLICY_URL)
    _require(value["calibration_records"] == [])
    frames = value["api_results"]
    _require(type(frames) is list and len(frames) == 59)
    queries = set()
    total_contexts = 0
    for frame in frames:
        _keys(frame, "source query_release parser_revision first_fixed advisory_context issues")
        query = frame["query_release"]
        _literal(query, r"17\.(?:9|12|15)\.[0-9]{1,2}[a-z]?")
        _require(query not in queries)
        queries.add(query)
        _receipt(frame["source"], _API_URL + query)
        _require(frame["parser_revision"] == "cisco-first-fixed-api-2")
        _require(frame["first_fixed"] == [])
        issues = frame["issues"]
        _require(type(issues) is list and len(issues) <= 4)
        _require(all(type(i) is str and i in _ISSUES for i in issues))
        _require(len(set(issues)) == len(issues))
        contexts = frame["advisory_context"]
        _require(type(contexts) is list and len(contexts) <= 1000)
        total_contexts += len(contexts)
        _require(total_contexts <= 2000)
        advisories = set()
        for index, context in enumerate(contexts):
            _keys(
                context,
                "advisory_id source_locator source_first_fixed first_fixed_state cve_refs ownership_state",
            )
            _literal(context["advisory_id"], r"cisco-sa-[A-Za-z0-9_-]+")
            _require(context["advisory_id"] not in advisories)
            advisories.add(context["advisory_id"])
            _require(context["source_locator"] == f"/advisories/{index}/firstFixed")
            fixed = context["source_first_fixed"]
            _require(type(fixed) is list and len(fixed) <= 100)
            for release in fixed:
                _literal(release, r"[0-9]+\.[0-9]+\.[0-9]+[a-z0-9()_.-]*")
            _require(context["first_fixed_state"] == ("present" if fixed else "empty"))
            _require(context["ownership_state"] == "ownership_unresolved")
            cves = context["cve_refs"]
            _require(type(cves) is list and len(cves) <= 100)
            for cve in cves:
                _literal(cve, r"CVE-[0-9]{4}-[0-9]{4,}")
            _require(len(set(cves)) == len(cves))
    return value


def _decode(raw: bytes, *, expected_sha256: str) -> dict:
    """Validate bounded bytes, their receipt and every allowed field before use."""
    _require(type(raw) is bytes and len(raw) <= MAX_RESOURCE_BYTES)
    if sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("switching_analysis_profile_digest_mismatch")
    return _validate(loads(raw, budget=MAX_RESOURCE_BYTES, label="Switching analysis profile"))


@dataclass(frozen=True)
class AnalysisProfile:
    """Keep immutable reviewed bytes; each consumer receives a new validated frame."""

    _raw: bytes

    def __post_init__(self):
        _decode(self._raw, expected_sha256=INPUT_SHA256)

    def identity(self) -> dict:
        return {"profile_id": PROFILE_ID, "input_sha256": INPUT_SHA256, "api_frames": 59}

    def build_options(self) -> dict:
        return {
            "include_switching_analysis": True,
            "switching_analysis_input": _decode(self._raw, expected_sha256=INPUT_SHA256),
        }


def profile(profile_id: str) -> AnalysisProfile:
    if type(profile_id) is not str or profile_id != PROFILE_ID:
        raise ValueError("unknown_switching_analysis_profile")
    resource = files("infrastructure_impact").joinpath(
        "resources/switching-analysis/" + PROFILE_ID + ".json"
    )
    with resource.open("rb") as stream:
        raw = stream.read(MAX_RESOURCE_BYTES + 1)
    return AnalysisProfile(raw)


def build_options(profile_id: str = "") -> dict:
    if type(profile_id) is str and profile_id == "":
        return {}
    return profile(profile_id).build_options()
