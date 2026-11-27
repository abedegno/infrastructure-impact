"""Installed options are independent of the selection advertised by a publication."""

import importlib
import json
from dataclasses import FrozenInstanceError
from hashlib import sha256

import pytest

PROFILE = "campus-switching-common-views-v1"
DIGEST = "79de64408c9df10cebeee363422784940e5288073d14dc0f7925e9b1d5e10dfc"


def module():
    return importlib.import_module("infrastructure_impact.application.analysis_delivery_profiles")


def expected():
    return [
        dict(vendor=vendor, window=window, scope_level="os_family", cve_ids=None)
        for vendor in (None, "cisco", "aruba", "arista")
        for window in ("all", "2025")
    ]


def test_closed_installed_profile_supplies_fresh_ordered_options():
    selected = module().profile(PROFILE)
    with pytest.raises(FrozenInstanceError):
        selected._raw = b""
    assert selected.identity() == {"profile_id": PROFILE, "input_sha256": DIGEST}
    writer = selected.build_options()
    assert writer == {
        "analysis_precomputed_delivery": True,
        "analysis_precomputed_options": expected(),
    }
    writer["analysis_precomputed_options"][0]["window"] = "2099"
    assert selected.options() == expected()
    assert module().hosted_profile() is None


@pytest.mark.parametrize(
    "bad", [None, False, [], {}, "../local", "https://example.org/", "unknown"]
)
def test_selector_is_closed(bad):
    with pytest.raises(ValueError):
        module().profile(bad)


@pytest.mark.parametrize(
    "change", ["hash", "large", "duplicate", "order", "partial", "extra", "year", "scope", "cves"]
)
def test_reject_changed_or_rehashed_invalid_options(change):
    options = expected()
    if change == "duplicate":
        options[1] = options[0]
    if change == "order":
        options.reverse()
    if change == "partial":
        del options[0]["vendor"]
    if change == "extra":
        options[0]["path"] = "unreviewed"
    if change == "year":
        options[1]["window"] = "2026"
    if change == "scope":
        options[0]["scope_level"] = "model_qualified"
    if change == "cves":
        options[0]["cve_ids"] = []
    raw = json.dumps(options).encode()
    if change == "large":
        raw += b" " * module().MAX_RESOURCE_BYTES
    digest = "0" * 64 if change == "hash" else sha256(raw).hexdigest()
    with pytest.raises(ValueError):
        module()._decode(raw, expected_sha256=digest)
