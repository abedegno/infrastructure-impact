"""Authored manifest fixtures exercise the closed exact-target perimeter."""

from collections import Counter
from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest

from infrastructure_impact.collection import target_import_profiles as profiles

PROFILE = "campus-switching-public-gap-2026-11-07-v1"


@pytest.mark.parametrize("offset", ["+00:99", "-00:99", "+00:60", "-00:60", "+24:00", "-24:00"])
def test_timestamp_fallback_rejects_out_of_range_offsets(offset):
    with pytest.raises(ValueError):
        profiles._validate_times({"observed_at": f"2026-11-06T12:00:00{offset}"})


@pytest.mark.parametrize("offset", ["Z", "+01:30", "-01:30", "+23:59", "-23:59"])
def test_timestamp_fallback_accepts_valid_offsets(offset):
    profiles._validate_times({"observed_at": f"2026-11-06T12:00:00{offset}"})


def manifest():
    return {
        "format": "impact-target-import-manifest",
        "schema_version": 1,
        "profile_id": "synthetic-two-vendor-v1",
        "version": "1",
        "expected_target_count": 2,
        "max_document_bytes": 3_000_000,
        "max_input_bytes": 40_000_000,
        "max_received_bytes": 80_000_000,
        "max_attempts_per_target": 2,
        "max_http_attempts": 348,
        "min_request_interval_seconds": 1,
        "allow_redirects": False,
        "max_receipt_bytes": 2_000_000,
        "targets": [
            {
                "vendor": "cisco",
                "advisory_id": "cisco-sa-synthetic-test",
                "fetch_url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-synthetic-test/csaf/cisco-sa-synthetic-test.json",
                "discovery_url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-synthetic-test",
                "source_sha256": "a" * 64,
                "cve_ids": ["CVE-2025-12345", "CVE-2025-12346"],
                "source_observed_at": "2026-11-06T12:00:00+00:00",
                "retained_collection_checked_at": "2026-11-06T12:00:01+00:00",
            },
            {
                "vendor": "aruba",
                "advisory_id": "ARUBA-PSA-2021-999",
                "fetch_url": "https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-999.txt",
                "discovery_url": "https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-999.txt",
                "source_sha256": "b" * 64,
                "cve_ids": ["CVE-2021-12345"],
                "source_observed_at": "2026-11-06T12:00:00+00:00",
                "retained_collection_checked_at": "2026-11-06T12:00:01+00:00",
            },
        ],
    }


def test_ordered_fingerprint_and_isolated_immutable_values():
    original = manifest()
    selected = profiles.from_manifest(original)
    reverse = deepcopy(original)
    reverse["targets"].reverse()
    reverse["targets"][1]["cve_ids"].reverse()
    assert profiles.from_manifest(reverse).fingerprint == selected.fingerprint
    assert [t.vendor for t in selected.targets] == ["aruba", "cisco"]
    assert selected.fingerprint == (
        "4fd5b1259650b182c902e6fcc3b1a1a3fcbf9dd15bfa2fc88b27a150d369d177"
    )
    original["targets"][0]["cve_ids"].clear()
    returned = selected.metadata()
    returned["targets"][0]["cve_ids"].clear()
    assert selected.targets[0].cve_ids == ("CVE-2021-12345",)
    with pytest.raises(FrozenInstanceError):
        selected.targets[0].vendor = "cisco"


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_url",
        "duplicate_identity",
        "unknown_vendor",
        "bad_route",
        "http",
        "credentials",
        "foreign",
        "hash",
        "cve",
        "empty_cves",
        "duplicate_cve",
        "extra_target",
        "extra_manifest",
        "boolean_limit",
        "empty_targets",
        "count",
        "timestamp",
        "fragment",
        "query",
    ],
)
def test_invalid_manifest_rejected(mutation):
    value = manifest()
    target = value["targets"][0]
    if mutation == "duplicate_url":
        value["targets"][1]["fetch_url"] = target["fetch_url"]
    elif mutation == "duplicate_identity":
        value["targets"][1] = deepcopy(target)
    elif mutation == "unknown_vendor":
        target["vendor"] = "unknown"
    elif mutation == "bad_route":
        target["fetch_url"] = "https://sec.cloudapps.cisco.com/unreviewed.json"
    elif mutation == "http":
        target["fetch_url"] = target["fetch_url"].replace("https:", "http:")
    elif mutation == "credentials":
        target["fetch_url"] = target["fetch_url"].replace("https://", "https://user:pass@")
    elif mutation == "foreign":
        target["fetch_url"] = target["fetch_url"].replace("sec.cloudapps.cisco.com", "example.org")
    elif mutation == "hash":
        target["source_sha256"] = "A" * 64
    elif mutation == "cve":
        target["cve_ids"] = ["CVE-25-1234"]
    elif mutation == "empty_cves":
        target["cve_ids"] = []
    elif mutation == "duplicate_cve":
        target["cve_ids"] *= 2
    elif mutation == "extra_target":
        target["local_id"] = 3
    elif mutation == "extra_manifest":
        value["path"] = "/private"
    elif mutation == "boolean_limit":
        value["max_http_attempts"] = True
    elif mutation == "empty_targets":
        value["targets"] = []
    elif mutation == "count":
        value["expected_target_count"] = 3
    elif mutation == "timestamp":
        target["source_observed_at"] = "yesterday"
    elif mutation == "fragment":
        target["fetch_url"] += "#content"
    elif mutation == "query":
        target["fetch_url"] += "?secret=x"
    with pytest.raises(ValueError):
        profiles.from_manifest(value)


def test_installed_profile_scope_limits_and_lookup():
    selected = profiles.profile(PROFILE)
    assert len(selected.targets) == 174
    assert Counter(t.vendor for t in selected.targets) == {"cisco": 173, "aruba": 1}
    assert len({t.fetch_url for t in selected.targets}) == 174
    assert len({(t.vendor, t.advisory_id) for t in selected.targets}) == 174
    assert (selected.max_document_bytes, selected.max_input_bytes, selected.max_received_bytes) == (
        3_000_000,
        40_000_000,
        80_000_000,
    )
    assert (selected.max_attempts_per_target, selected.max_http_attempts) == (2, 348)
    assert (
        selected.min_request_interval_seconds,
        selected.allow_redirects,
        selected.max_receipt_bytes,
    ) == (1, False, 2_000_000)
    for name in ["unknown", "../profile", None, True]:
        with pytest.raises(ValueError, match="unknown_target_import_profile"):
            profiles.profile(name)


def test_original_tools_discovery_is_retained_without_becoming_a_fetch_alias():
    value = manifest()
    value["targets"][0]["discovery_url"] = value["targets"][0]["discovery_url"].replace(
        "sec.cloudapps.cisco.com", "tools.cisco.com"
    )
    selected = profiles.from_manifest(value)
    cisco = selected.targets[1]
    assert cisco.discovery_url.startswith("https://tools.cisco.com/")
    assert cisco.discovery_url not in selected.allowed_urls
    assert cisco.fetch_url in selected.allowed_urls
