"""Ordering is opt-in analysis; unsupported literals never become candidates."""

import pytest

from infrastructure_impact.application import software_versions as versions


@pytest.mark.parametrize(
    "vendor,left,right,want",
    [
        ("cisco", "17.9.9", "17.9.10", -1),
        ("cisco", "17.12.7", "17.12.7a", -1),
        ("cisco", "17.12.7a", "17.12.7b", -1),
        ("cisco", "17.12.7b", "17.12.7c", -1),
        ("cisco", "17.12.8", "17.12.7c", 1),
        ("cisco", "17.12.8", "17.12.8", 0),
        ("cisco", "17.9.9", "17.12.1", None),
        ("aruba", "10.13.1000", "10.13.1040", -1),
        ("aruba", "10.13.1000", "10.14.1000", None),
        ("arista", "4.32.1F", "4.32.2M", -1),
        ("arista", "4.32.1F", "4.32.1M", None),
        ("arista", "4.32.1", "4.32.1M", None),
        ("arista", "4.32.1.1M", "4.32.1.2M", -1),
        ("arista", "4.32.1M", "4.33.1M", None),
    ],
)
def test_only_supported_same_train_releases_compare(vendor, left, right, want):
    assert versions.compare_releases(vendor, left, right) == want


@pytest.mark.parametrize(
    "literal",
    [
        "17.12.7s",
        "17.12.7t",
        "17.12.7w",
        "17.12.7A",
        "１７.12.7",
        "17.12.7\n",
        " 17.12.7",
        "17.12.7 and later",
        "17.12.7-17.12.8",
        "17.12.7,17.12.8",
        "17.8 and earlier",
        "",
    ],
)
def test_cisco_unsupported_forms_abstain(literal):
    assert versions.version_key("cisco", literal) is None
    assert versions.release_train("cisco", literal) is None
    assert versions.compare_releases("cisco", literal, "17.12.8") is None


def test_keys_and_train_are_numeric_without_case_or_whitespace_coercion():
    assert versions.version_key("cisco", "17.12.7b") == (17, 12, 7, 2)
    assert versions.release_train("cisco", "17.12.7b") == "17.12"
    assert versions.version_key("aruba", "10.13.1040") == (10, 13, 1040)
    assert versions.version_key("arista", "4.32.1.2M") == (4, 32, 1, 2, "M")
    assert versions.version_key("unknown", "1.2.3") is None


@pytest.mark.parametrize("vendor", ["cisco", "aruba", "arista"])
def test_unbounded_literals_abstain_before_numeric_conversion(vendor):
    assert versions.version_key(vendor, "1.2." + "9" * 5000) is None
