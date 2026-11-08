import pytest

from infrastructure_impact.application import families


def test_family_prefix_patterns_are_prepared_once(monkeypatch):
    calls = []
    original = families.re.escape

    def escape(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(families.re, "escape", escape)
    family = dict(prefixes=["profile-unique-foo", "profile-unique-bar"], platform_prefixes=[])
    for _ in range(100):
        assert families.matches(family, dict(product="PROFILE-UNIQUE-BAR (device)"))
    assert len(calls) <= 2


@pytest.mark.parametrize(
    "suffix,expected",
    [
        ("", True),
        (" switch", True),
        ("\tdevice", True),
        ("\u00a0device", True),
        ("\u2028device", True),
        ("/device", True),
        ("(device)", True),
        ("-device", False),
        (".device", False),
        ("plus", False),
        ("\u200bdevice", False),
    ],
)
def test_literal_family_prefix_boundary(suffix, expected):
    family = dict(prefixes=["EOS [test]"], platform_prefixes=[])
    assert families.matches(family, dict(product="  eOs [TEST]" + suffix)) is expected


def test_family_context_and_platform_restrictions_remain_literal():
    family = dict(prefixes=["Straße"], platform_prefixes=["CX"])
    claim = dict(product="unrelated", product_context=[("product_family", "STRASSE/device")])
    assert not families.matches(family, claim)
    assert families.matches(family, {**claim, "platforms": ["CX6300", "CX6400"]})
    assert not families.matches(family, {**claim, "platforms": ["CX6300", "Other"]})
