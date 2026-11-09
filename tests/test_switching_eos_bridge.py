"""Authored HTML contracts: no retained publisher bytes."""

import pytest

from infrastructure_impact.adapters.switching import extract
from infrastructure_impact.plugins.arista import parse

PREFIX = "https://www.arista.com/en/support/advisories-notices/security-advisory/"
CASES = [
    ("23115-security-advisory-0128", "0128", "CVE-2025-8872"),
    ("24847-security-advisory-0201", "0201", "CVE-2026-111943"),
]


def authored(case):
    slug, number, cid = case
    extra = (
        ""
        if number == "0128"
        else "<div>Streaming Telemetry Agent (TerminAttr) Versions:</div>"
        "<ul><li>v1.46.2 and below releases in the v1.46 train</li></ul>"
        "<div>CloudVision Portal on-premises, virtual appliance or physical appliance "
        "(including the CV-CUE on premises software)</div><ul><li>2026.1.4</li></ul>"
    )
    return (
        f"<!-- Authored synthetic fixture, not vendor evidence. -->"
        f"<h2>Security Advisory {number}<span>PDF</span></h2>"
        f"<p>The CVE-ID tracking this issue: {cid}</p>"
        "<h2>Vulnerability Assessment</h2><h3>Affected Software</h3>"
        "<div>EOS Versions</div><ul><li>4.34.1F and below releases in the 4.34.x train</li></ul>"
        f"{extra}<h3>Affected Platforms</h3><ul><li>720XP/722XPM Series</li></ul>"
        "<h2>Resolution</h2><p>Upgrade to a remediated version.</p>"
        "<table><tr><th>Revision</th><th>Date</th><th>Changes</th></tr>"
        "<tr><td>1.0</td><td>January 1, 2026</td><td>Initial</td></tr>"
        "<tr><td>1.1</td><td>February 1, 2026</td><td>Update</td></tr></table>"
    ).encode()


@pytest.mark.parametrize("case", CASES)
def test_owned_eos_bridge_reparses_and_preserves_identity_without_models_or_fixes(case):
    raw = authored(case)
    url = PREFIX + case[0]
    document = parse(raw, url, "arista")
    document["assessments"] = []  # Caller assessments are never authoritative.
    claims = extract(raw, url, "arista", document)["claims"]
    assert len(claims) == (1 if case[1] == "0128" else 2)
    eos = claims[0]
    assert eos["cve_id"] == case[2]
    assert eos["family"] == "arista-eos"
    assert eos["version_expressions"] == ["4.34.1F and below releases in the 4.34.x train"]
    assert eos["initial_published_at"] == "2026-01-01"
    assert eos["updated_at"] == "2026-02-01"
    assert eos["publisher"]["id"] == "Security Advisory " + case[1]
    assert eos["publisher"]["sequence"] == "1.1"
    assert (
        eos["source"]["source_locator"] == "Affected Software / EOS (source platform scope applies)"
    )
    for claim in claims:
        assert claim["product_id"] is None
        assert claim["scope"] == "cve_specific"
        assert claim["scope_level"] == "os_family"
        assert not claim["platform_bindings"]
        assert not claim["remediations"]
    if len(claims) == 2:
        assert claims[1]["family"] is None
        assert claims[1]["version_expressions"] == ["v1.46.2 and below releases in the v1.46 train"]


@pytest.mark.parametrize(
    "old,new",
    [
        ("CVE-2026-111943", "CVE-2026-12345"),
        ("CVE-2026-111943", "CVE-2026-111943 CVE-2026-12345"),
        ("Affected Software", "Software"),
        ("Affected Platforms", "Platforms"),
        ("EOS Versions", "Other Versions"),
        ("EOS Versions", "Streaming Telemetry Agent (TerminAttr) Versions:"),
        ("Streaming Telemetry Agent (TerminAttr) Versions:", "EOS Versions"),
        ("Revision", "Revision changed"),
        ("Security Advisory 0201", "Security Advisory 0128"),
        (
            "<div>EOS Versions",
            "<p>product releases are affected for CVE-2026-12345</p><div>EOS Versions",
        ),
    ],
)
def test_changed_owned_structure_or_identity_is_rejected(old, new):
    case = CASES[1]
    raw = authored(case).replace(old.encode(), new.encode())
    document = {"advisory_id": case[0], "source_format": "Arista affected software HTML"}
    with pytest.raises(ValueError):
        extract(raw, PREFIX + case[0], "arista", document)


@pytest.mark.parametrize(
    "url,fmt",
    [
        ("https://example.com/", "Arista affected software HTML"),
        (PREFIX + CASES[0][0], "foreign format"),
    ],
)
def test_foreign_route_or_format_stays_unsupported(url, fmt):
    result = extract(
        authored(CASES[0]), url, "arista", {"advisory_id": CASES[0][0], "source_format": fmt}
    )
    assert not result["claims"]


def test_core_unknown_product_heading_stops_terminattr_version_inheritance():
    case = CASES[1]
    document = parse(authored(case), PREFIX + case[0], "arista")
    agent = next(a for a in document["assessments"] if "TerminAttr" in a["product"])
    assert agent["versions"] == [{"expression": "v1.46.2 and below releases in the v1.46 train"}]


def test_core_unknown_boundary_keeps_following_recognized_product_separate():
    case = CASES[1]
    raw = authored(case).replace(
        b"<h3>Affected Platforms",
        b"<div>CloudVision Appliance Versions</div><ul><li>7.2.0</li></ul><h3>Affected Platforms",
    )
    document = parse(raw, PREFIX + case[0], "arista")
    appliance = next(
        a for a in document["assessments"] if a["product"].startswith("CloudVision Appliance")
    )
    assert appliance["versions"] == [{"expression": "7.2.0"}]
    assert any("Unresolved affected-software headings:" in w for w in document["warnings"])


def test_core_reviewed_list_introduction_keeps_wifi_product_ownership():
    case = CASES[1]
    raw = authored(case).replace(
        b"<h3>Affected Platforms",
        b"<div>WIFI AP Versions</div><div>All releases are impacted including:</div>"
        b"<ul><li>21.6.0M -8 and below releases in 21.X train</li></ul><h3>Affected Platforms",
    )
    document = parse(raw, PREFIX + case[0], "arista")
    matches = [a for a in document["assessments"] if a["product"].startswith("WIFI AP")]
    assert len(matches) == 1
    wifi = matches[0]
    assert wifi["versions"] == [{"expression": "21.6.0M -8 and below releases in 21.X train"}]
