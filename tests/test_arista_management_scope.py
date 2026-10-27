"""Synthetic appliance-only examples preserve role, version and fix qualifications."""

import pytest

from infrastructure_impact.adapters.arista_management_scope import ROUTES
from infrastructure_impact.plugins.registry import default_registry


def source(number, edit=lambda value: value):
    slug, ids = ROUTES[number]
    descriptions = {
        "50": "Synthetic TACACS+ authentication for the base operating system; not for Web UI logins. No real credentials or logs are included.",
        "51": "Synthetic Configlet Management API for authenticated users, including network-admins and qualifying custom roles.",
        "52": "Synthetic ControllerOob control-plane issue. Impact to production traffic is not expected in this example.",
    }
    platforms = "<ul><li>This vulnerability affects CloudVision synthetic virtual and physical appliances with the versions identified above</li><li>The following products are not affected:</li><ul><li>Synthetic independent appliance</li><li>Synthetic CVX client switch</li></ul></ul>"
    if number in {"50", "51"}:
        cutoff = "2020.2" if number == "51" else "2019.1.5"
        software = f"<table><tr><th>CloudVision Portal</th></tr><tr><td>All releases prior to {cutoff}</td></tr></table>"
        builds = "2020.1.2, 2020.2.0" if number == "51" else "2019.1.5, 2019.2.0"
        resolution = f"<p>Synthetic issue addressed in the {builds}, and later versions of CloudVision Portal.</p>"
        mitigation = (
            "<p>Synthetic control cannot be disabled for default roles; it applies to custom roles alone.</p>"
            if number == "51"
            else ""
        )
        if number == "50":
            resolution += "<p>Synthetic key will no longer be logged by journald. Change both the TACACS+ and Administrator passwords after the upgrade.</p>"
    else:
        software = "<ul><li>CloudVision eXchange VM/Appliance:</li><ul><li>6.10.1F and below release in the 6.10.x train.</li><li>6.9.1F to 6.9.3M releases in the 6.9.x train.</li></ul></ul>"
        mitigation = "<p>Synthetic ACLs for known CVX clients only on 50003 and 50004.</p>"
        resolution = '<p>Synthetic fixed builds follow.</p><ul><li>6.10.2F</li><li>6.9.4M</li></ul><p><a href="/assets/data/SecurityAdvisories/SA52/SecurityAdvisory0052Hotfix.swix">Publisher reference only, never download this binary</a></p><p>Synthetic installation must be persistent across reboots; agents restart.</p>'
    raw = f"""<div class="item-page"><div><h2>Security Advisory {int(number):04d}</h2></div>
    <table><tr><td>Revision</td><td>Date</td><td>Changes</td></tr><tr><td>1.0</td><td>October 7, 2020</td><td>Synthetic initial entry</td></tr></table>
    <p>The CVE-ID tracking this synthetic issue: {ids[0]}</p><h3>Description</h3><p>{descriptions[number]}</p>
    <h3>Vulnerability Assessment</h3><p>Affected Software</p>{software}<p>Affected Platforms</p>{platforms}
    <h3>Mitigation</h3>{mitigation}<h3>Resolution</h3>{resolution}
    <h4>For More Information:</h4><p>Unrelated synthetic reference CVE-2099-12345.</p></div>"""
    return edit(
        raw
    ).encode(), "https://www.arista.com/en/support/advisories-notices/security-advisory/" + slug


def parse(number, edit=lambda value: value):
    raw, url = source(number, edit)
    return default_registry().normalize(raw, url, "arista")


@pytest.mark.parametrize("number", ["50", "51", "52"])
def test_appliance_scope_and_exclusions_are_separate(number):
    document = parse(number)
    assert document["cves"] == ROUTES[number][1]
    assert len(document["assessments"]) == 3
    affected, *excluded = document["assessments"]
    assert affected["status"] == "affected" and affected["versions"]
    assert "virtual and physical appliances" in affected["platforms"][0]
    assert all(
        c["status"] == "unaffected" and not c["versions"] and not c["remediations"]
        for c in excluded
    )
    assert {c["product"] for c in excluded} == {
        "Synthetic independent appliance",
        "Synthetic CVX client switch",
    }
    assert all(c["cve_id"] != "CVE-2099-12345" for c in document["assessments"])


def test_tacacs_shell_condition_and_post_upgrade_rotation_survive():
    claim = parse("50")["assessments"][0]
    assert claim["versions"] == [{"expression": "All releases prior to 2019.1.5"}]
    context = claim["exposure"][0]["details"]
    assert (
        "base-VM/shell" in context and "web UI" in context and "passwords after upgrade" in context
    )
    assert [r["details"] for r in claim["remediations"]] == ["2019.1.5", "2019.2.0"]


def test_custom_role_mitigation_does_not_reconcile_release_discrepancy():
    document = parse("51")
    claim = document["assessments"][0]
    assert claim["status"] == "affected"
    assert claim["versions"] == [{"expression": "All releases prior to 2020.2"}]
    assert [r["details"] for r in claim["remediations"][:2]] == ["2020.1.2", "2020.2.0"]
    assert claim["remediations"][-1]["availability"] == "partial_mitigation"
    assert "default network-operator" in claim["remediations"][-1]["details"]
    assert "different release cutoffs" in document["warnings"][0]


def test_cvx_fixes_are_not_transferred_to_client_switches_or_inferred_ranges():
    document = parse("52")
    claim = document["assessments"][0]
    assert claim["product"] == "CloudVision eXchange VM/Appliance"
    assert len(claim["versions"]) == 2 and " to " in claim["versions"][1]["expression"]
    assert [r["details"] for r in claim["remediations"][:2]] == ["6.10.2F", "6.9.4M"]
    hotfix = claim["remediations"][-1]
    assert (
        hotfix["release_type"] == "hotfix_extension"
        and "not independently verified" in hotfix["details"]
    )
    assert claim["remediations"][-2]["availability"] == "partial_mitigation"
    assert document["assessments"][-1]["status"] == "unaffected"


@pytest.mark.parametrize(
    "number,old,new",
    [
        ("50", "not for Web UI logins", "all logins"),
        ("50", "passwords after the upgrade", "passwords whenever"),
        ("51", "custom roles alone", "all roles"),
        ("51", "All releases prior to 2020.2", "All releases prior to 2020.1.2"),
        ("51", "2020.1.2, 2020.2.0", "2020.1.3, 2020.2.0"),
        ("52", "Impact to production traffic is not expected", "Production traffic can fail"),
        ("52", "known CVX clients only", "any client"),
        ("52", "persistent across reboots", "transient installation"),
        ("52", "SecurityAdvisory0052Hotfix.swix", "different.swix"),
        ("52", "6.9.1F to 6.9.3M releases", "all 6.9 releases"),
    ],
)
def test_changed_qualifications_require_review(number, old, new):
    with pytest.raises(ValueError):
        parse(number, lambda value: value.replace(old, new))


@pytest.mark.parametrize("number", ["50", "51", "52"])
def test_unknown_nesting_and_new_tracked_cves_are_not_flattened(number):
    with pytest.raises(ValueError):
        parse(
            number,
            lambda value: value.replace(
                "<li>Synthetic independent appliance</li>",
                "<li>Synthetic family<ul><li>Nested model</li></ul></li>",
            ),
        )
    with pytest.raises(ValueError):
        parse(number, lambda value: value.replace(ROUTES[number][1][0], "CVE-2099-99999"))
    raw, url = source(number)
    with pytest.raises(ValueError):
        default_registry().normalize(
            raw, url.replace("www.arista.com", "other.arista.com"), "arista"
        )
