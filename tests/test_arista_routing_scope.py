"""Original synthetic routing articles test branch and exclusion scope isolation."""

import pytest

from infrastructure_impact.adapters.arista_routing_scope import ROUTES, routing_scope
from infrastructure_impact.plugins.registry import default_registry


def source(number, *, edit=lambda s: s):
    slug, ids = ROUTES[number]
    description = {
        "54": "Synthetic IS-IS configured prerequisite.",
        "55": "Synthetic VxLAN Routing and VRFs prerequisite.",
        "56": "Synthetic crossing VLAN boundaries issue.",
    }[number]
    symptoms = {
        "54": "Both modes are vulnerable; synthetic routing-mode check.",
        "55": "Synthetic systems require both non-default VRFs and VxLAN configured.",
        "56": "Synthetic systems configured with VLAN interfaces (SVIs) where the SVI is assigned to a VRF with ip routing disabled. IPv4 or IPv6 routing has been disabled. The check for IP routing is not required for this platform. 7170 systems are vulnerable if an SVI is configured in any VLAN.",
    }[number]
    group = "<ul><li>EOS</li><ul><li>1.2.3F and below releases in the 1.2.x train.</li><li>All releases in the 1.1.x train</li></ul></ul>"
    if number == "56":
        group = "<p>EOS</p><ul><li>7170 platforms:</li><ul><li>1.2.3F and below releases in the 1.2.x train.</li></ul><li>For all X-Series:</li><ul><li>2.3.4M and below releases in the 2.3.x train.</li></ul></ul>"
    affected = "<ul><li>The following products are affected by this vulnerability:<ul><li>7170 series</li><li>Synthetic X-Series label</li></ul></li></ul>"
    if number == "54":
        platforms = "<ul><li>This is a platform-independent vulnerability and affects all systems running EOS with the versions identified above.</li><li>The following products are not affected:</li><ul><li>Synthetic independent product</li></ul></ul>"
    elif number == "55":
        platforms = (
            affected
            + "<ul><li>The following products are not affected:<ul><li>Synthetic independent product</li><li>Arista EOS-based products:</li><li>Synthetic excluded model</li><li>Another excluded model</li></ul></li></ul>"
        )
    else:
        platforms = (
            affected
            + "<ul><li>The following products are not affected:<ul><li>Synthetic independent product</li><li>Arista EOS-based products:<ul><li>Synthetic excluded model</li></ul></li></ul></li></ul>"
        )
    resolution = "<p>Synthetic publisher fixed-release context.</p><p>The vulnerability has been fixed in the following EOS versions:</p><ul><li>9.8.7F</li></ul>"
    if number == "55":
        resolution = "<p>Synthetic publisher fixed-release context.</p><p>The vulnerability is fixed in the following EOS versions:</p><ul><li>8.7.6M</li><li>Special releases:<ul><li>8.7.5.1F</li></ul></li></ul><p>Post upgrade impact on select platforms:</p><p>Synthetic core-facing interface changes can revert the default behavior.</p>"
    if number == "56":
        resolution = "<p>Synthetic publisher fixed-release context.</p><ul><li>For X-Series platforms, the vulnerability has been fixed in the following EOS versions:<ul><li>9.9.9F</li><li>Special releases<ul><li>9.9.8.1F</li></ul></li></ul></li><li>For 7170 platforms, the vulnerability has been fixed in 1.2.4F and above releases in the 1.2.x train. Note that the 7170 platforms running versions in EOS release trains 4.22.x, 4.23.x and 4.24.x are not affected.</li></ul>"
    body = f"""<div class="item-page"><div><h2>Security Advisory {int(number):04d}</h2></div>
    <table><tr><td>Revision</td><td>Date</td><td>Changes</td></tr><tr><td>1.0</td><td>October 7, 2020</td><td>Synthetic initial publication</td></tr></table>
    <p>The CVE-ID tracking this issue: {ids[0]}</p><h3>Description</h3><p>{description}</p>
    <h3>Symptoms</h3><p>{symptoms}</p><h3>Vulnerability Assessment</h3><p>Affected Software</p>{group}<p>Affected Platforms</p>{platforms}
    <h3>Mitigation</h3><p>Synthetic mitigation.</p><h3>Resolution</h3>{resolution}
    <h4>For More Information:</h4><p>CVE-2099-12345 is a synthetic unrelated footer reference.</p></div>"""
    return edit(
        body
    ).encode(), "https://www.arista.com/en/support/advisories-notices/security-advisory/" + slug


def parse(number, **kwargs):
    raw, url = source(number, **kwargs)
    return default_registry().normalize(raw, url, "arista")


def test_platform_independence_stays_restricted_to_eos_and_isis_context():
    d = parse("54")
    assert d["cves"] == ["CVE-2020-15897"]
    assert len(d["assessments"]) == 2
    affected, excluded = d["assessments"]
    assert affected["product"] == "Arista EOS" and affected["status"] == "affected"
    assert len(affected["versions"]) == 2
    assert affected["remediations"][0]["details"] == "9.8.7F"
    assert "IS-IS must be configured" in affected["exposure"][0]["details"]
    assert (
        excluded["product"] == "Synthetic independent product"
        and excluded["status"] == "unaffected"
    )


def test_flat_model_exclusions_do_not_become_blanket_eos_unaffectedness():
    claims = parse("55")["assessments"]
    eos = [a for a in claims if a["product"] == "Arista EOS"]
    assert len(eos) == 2
    assert eos[0]["status"] == "affected" and eos[0]["platforms"] == [
        "7170 series",
        "Synthetic X-Series label",
    ]
    assert eos[1]["status"] == "unaffected" and eos[1]["platforms"] == [
        "Synthetic excluded model",
        "Another excluded model",
    ]
    assert "post-upgrade" in eos[0]["exposure"][0]["details"]
    assert all(a["product"] not in eos[1]["platforms"] for a in claims)
    assert [r["details"] for r in eos[0]["remediations"]] == ["8.7.6M", "8.7.5.1F"]
    assert eos[0]["remediations"][1]["release_type"] == "special_release"


def test_7170_x_series_ranges_and_explicit_unaffected_trains_stay_separate():
    claims = parse("56")["assessments"]
    affected = [a for a in claims if a["status"] == "affected"]
    assert len(affected) == 2
    assert affected[0]["platforms"] == ["7170 platforms"]
    assert affected[0]["versions"] == [
        {"expression": "1.2.3F and below releases in the 1.2.x train."}
    ]
    assert affected[1]["platforms"] == ["X-Series"]
    assert affected[1]["versions"] == [
        {"expression": "2.3.4M and below releases in the 2.3.x train."}
    ]
    assert all(
        a["exposure"][1]["source_scope"].startswith("common_advisory_list_not_crossjoined")
        for a in affected
    )
    unaffected = next(a for a in claims if "explicit_unaffected_trains" in a["product_id"])
    assert unaffected["status"] == "unaffected" and unaffected["platforms"] == ["7170 platforms"]
    assert "4.24.x" in unaffected["versions"][0]["expression"]
    assert len({a["product_id"] for a in claims}) == len(claims)
    assert all(not a["remediations"] for a in claims if a["status"] == "unaffected")
    assert "1.2.4F" in affected[0]["remediations"][0]["details"]
    assert [r["details"] for r in affected[1]["remediations"]] == ["9.9.9F", "9.9.8.1F"]
    assert affected[1]["remediations"][1]["release_type"] == "special_release"
    assert all(
        r["availability"] == "vendor_reports_fixed" for a in affected for r in a["remediations"]
    )


@pytest.mark.parametrize(
    "number,old,new",
    [
        ("54", "Both modes are vulnerable", "Different prerequisite"),
        ("54", "All releases in the 1.1.x train", "1.1.0 through 2.2.0, except some models"),
        ("54", "with the versions identified above.", "without version restrictions."),
        ("54", "9.8.7F", "TBD, upcoming release"),
        (
            "54",
            "The vulnerability has been fixed in the following EOS versions:",
            "Another product fixes:",
        ),
        ("55", "both non-default VRFs and VxLAN configured", "VxLAN only"),
        ("55", "Arista EOS-based products:", "Unknown family:"),
        ("55", "Post upgrade impact on select platforms:", "Different resolution:"),
        ("55", "Special releases:", "Unreviewed conditional releases:"),
        ("56", "For all X-Series:", "All platforms:"),
        ("56", "7170 series", "Different series"),
        ("56", "IPv4 or IPv6 routing has been disabled", "All routing states"),
        ("56", "4.24.x are not affected.", "4.24.x require investigation."),
        ("56", "Arista EOS-based products:", "Unknown nested family:"),
        ("56", "Special releases<ul>", "Unknown branch<ul>"),
    ],
)
def test_scope_changes_require_review(number, old, new):
    with pytest.raises(ValueError):
        parse(number, edit=lambda s: s.replace(old, new))


def test_identity_and_software_branch_label_changes_require_review():
    raw, url = source("56")
    with pytest.raises(ValueError):
        routing_scope(raw, url.replace("11996-", "99999-"), "arista")
    with pytest.raises(ValueError):
        routing_scope(raw.replace(b"CVE-2020-15898", b"CVE-2099-54321"), url, "arista")
    with pytest.raises(ValueError):
        routing_scope(
            raw.replace(
                b"<li>7170 platforms:</li>",
                b"<li>7170 platforms:<ul><li>Unexpected condition</li></ul></li>",
            ),
            url,
            "arista",
        )
