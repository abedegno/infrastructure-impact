"""Synthetic older Arista articles exercise model, condition and matrix boundaries."""

import pytest

from infrastructure_impact.adapters.arista_legacy_scope import ROUTES
from infrastructure_impact.plugins.registry import default_registry


def wrapper(number, body, *, extra="", updated=False):
    slug, ids = ROUTES[number]
    revisions = "<tr><td>1.0</td><td>May 12th, 2021</td><td>Initial release</td></tr>"
    if updated:
        revisions += "<tr><td>1.3</td><td>August 19, 2021</td><td>Synthetic revision</td></tr>"
    raw = f"""<div class="item-page"><div><h2>Security Advisory {int(number):04d} PDF</h2></div>
    <h4>Updated: May 25th, 2021</h4><table><tr><td>Revision</td><td>Date</td><td>Changes</td></tr>{revisions}</table>
    <p>The CVE-IDs tracking this issue: {", ".join(ids)}</p>
    <h3>Description</h3><p>Synthetic source: optional configuration and source model restrictions apply.</p>{extra}
    <h3>Symptoms</h3><p>Synthetic prerequisite checks.</p>
    <h3>Vulnerability Assessment</h3>{body}
    <h3>Mitigation</h3><p>Synthetic mitigation.</p><h3>Resolution</h3>
    <p>Planned model-specific software; no actual release verification.</p></div>""".encode()
    return raw, "https://www.arista.com/en/support/advisories-notices/security-advisory/" + slug


def parse(number, body, **kwargs):
    raw, url = wrapper(number, body, **kwargs)
    return default_registry().normalize(raw, url, "arista")


def eos_body():
    return """<p>Affected Software</p><p>EOS</p><ul><li>4.24.2F and below releases in the 4.24.x train.</li></ul>
    <p>Affected Platforms</p><ul><li>The following products are affected by this vulnerability:<ul><li>7050X series</li></ul></li></ul>
    <ul><li>The following products are not affected:</li><ul><li>Example independent product</li>
    <li>Arista EOS-based products:<ul><li>7280R series</li></ul></li></ul></ul>"""


def ap_body():
    return """<p>Affected Software</p><ul><li>AP Build versions<ul><li>8.8.3-12 and below releases in the 8.8.3 train.</li></ul></li></ul>
    <p>Affected Platforms</p><ul><li>This vulnerability is applicable to following Arista Wireless Access Point platforms:<ul><li>C-75/C75-E</li><li>W-68</li></ul></li></ul>
    <p>These models have reached end of sale; the source describes support until 2023.</p>
    <ul><li>The following products are not affected:<ul><li>Arista EOS-based products</li>
    <li>Arista Wireless Access Points:<ul><li>C-250</li><li>O-105E</li></ul></li></ul></li></ul>"""


def dns_body():
    return """<p>Affected Software</p><p>EOS Versions</p><ul><li>4.25.1F and below releases in the 4.25.x train</li></ul>
    <p>Affected Platforms</p><p>This vulnerability affects all EOS products including the CloudEOS packaging described by the publisher.</p>
    <p>The following products are not affected * :</p><ul><li>Example excluded product</li></ul>
    <p>Native Linux customization caveat: ensure DNS Proxy is not enabled.</p>"""


def tls_body():
    return """<h4>Affected Software</h4><p>CloudVision Portal:</p><ul><li>2020.3.0 release</li></ul>
    <p>EOS:</p><ul><li>4.25.1F (if gRIBI is configured).</li></ul>
    <p>TerminAttr:</p><ul><li>TerminAttr-v1.11.0</li></ul><p>MOS:</p><ul><li>MOS-0.29.0</li></ul>
    <h3>Affected Platforms</h3><ul><li>The following products are affected by this vulnerability:<ul><li>7130 series</li><li>CloudVision Portal virtual appliance</li></ul></li>
    <li>The following products are not affected:<ul><li>Example excluded product</li></ul></li></ul>"""


def matrix_body(*, reverse=False):
    headers = [
        "Access Points C-250 C-260 C-230 C-235 C-200",
        "Access Points C-120 C-130 C-100 C-110 O-105 W-118",
        "Access Points C-75 O-90 C-65 W-68",
    ]
    rows = []
    for index, cid in enumerate(ROUTES["63"][1]):
        values = ["Y", "N", "N"] if index == 0 else ["N", "Y", "N"]
        if reverse:
            values.reverse()
        rows.append(
            "<tr><td>" + cid + "</td>" + "".join("<td>" + v + "</td>" for v in values) + "</tr>"
        )
    if reverse:
        headers.reverse()
    return (
        "<p>Affected Software</p><ul><li>All available versions of Wi-Fi AP software as per the impact matrix below</li></ul><p>Affected Platforms</p><table><tr><td>CVE ID</td>"
        + "".join("<td>" + h + "</td>" for h in headers)
        + "</tr>"
        + "".join(rows)
        + "</table>"
    )


def test_eos_affected_and_unaffected_models_never_become_blanket_family_statuses():
    record = parse("57", eos_body())
    claims = record["assessments"]
    affected = next(a for a in claims if a["status"] == "affected")
    excluded = next(
        a for a in claims if a["status"] == "unaffected" and a["product"] == "Arista EOS"
    )
    assert affected["platforms"] == ["7050X series"]
    assert excluded["platforms"] == ["7280R series"] and not excluded["versions"]
    assert affected["versions"] == [
        {"expression": "4.24.2F and below releases in the 4.24.x train."}
    ]
    assert all(a["scope"] == "cve_specific" for a in claims)
    assert "EVPN VxLAN" in affected["exposure"][0]["details"]
    assert not any(a["product"] == "7280R series" for a in claims)


def test_ap_aliases_and_historical_support_are_scoped_to_literal_models():
    record = parse("58", ap_body())
    affected = next(a for a in record["assessments"] if a["status"] == "affected")
    excluded = next(
        a
        for a in record["assessments"]
        if a["status"] == "unaffected" and a["product"] == affected["product"]
    )
    assert affected["platforms"] == ["C-75/C75-E", "W-68"]
    assert excluded["platforms"] == ["C-250", "O-105E"]
    assert "does not establish current support" in affected["exposure"][0]["details"]
    assert len(record["assessments"]) == 3


def test_dns_cohort_stays_shared_and_exclusions_keep_the_customization_caveat():
    record = parse("61", dns_body())
    assert set(record["cves"]) == {"CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686"}
    assert len(record["assessments"]) == 6
    assert all(a["scope"] == "bulletin_shared" for a in record["assessments"])
    assert all(
        "native-Linux customization caveat" in a["exposure"][0]["details"]
        for a in record["assessments"]
    )
    with pytest.raises(ValueError, match="caveat"):
        parse("61", dns_body().replace("DNS Proxy is not enabled", "Unreviewed prerequisite"))


def test_tls_conditions_are_literal_and_common_platforms_are_not_cross_joined():
    record = parse("62", tls_body())
    assert len(record["assessments"]) == 5
    eos = next(a for a in record["assessments"] if a["product"] == "Arista EOS")
    assert eos["versions"] == [{"expression": "4.25.1F (if gRIBI is configured)."}]
    assert not eos["platforms"]
    assert "does not map every platform to each software row" in eos["exposure"][0]["details"]
    assert not any(a["product"] == "7130 series" for a in record["assessments"])


def test_wifi_matrix_is_local_per_cve_model_group_and_ignores_reference_only_identifiers():
    record = parse(
        "63", matrix_body(), extra="<p>External reference only: CVE-2020-26135</p>", updated=True
    )
    assert len(record["assessments"]) == 36
    assert "CVE-2020-26135" not in record["cves"]
    assert any("CVE-2020-26135" in warning for warning in record["warnings"])
    affected = next(
        a
        for a in record["assessments"]
        if a["cve_id"] == "CVE-2020-24586" and "C-250" in a["platforms"]
    )
    unaffected = next(
        a
        for a in record["assessments"]
        if a["cve_id"] == "CVE-2020-24586" and "C-75" in a["platforms"]
    )
    assert affected["status"] == "affected" and unaffected["status"] == "unaffected"
    assert "C-235" in affected["platforms"] and "O-235" not in affected["platforms"]
    assert all(
        a["scope"] == "cve_specific" and not a["remediations"] for a in record["assessments"]
    )
    assert record["published_at"] == "2021-05-12" and record["updated_at"] == "2021-08-19"
    assert any("update header" in warning for warning in record["warnings"])
    assert "observed_at" not in record


def test_reordered_matrix_columns_keep_their_own_model_statuses():
    first = parse("63", matrix_body())["assessments"]
    second = parse("63", matrix_body(reverse=True))["assessments"]

    def key(a):
        return a["cve_id"], tuple(a["platforms"]), a["status"]

    assert sorted(map(key, first)) == sorted(map(key, second))


@pytest.mark.parametrize(
    "before,after",
    [
        ("<td>Y</td>", "<td>?</td>"),
        ("<td>CVE ID</td>", '<td colspan="2">CVE ID</td>'),
        ("<p>Affected Platforms</p>", "<p>Unreviewed examples</p>"),
        ("Access Points C-75 O-90 C-65 W-68", "Access Points All models"),
        ("CVE-2020-26147", "CVE-2025-12345"),
    ],
)
def test_changed_matrix_boundaries_cells_or_identities_fail(before, after):
    with pytest.raises(ValueError):
        parse("63", matrix_body().replace(before, after))


def test_unknown_nested_exclusions_and_version_qualifiers_fail_closed():
    for body in [
        eos_body().replace("Arista EOS-based products:", "All other products:"),
        eos_body().replace("4.24.x train.", "unreviewed train."),
        eos_body().replace(
            "<li>7280R series</li>", "<li>7280R series<ul><li>conditional submodel</li></ul></li>"
        ),
    ]:
        with pytest.raises(ValueError):
            parse("57", body)
    raw, url = wrapper("57", eos_body())
    with pytest.raises(ValueError):
        default_registry().normalize(
            raw.replace(b"Security Advisory 0057", b"Security Advisory 0058"), url, "arista"
        )
