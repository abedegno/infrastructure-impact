"""Synthetic scope guards for two reviewed informational bulletins."""

import json

import pytest

from infrastructure_impact.plugins.paloalto import resolve
from infrastructure_impact.plugins.registry import default_registry

BASE = "https://security.paloaltonetworks.com/"
NAT = "PAN-SA-2021-0002"
MOVE = "PAN-SA-2023-0003"
PRODUCTS = (
    "AutoFocus;Bridgecrew;Cloud NGFW;Cortex Data Lake;Cortex XDR;Cortex XDR Agent;"
    "Cortex Xpanse;Cortex XSOAR;Enterprise Data Loss Prevention;Exact Data Matching CLI;"
    "Expanse;Expedition Migration Tool;GlobalProtect App;IoT Security;Okyo Garde;"
    "Palo Alto Networks App for Splunk;PAN-OS;Prisma Access;Prisma Cloud;"
    "Prisma Cloud Compute;Prisma SD-WAN (CloudGenix);Prisma SD-WAN ION;SaaS Security;"
    "User-ID Agent;WildFire Appliance (WF-500);WildFire Cloud"
).split(";")
CVES = ["CVE-2023-34362", "CVE-2023-35036", "CVE-2023-35708"]


def page(identity):
    move = identity == MOVE
    title = (
        f"{MOVE} Informational Bulletin: Impact of MOVEit Vulnerabilities ({', '.join(CVES)})"
        if move
        else f"{NAT} Informational: PAN-OS: NAT slipstreaming v1.0 and v2.0 attacks"
    )
    description = (
        f"Synthetic scope: {', '.join(CVES)}. Palo Alto Networks does not use MOVEit Transfer "
        "and is not impacted by these vulnerabilities."
        if move
        else "Synthetic NAT advisory without a CVE."
    )
    solution = (
        "No software updates are required at this time."
        if move
        else "A PAN-OS software upgrade is not required to mitigate NAT slipstreaming attacks. "
        + " ".join(
            f"NAT Slipstreaming Detection ({n})" for n in [59667, 59668, 59669, 59671, 59672]
        )
    )
    status = "".join(
        f"<tr><td>{p}</td><td>None</td><td>All</td></tr>"
        for p in (PRODUCTS if move else ["PAN-OS"])
    )
    context = (
        "<h3>Exploitation Status</h3><p>Synthetic status.</p>"
        if move
        else "<h3>Required Configuration for Exposure</h3><p>Cannot be exposed.</p>"
    )
    return (
        f'<div id="content"><h2>{title}</h2><div class="sa_summary">Informational '
        "Published 2023-06-16 Updated 2023-06-20</div>"
        f"<h3>Description</h3><p>{description}</p><h3>Product Status</h3><table>"
        "<tr><th>Versions</th><th>Affected</th><th>Unaffected</th></tr>"
        f"{status}</table>{context}<h3>Solution</h3><p>{solution}</p>"
        "<h3>Workarounds and Mitigations</h3><p>Synthetic qualified guidance.</p>"
        "<h3>Timeline</h3><p>Synthetic timeline.</p></div>"
    )


def normalize(identity, text=None):
    return default_registry().normalize(
        (text or page(identity)).encode(), BASE + identity, "paloalto"
    )


def test_nat_notice_has_no_fabricated_cve_or_upgrade():
    record = normalize(NAT)
    assert record["cves"] == record["assessments"] == []
    assert default_registry().get("paloalto").retain_unlinked_notice(record)
    assert record["published_at"] == "2023-06-16"
    assert record["updated_at"] == "2023-06-20"
    assert record["notes"] and record["warnings"]


def test_moveit_explicit_product_rows_are_unaffected_without_fix_versions():
    record = normalize(MOVE)
    assert record["cves"] == CVES
    pairs = {(a["cve_id"], a["product"]) for a in record["assessments"]}
    assert len(record["assessments"]) == len(pairs) == 78
    assert ("CVE-2023-34362", "PAN-OS") in pairs
    assert ("CVE-2023-35708", "WildFire Appliance (WF-500)") in pairs
    for claim in record["assessments"]:
        assert claim["status"] == "unaffected"
        assert claim["scope"] == "cve_specific"
        assert claim["versions"] == claim["remediations"] == []
        assert claim["exposure"] and "Product Status" in claim["evidence_locator"]


@pytest.mark.parametrize("identity", [NAT, MOVE])
def test_article_boundaries_exclude_cve_date_and_table_decoys(identity):
    decoy = "<p>CVE-2025-99999 Published 2099-01-01</p><table><tr><td>Other</td></tr></table>"
    assert normalize(identity, decoy + page(identity) + decoy) == normalize(identity)


@pytest.mark.parametrize("identity", [NAT, MOVE])
@pytest.mark.parametrize(
    "old,new",
    [
        ('id="content"', 'id="other"'),
        ("<h3>Product Status</h3>", "<h3>Unexpected status</h3>"),
        ("<td>None</td><td>All</td>", "<td>All</td><td>None</td>"),
        ("Published 2023-06-16", "Published unknown"),
        ("Updated 2023-06-20", "Updated 2023-06-20 Updated 2023-06-21"),
        ("<h3>Description</h3>", "<h3>Description</h3><p>CVE-2025-99999</p>"),
        ("<h3>Timeline</h3>", "<h3>Solution</h3>"),
    ],
)
def test_changed_or_missing_scope_fails_closed(identity, old, new):
    with pytest.raises(ValueError):
        normalize(identity, page(identity).replace(old, new))


@pytest.mark.parametrize("identity", [NAT, MOVE])
def test_duplicate_article_or_metadata_is_ambiguous(identity):
    for text in [page(identity) * 2, page(identity).replace('class="sa_summary"', 'class="other"')]:
        with pytest.raises(ValueError):
            normalize(identity, text)


@pytest.mark.parametrize(
    "old,new",
    [
        ("does not use MOVEit Transfer", "uses MOVEit Transfer"),
        ("No software updates are required", "Software updates are required"),
        ("<td>AutoFocus</td>", "<td>PAN-OS</td>"),
        ("CVE-2023-35708", "CVE-2023-99999"),
    ],
)
def test_moveit_scope_changes_are_not_silently_reused(old, new):
    with pytest.raises(ValueError):
        normalize(MOVE, page(MOVE).replace(old, new))


@pytest.mark.parametrize("identity", [NAT, MOVE])
def test_resolver_preserves_reviewed_html_instead_of_export(identity):
    raw = page(identity).encode()
    assert resolve(raw, BASE + identity, lambda _: pytest.fail("unexpected export fetch")) == (
        BASE + identity,
        raw,
    )


@pytest.mark.parametrize("identity", [NAT, MOVE, "PAN-SA-2025-0005"])
@pytest.mark.parametrize("prefix", ["", "csaf/", "json/"])
@pytest.mark.parametrize("text_input", [False, True])
def test_known_html_policies_cannot_be_overridden_by_populated_csaf(identity, prefix, text_input):
    raw = json.dumps(
        {
            "document": {"title": "Synthetic", "tracking": {"id": identity}},
            "product_tree": {"full_product_names": [{"product_id": "p", "name": "PAN-OS"}]},
            "vulnerabilities": [
                {"cve": "CVE-2025-99999", "product_status": {"known_affected": ["p"]}}
            ],
        }
    ).encode()
    if text_input:
        raw = raw.decode()
    with pytest.raises(ValueError):
        default_registry().normalize(raw, BASE + prefix + identity, "paloalto")


def test_reviewed_route_query_cannot_bypass_representation_guard():
    raw = json.dumps({"document": {"tracking": {"id": "other"}}}).encode()
    with pytest.raises(ValueError):
        resolve(raw, BASE + "csaf/" + MOVE + "?download=1", lambda _: None)


@pytest.mark.parametrize("identity", [NAT, MOVE, "PAN-SA-2025-0005"])
def test_reviewed_identity_cannot_bypass_guard_under_another_route(identity):
    raw = json.dumps({"document": {"tracking": {"id": identity}}}).encode()
    with pytest.raises(ValueError):
        resolve(raw, BASE + "csaf/CVE-2025-99999", lambda _: None)


def test_collector_preserves_notice_and_unaffected_rows_without_fake_cves(tmp_path, monkeypatch):
    from infrastructure_impact.application.query import state
    from infrastructure_impact.collection import service
    from infrastructure_impact.storage.repository import connect, latest

    documents = {BASE + identity: page(identity).encode() for identity in (NAT, MOVE)}
    monkeypatch.setattr(service, "fetch", lambda db, url, vendor: documents[url])
    config = {"vendors": [], "pinned": [{"vendor": "paloalto", "url": u} for u in documents]}
    database = tmp_path / "public.sqlite3"
    assert service.run(config, db_path=database) == (2, 0)
    with connect(database) as db:
        assert len(latest(db)) == 2
        assert state(db)["all_cves"] == CVES
    assert service.run(config, db_path=database) == (0, 0)
