"""Non-CVE notice retention must never turn advisory IDs into CVE claims."""

import json

import pytest

from infrastructure_impact.adapters.pan_notices import TITLE, URL
from infrastructure_impact.collection.service import run
from infrastructure_impact.plugins.paloalto import resolve
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.storage.repository import connect, latest


def source(edit=lambda value: value):
    return edit(f"""<div id="content"><h2>{TITLE}</h2>
    <div class="sa_summary">Informational JSON CSAF Published 2025-02-12 Updated 2025-02-12</div>
    <h3>Description</h3><p>Synthetic configuration notice without a CVE.</p>
    <h3>Product Status</h3><table><tr><th>Versions</th><th>Affected</th><th>Unaffected</th></tr>
    <tr><td>Cloud NGFW</td><td>None</td><td>All</td></tr><tr><td>PAN-OS</td><td>All</td><td>None</td></tr><tr><td>Prisma Access</td><td>All</td><td>None</td></tr></table>
    <h3>Required Configuration for Exposure</h3><p>All of the following must be true: a valid GlobalProtect Subscription license; Clientless VPN is enabled; Security Policies allow Clientless VPN access to more than one internal or external Application.</p>
    <h3>Exploitation Status</h3><p>Synthetic status.</p><h3>Workarounds and Mitigations</h3><p>Synthetic configuration restrictions.</p><h3>Acknowledgments</h3><p>Synthetic credit.</p><h3>Timeline</h3><div>2025-02-12 Synthetic publication.</div></div>""").encode()


def test_notice_is_retained_with_no_cve_or_product_assessments():
    plugin = default_registry().get("paloalto")
    raw = source()
    record = default_registry().normalize(raw, URL, "paloalto")
    assert plugin.retain_unlinked_notice(record)
    assert record["cves"] == record["assessments"] == []
    assert record["published_at"] == record["updated_at"] == "2025-02-12"
    assert "notice-scoped" in record["warnings"][0]
    assert not plugin.retain_unlinked_notice({**record, "cves": ["CVE-2025-12345"]})
    assert not plugin.retain_unlinked_notice({**record, "source_url": URL + "/unreviewed"})
    assert resolve(
        raw, URL, lambda _: pytest.fail("Non-CVE notice must not auto-follow invalid-CVE export")
    ) == (URL, raw)


@pytest.mark.parametrize(
    "old,new",
    [
        ("Clientless VPN Misconfiguration Allows Cross-Site Attacks", "Different issue"),
        ("Synthetic configuration notice without a CVE.", "Assigned CVE-2025-12345."),
        (
            "<td>Cloud NGFW</td><td>None</td><td>All</td>",
            "<td>Cloud NGFW</td><td>All</td><td>None</td>",
        ),
        ("valid GlobalProtect Subscription license", "no subscription prerequisite"),
        ("Clientless VPN is enabled", "Different enabled feature"),
        ("<h3>Required Configuration for Exposure</h3>", "<h3>New applicability section</h3>"),
        ("Published 2025-02-12", "Published unknown"),
    ],
)
def test_changed_identity_cve_or_configuration_scope_requires_review(old, new):
    with pytest.raises(ValueError):
        default_registry().normalize(source(lambda value: value.replace(old, new)), URL, "paloalto")


def test_structured_pan_sa_placeholder_remains_invalid_as_a_cve():
    raw = json.dumps(
        {
            "document": {"title": "Synthetic notice", "tracking": {"id": "PAN-SA-2025-0005"}},
            "vulnerabilities": [
                {
                    "cve": "PAN-SA-2025-0005",
                    "product_status": {"known_affected": ["synthetic-product"]},
                }
            ],
        }
    ).encode()
    with pytest.raises(ValueError):
        default_registry().normalize(
            raw, "https://security.paloaltonetworks.com/csaf/PAN-SA-2025-0005", "paloalto"
        )


def test_collector_imports_notice_without_creating_cve_assessments(tmp_path, monkeypatch):
    import infrastructure_impact.collection.service as service

    monkeypatch.setattr(service, "fetch", lambda db, url, vendor: source())
    database = tmp_path / "notice.sqlite3"
    assert run(
        {"vendors": [], "pinned": [{"vendor": "paloalto", "url": URL}], "release_documents": []},
        db_path=database,
    ) == (1, 0)
    with connect(database) as db:
        records = latest(db)
        assert len(records) == 1 and not records[0]["cves"] and not records[0]["assessments"]
        from infrastructure_impact.application.query import state

        assert "PAN-SA-2025-0005" not in state(db)["all_cves"]
