"""Family evidence, comparable-cohort gates and fix-lead provenance boundaries."""

from infrastructure_impact.application.families import completeness, matches

PAN_URL = "https://docs.paloaltonetworks.com/oss-listings/panorama-oss-listings/panorama-11-2-open-source-software-oss-listing"


def inventory(version="3.0.10"):
    return f"<h1>Panorama 11.2 OSS Listing</h1><p>Open-Source Software (OSS) licensing for the Panorama release.</p><table><tr><th>NAME</th><th>VERSION</th><th>LICENSE TYPE</th></tr><tr><td>openssl</td><td>{version}</td><td>Example license</td></tr><tr><td>openssh</td><td>8.0p1</td><td>Example license</td></tr><tr><td></td><td></td></tr></table>".encode()


def test_component_inventory_requires_reviewed_identity_table_and_literal_versions():
    import pytest

    from infrastructure_impact.adapters.pan_components import component_inventory

    result = component_inventory(inventory(), PAN_URL, "paloalto")
    assert result["components"] == {"openssl": ["3.0.10"], "openssh": ["8.0p1"]}
    assert "No running-appliance" in result["component_scope"] and not any(
        b["cves"] for b in result["blocks"]
    )
    assert component_inventory(inventory(), "https://example.test/list", "paloalto") is None
    for before, after in [
        (b"Panorama 11.2 OSS Listing", b"PAN-OS 11.2 OSS Listing"),
        (b"VERSION", b"UPSTREAM AFFECTED RANGE"),
        (b"3.0.10", b"before 3.0.10"),
    ]:
        with pytest.raises(ValueError):
            component_inventory(inventory().replace(before, after), PAN_URL, "paloalto")


def test_component_listings_keep_multiple_versions_ambiguous_and_require_pan_scope():
    import pytest

    from infrastructure_impact.adapters.pan_components import component_inventory

    assert component_inventory(inventory("3.0.10, 3.0.11"), PAN_URL, "paloalto")["components"][
        "openssl"
    ] == ["3.0.10", "3.0.11"]
    pan_url = PAN_URL.replace("panorama", "pan-os")
    raw = inventory().replace(b"Panorama", b"PAN-OS")
    with pytest.raises(ValueError):
        component_inventory(raw, pan_url, "paloalto")
    raw += b"<p>Our goal is the latest maintenance release; we do not attempt to capture these differences in detail or per product.</p>"
    assert component_inventory(raw, pan_url, "paloalto")["state"] == "scoped"


def test_component_collection_rejects_invalid_listing_without_creating_a_baseline(
    tmp_path, monkeypatch
):
    from infrastructure_impact.collection import service
    from infrastructure_impact.storage.repository import connect

    monkeypatch.setattr(service, "fetch", lambda *args: b"<h1>Unreviewed layout</h1>")
    path = tmp_path / "vault.sqlite3"
    config = dict(
        vendors=[],
        release_documents=[
            dict(vendor="paloalto", url=PAN_URL, product="Panorama OSS", kind="component_inventory")
        ],
    )
    result = service.run(config, db_path=path)
    with connect(path) as db:
        assert db.execute("SELECT count(*) FROM documents").fetchone()[0] == 0
    assert result == (0, 1)


def family():
    return dict(id="test", vendor="juniper", prefixes=["Junos OS"], platform_prefixes=["SRX"])


def test_mixed_platforms_are_not_split_into_comparable_family_evidence():
    f = family()
    assert matches(f, dict(product="Junos OS", platforms=["SRX Series"]))
    assert not matches(f, dict(product="Junos OS", platforms=["SRX Series", "MX Series"]))
    assert not matches(f, dict(product="Junos OS"))


def test_family_prefixes_do_not_turn_switch_software_into_wireless():
    f = dict(prefixes=["ArubaOS"], platform_prefixes=[])
    assert matches(f, dict(product="ArubaOS 8"))
    assert not matches(f, dict(product="ArubaOS-Switch"))


def test_missing_family_is_unknown_and_release_reference_is_not_train_completeness():
    data = dict(
        vendors={"hpe": "HPE", "arista": "Arista"},
        records=[
            dict(
                vendor="arista",
                advisory_id="TEST",
                source_url="https://www.arista.com/advisory",
                sha256="a" * 64,
                published_at="2026-01-01",
                assessments=[
                    dict(
                        product="Arista EOS",
                        cve_id="CVE-2026-12345",
                        status="affected",
                        scope="bulletin_shared",
                        versions=[dict(expression="4.35.2 and below in 4.35.x train")],
                    )
                ],
            )
        ],
    )
    r = completeness(data)
    msa = next(f for f in r["families"] if f["id"] == "hpe-msa")
    eos = next(f for f in r["families"] if f["id"] == "arista-eos")
    assert msa["state"] == "unknown" and msa["inventory_completeness"] == "not_established"
    assert eos["explicit_statements"] == 0 and eos["shared_statements"] == 1
    assert next(t for t in eos["train_references"] if t["train"] == "4.35")["state"] == "referenced"
    assert next(t for t in eos["train_references"] if t["train"] == "4.34")["state"] == "unknown"


def test_readiness_keeps_the_same_cohort_for_missing_families_and_blocks_rates():
    from infrastructure_impact.application.readiness import readiness

    data = dict(
        vendors={"cisco": "Cisco", "hpe": "HPE"},
        records=[],
        generated_at="2026-10-26T12:00:00Z",
        benchmark_cohort=["CVE-2026-12345", "CVE-2021-44228"],
    )
    data["family_completeness"] = completeness(data)
    result = readiness(data)
    assert result["eligible_comparisons"] == []
    assert all(p["cohort"] == ["CVE-2021-44228", "CVE-2026-12345"] for p in result["plans"])
    assert all(
        p["state"] == "blocked" and p["rate_comparison"] == "suppressed" for p in result["plans"]
    )
    assert all(
        m["comparison_rate"] is None and m["unknown_or_unresolved_cases"] == 2
        for p in result["plans"]
        for m in p["members"]
    )


def test_a_fixed_only_statement_does_not_establish_prior_exposure_for_comparison():
    from infrastructure_impact.application.readiness import readiness

    r = dict(
        vendor="cisco",
        advisory_id="TEST",
        source_url="https://www.cisco.com/test",
        sha256="a" * 64,
        published_at="2026-01-01",
        assessments=[
            dict(
                product="Cisco NX-OS Software",
                cve_id="CVE-2026-12345",
                status="fixed",
                scope="cve_specific",
                versions=[],
            )
        ],
    )
    data = dict(
        vendors={"cisco": "Cisco"},
        records=[r],
        generated_at="2026-10-26T12:00:00Z",
        benchmark_cohort=["CVE-2026-12345"],
    )
    data["family_completeness"] = completeness(data)
    row = next(
        m for p in readiness(data)["plans"] for m in p["members"] if m["family_id"] == "cisco-nxos"
    )
    assert row["explicit_cases"] == 0 and row["state"] == "blocked"
    assert row["cases"][0]["state"] == "unresolved"
    assert row["cases"][0]["evidence"][0]["source_sha256"] == "a" * 64


def test_readiness_retains_excluded_evidence_and_protocol_without_counting_it():
    from infrastructure_impact.application.readiness import readiness

    record = dict(
        vendor="cisco",
        advisory_id="TEST",
        source_url="https://www.cisco.com/test",
        sha256="b" * 64,
        published_at=None,
        assessments=[
            dict(
                product="Cisco NX-OS Software",
                cve_id="CVE-2026-12345",
                status="affected",
                scope="cve_specific",
                versions=[dict(expression="1.0")],
                platforms=["Nexus"],
            )
        ],
    )
    data = dict(
        vendors={"cisco": "Cisco"},
        records=[record],
        generated_at="2026-10-26T12:00:00Z",
        benchmark_cohort=["CVE-2026-12345"],
    )
    data["family_completeness"] = completeness(data)
    plan = next(p for p in readiness(data)["plans"] if p["id"] == "switching")
    row = next(m for m in plan["members"] if m["family_id"] == "cisco-nxos")
    assert row["explicit_cases"] == 0 and row["cases"][0]["state"] == "unknown"
    evidence = row["cases"][0]["evidence"][0]
    assert evidence["period_state"] == "undated_excluded" and evidence["platforms"] == ["Nexus"]
    assert plan["protocol"]["confounders"] and plan["rate_comparison"] == "suppressed"


def release_snapshot(raw, digest, at):
    from infrastructure_impact.application.fix_leads import scoped_release

    return dict(
        source_url="https://docs.fortinet.com/document/fortigate/7.2.7/release-notes",
        source_sha256=digest * 64,
        observed_at=at,
        publisher_date_claim=None,
        analysis=scoped_release(raw),
    )


def test_component_change_requires_scoped_explicit_versions_and_two_snapshots():
    from infrastructure_impact.application.fix_leads import leads

    before = release_snapshot(
        b"<h2>Component Versions</h2><p>OpenSSL 3.0.10</p>", "a", "2026-01-01T00:00:00Z"
    )
    after = release_snapshot(
        b"<h2>Component Versions</h2><p>OpenSSL 3.0.11</p>", "b", "2026-01-02T00:00:00Z"
    )
    source = dict(
        vendor="fortinet",
        product="FortiOS test",
        source_url=after["source_url"],
        snapshots=[after, before],
    )
    result = leads(dict(research=dict(lead_inputs=dict(release_sources=[source]))))
    changed = next(lead for lead in result["leads"] if lead["kind"] == "component_version_changed")
    assert (
        len(changed["evidence"]) == 2
        and changed["concealment"] == "not_established"
        and changed["alternative_explanations"]
    )
    source["snapshots"] = [after]
    result = leads(dict(research=dict(lead_inputs=dict(release_sources=[source]))))
    assert not result["leads"] and any(
        g["reason"] == "no_comparable_prior_snapshot" for g in result["analysis_gaps"]
    )


def test_navigation_churn_and_unscoped_security_text_do_not_generate_fix_leads():
    from infrastructure_impact.application.fix_leads import scoped_release

    raw = b"<nav><p>security vulnerabilities PHP 8.0</p></nav><h2>Resolved Issues</h2><table><tr><td>Fixed vulnerability CVE-2026-12345</td></tr></table><h2>Support</h2><p>OpenSSL 3.0.11</p>"
    result = scoped_release(raw)
    assert (
        len(result["blocks"]) == 1
        and result["blocks"][0]["cves"] == ["CVE-2026-12345"]
        and not result["components"]
    )


def test_security_statement_without_cve_is_only_a_scoped_investigation_lead():
    from infrastructure_impact.application.fix_leads import leads

    s = release_snapshot(
        b"<h2>Security Fixes</h2><p>Corrected an authentication bypass.</p>",
        "a",
        "2026-01-01T00:00:00Z",
    )
    result = leads(
        dict(
            research=dict(
                lead_inputs=dict(
                    release_sources=[
                        dict(
                            vendor="fortinet",
                            product="Test",
                            source_url=s["source_url"],
                            snapshots=[s],
                        )
                    ]
                )
            )
        )
    )
    lead = result["leads"][0]
    assert lead["kind"] == "security_statement_without_cve" and not lead["cve_ids"]
    assert (
        lead["state"] == "investigation_required"
        and lead["evidence"][0]["observed_at"] == "2026-01-01T00:00:00Z"
    )


def test_public_lead_inputs_exclude_unregistered_documents_and_unknown_fields():
    from infrastructure_impact.application.fix_leads import public_inputs

    s = release_snapshot(
        b"<h2>Component Versions</h2><p>OpenSSL 3.0.10</p>", "a", "2026-01-01T00:00:00Z"
    )
    s["analysis"]["PRIVATE_SENTINEL"] = "private"
    source = dict(
        vendor="fortinet",
        product="Test",
        source_url=s["source_url"],
        snapshots=[s],
        PRIVATE_SENTINEL="private",
    )
    assert public_inputs(dict(release_sources=[source]), [], [])["release_sources"] == []
    result = public_inputs(dict(release_sources=[source]), [s["source_url"]], [])
    import json

    assert "PRIVATE_SENTINEL" not in json.dumps(result)


def test_public_reports_share_generation_and_remove_private_inputs(tmp_path):
    import json

    from infrastructure_impact.adapters.common import assessment, base
    from infrastructure_impact.application.disclosure import import_release_note
    from infrastructure_impact.application.publication import publish
    from infrastructure_impact.application.query import state
    from infrastructure_impact.http import Application
    from infrastructure_impact.storage.repository import connect, ingest

    url = "https://docs.fortinet.com/document/fortigate/7.2.7/release-notes"
    with connect(":memory:") as db:
        record = base(
            "fortinet",
            "https://www.fortiguard.com/psirt/SYNTHETIC",
            "SYNTHETIC",
            "Synthetic",
            published="2026-01-01",
        )
        record["cves"] = ["CVE-2026-12345"]
        record["assessments"] = [
            assessment(
                "CVE-2026-12345", "FortiOS 7.2", "affected", "Synthetic", [dict(expression="7.2.0")]
            )
        ]
        ingest(db, b"synthetic", record["source_url"], lambda *args: record, "fortinet")
        for version in ["3.0.10", "3.0.11"]:
            import_release_note(
                db,
                f"<h2>Component Versions</h2><p>OpenSSL {version}</p>".encode(),
                url,
                "fortinet",
                "FortiOS test",
            )
            import_release_note(
                db, inventory(version), PAN_URL, "paloalto", "Panorama 11.2 OSS reference"
            )
        data = state(db)
    data["family_completeness"]["PRIVATE_SENTINEL"] = "private"
    data["fix_leads"]["PRIVATE_SENTINEL"] = "private"
    generation = publish(data, tmp_path, public_release_urls=[url, PAN_URL])
    snapshot = json.loads((generation / "snapshot.json").read_text())
    assert "lead_inputs" not in snapshot["research"] and "PRIVATE_SENTINEL" not in json.dumps(
        snapshot
    )
    assert any(
        lead["kind"] == "component_version_changed" for lead in snapshot["fix_leads"]["leads"]
    )
    component_lead = next(
        lead for lead in snapshot["fix_leads"]["leads"] if lead["vendor"] == "paloalto"
    )
    assert (
        component_lead["kind"] == "component_version_changed"
        and component_lead["concealment"] == "not_established"
    )
    assert len(component_lead["evidence"]) == 2
    source = next(s for s in snapshot["fix_leads"]["sources"] if s["vendor"] == "paloalto")
    assert "patch" in source["component_scope"] and source["components"]["openssl"] == ["3.0.11"]
    app = Application(tmp_path)
    for name in ["family-completeness", "comparison-readiness", "fix-leads"]:
        status, _, raw = app.route(
            dict(
                REQUEST_METHOD="GET",
                PATH_INFO="/api/v1/" + name,
                QUERY_STRING="cves=CVE-2021-44228",
            )
        )
        assert status == 200 and json.loads(raw)["publication"] == snapshot["publication"]
        assert (generation / "schemas" / (name + "-v1.json")).exists()
