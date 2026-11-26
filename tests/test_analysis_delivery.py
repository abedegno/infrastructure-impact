"""Vendor previews preserve complete selected exports and source closure."""

import copy

import pytest
from test_switching_analysis import api, fixture

from infrastructure_impact.application import analysis_delivery as delivery


def source():
    _, _, _, study = fixture()
    return api().build_report([], [], study), study


@pytest.mark.parametrize("vendor", ["cisco", "aruba", "arista"])
@pytest.mark.parametrize("scope", ["os_family", "model_qualified"])
@pytest.mark.parametrize("window", ["all", "2024", "2025", "undated"])
@pytest.mark.parametrize("cves", [None, [], ["CVE-1999-99999"]])
def test_vendor_selected_exports_equal_full_source(vendor, scope, window, cves):
    full, _ = source()
    envelope = delivery.project_vendor(full, vendor)
    delivery.validate_vendor(envelope, source=full)
    study = api().selection_context(
        full, dict(vendor=vendor, scope_level=scope, window=window, cve_ids=cves)
    )
    expected = api().select_report(full, study)
    actual = delivery.select_vendor(envelope, study)
    assert actual == expected
    assert api().analysis_csv_export(actual) == api().analysis_csv_export(expected)
    assert api().csv_export(actual["upgrades"]) == api().csv_export(expected["upgrades"])


def test_vendor_domain_regeneration_and_bounds():
    full, _ = source()
    envelope = delivery.project_vendor(full, "cisco")
    bad = copy.deepcopy(envelope)
    bad["source_content_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        delivery.validate_vendor(bad, source=full)
    with pytest.raises(ValueError):
        delivery.project_vendor(full, "unknown")
    with pytest.raises(ValueError):
        delivery.select_vendor(envelope, api().selection_context(full, {}))
    with pytest.raises(ValueError):
        delivery.project_vendor(full, "cisco", max_bytes=1)
    bad = copy.deepcopy(full)
    bad["content_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        delivery.project_vendor(bad, "cisco")


def test_public_vectors_preserve_kev_history_groups_and_all_exports():
    import json
    from pathlib import Path

    vectors = json.loads(Path("tests/fixtures/switching-analysis-vectors.json").read_text())
    full = vectors["compiled"]
    for vendor in delivery.VENDORS:
        envelope = delivery.project_vendor(full, vendor)
        assert envelope["payload"]["release_history"] == full["release_history"]
        assert [
            e
            for e in envelope["payload"]["kev_reconciliation"]["entries"]
            if e["mapping"]["vendor"] is None
        ] == [
            e
            for e in api()._kev_selected(
                full, api().selection_context(full, dict(vendor=vendor))["selection"]
            )["entries"]
            if e["mapping"]["vendor"] is None
        ]
        for case in vectors["cases"]:
            options = dict(case["options"], vendor=vendor)
            context = api().selection_context(full, options)
            actual = delivery.select_vendor(envelope, context)
            expected = api().select_report(full, context)
            assert actual == expected
            assert api().analysis_csv_export(actual) == api().analysis_csv_export(expected)
            assert api().csv_export(actual["upgrades"]) == api().csv_export(expected["upgrades"])


def test_opt_in_publication_roots_and_native_regeneration(tmp_path):
    import json
    from pathlib import Path

    from test_static_delivery import dataset

    from infrastructure_impact.application import publication, publication_v2
    from infrastructure_impact.application.publication_reader import PublicationReader

    data = dataset()
    data["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    data["current_evidence"]["publication"] = data["publication"]
    data["research"]["switching_input"] = json.loads(
        Path("tests/fixtures/switching-cases.json").read_text()
    )["evidence"]
    public = publication.public_projection(
        data, publication_format="v2", include_switching_analysis=True
    )
    publication.write_bundle(tmp_path / "default", public, publication_format="v2")
    baseline = PublicationReader(tmp_path / "default")
    assert delivery.MANIFEST not in baseline.catalog["roots"]
    publication_v2.write_bundle(tmp_path / "preview", public, analysis_vendor_delivery=True)
    reader = PublicationReader(tmp_path / "preview")
    manifest = reader.materialize_range(reader.ranges(delivery.MANIFEST)[()])
    assert set(manifest["vendors"]) == set(delivery.VENDORS)
    publication_v2.verify_projection(reader, public)
    for vendor in delivery.VENDORS:
        name = delivery.root_name(vendor)
        envelope = reader.materialize_range(reader.ranges(name)[()])
        delivery.validate_vendor(envelope, source=public["switching_analysis"])
    for name in baseline.catalog["roots"]:
        assert baseline.root(name)["logical"] == reader.root(name)["logical"]
    with pytest.raises(ValueError, match="v2"):
        publication.write_bundle(tmp_path / "v1", public, analysis_vendor_delivery=True)


def test_rehashed_omission_is_rejected_against_native_source():
    full, _ = source()
    # An empty domain is locally well formed, but cannot replace a nonempty
    # advertised vendor. Regeneration, rather than a caller-owned hash, proves it.
    bad = delivery.project_vendor(full, "aruba")
    bad["vendor"] = "cisco"
    bad["content_sha256"] = delivery._digest(bad)
    with pytest.raises(ValueError, match="source closure"):
        delivery.validate_vendor(bad, source=full)
    bad = delivery.project_vendor(full, "cisco")
    bad["payload"]["requirements"]["requirements"].pop()
    r = bad["payload"]["requirements"]
    r["content_sha256"] = delivery._digest(r)
    bad["payload"]["content_sha256"] = delivery._digest(bad["payload"])
    bad["counts"] = delivery._counts(bad["payload"])
    bad["content_sha256"] = delivery._digest(bad)
    with pytest.raises(ValueError, match="scenario"):
        delivery.validate_vendor(bad)


def rich_source():
    """Authored multi-vendor evidence with inference, history and KEV gaps."""
    import json

    from test_switching_aruba_fix_links import projected as aruba_evidence
    from test_switching_kev_reconciliation import AT, claim
    from test_switching_kev_reconciliation import inputs as kev_inputs
    from test_switching_release_history import frame
    from test_switching_upgrades import inputs

    from infrastructure_impact.adapters.common import assessment, base
    from infrastructure_impact.application import switching_releases as releases

    ev, _, _ = inputs(
        [
            ("2024-12-31", ["17.15.3"]),
            ("2025-02-01", ["17.15.4"]),
            ("2025-01-01", []),
            ("2025-01-01", []),
        ]
    )
    claims = copy.deepcopy(ev["claims"])
    for c, version in zip(claims[2:], ["17.15.1", "17.15.9"], strict=True):
        c["advisory_id"] = "same-advisory"
        c["publisher"]["id"] = "same-advisory"
        c["version_expressions"] = [version]
    claims += copy.deepcopy(aruba_evidence()["claims"]) + [claim()]
    entries = []
    for cid, vendor, product in [
        ("CVE-2026-7473", "Arista", "Extensible Operating System"),
        ("CVE-2026-99999", "Unmapped publisher", "Unmapped product"),
    ]:
        entries.append(
            dict(
                cveID=cid,
                vendorProject=vendor,
                product=product,
                vulnerabilityName="Authored example",
                dateAdded="2026-11-12",
                shortDescription="Authored example",
                requiredAction="Review",
                dueDate="2026-12-01",
            )
        )
    raw = json.dumps(
        dict(catalogVersion="2026.11.13", dateReleased=AT, count=2, vulnerabilities=entries)
    ).encode()
    _, ev, _, study = kev_inputs(claims, raw=raw)
    history = releases.build(
        ev, [frame()], publication=None, generated_at=AT, observation_end=AT[:10]
    )
    calibration = base("cisco", "https://example.org/heldout", "heldout", "Authored calibration")
    for version in ["17.15.2", "17.15.10"]:
        a = assessment(
            "CVE-2099-12345", "Cisco IOS XE Software", "affected", "affected / " + version
        )
        a["product_id"] = version
        a["product_context"] = [["service_pack", version]]
        calibration["assessments"].append(a)
    calibration.update(
        sha256="a" * 64, source_observed_at=AT, revision_id=1, cves=["CVE-2099-12345"]
    )
    migration = base(
        "cisco", claims[0]["source"]["source_url"], claims[0]["advisory_id"], "Authored migration"
    )
    migration.update(
        sha256=claims[0]["source"]["source_sha256"],
        source_observed_at=claims[0]["source"]["retrieved_at"],
        revision_id=1,
        cves=[claims[0]["cve_id"]],
    )
    migration["first_fixed"] = [
        dict(
            method="stated_table",
            evidence_state="publisher_stated",
            family="cisco-iosxe",
            product=None,
            product_ids=None,
            scope="cve_specific",
            cve_ids=[claims[0]["cve_id"]],
            train=None,
            train_expression="17.8 and earlier",
            fixed_versions=[],
            disposition="migrate",
            source_locator="authored migration row",
        )
    ]
    full = api().build_report(
        [],
        [],
        study,
        release_history=history,
        source_frame={"calibration_records": [calibration, migration]},
    )
    assert {c["vendor"] for c in full["claims"].values()} == set(delivery.VENDORS)
    assert full["requirements"]["source_groups"]
    assert full["requirements"]["inference_groups"]
    assert history["releases"]
    assert any(e["mapping"]["vendor"] is None for e in full["kev_reconciliation"]["entries"])
    return full


def test_rich_vendor_closure_parity():
    full = rich_source()
    for vendor in delivery.VENDORS:
        envelope = delivery.project_vendor(full, vendor)
        for scope in ("os_family", "model_qualified"):
            for window in ("all", "pre", "post", "undated", "2024", "2025", "2026"):
                for cves in (None, [], ["CVE-2026-7473"]):
                    study = api().selection_context(
                        full, dict(vendor=vendor, scope_level=scope, window=window, cve_ids=cves)
                    )
                    actual = delivery.select_vendor(envelope, study)
                    expected = api().select_report(full, study)
                    assert actual == expected
                    assert api().analysis_csv_export(actual) == api().analysis_csv_export(expected)
                    assert api().csv_export(actual["upgrades"]) == api().csv_export(
                        expected["upgrades"]
                    )
