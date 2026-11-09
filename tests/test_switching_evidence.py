"""Source-led scope regressions; synthetic products are not publisher evidence."""

import copy
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from infrastructure_impact.adapters import standards
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.plugins.contracts import VendorPlugin
from infrastructure_impact.plugins.registry import PluginRegistry, default_registry
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.storage.repository import connect, ingest, latest

URL = "https://support.hpe.com/security/test.json"
AT = "2026-11-04T12:00:00Z"


def tree(product="CX 6410", status="known_affected"):
    return {
        "document": {
            "title": "Synthetic switching test",
            "tracking": {
                "id": "TEST-1",
                "version": "1.0",
                "status": "final",
                "initial_release_date": "2024-01-01T00:00:00Z",
                "current_release_date": "2024-02-01T00:00:00Z",
            },
        },
        "product_tree": {
            "branches": [
                {
                    "category": "product_family",
                    "name": "AOS-CX",
                    "branches": [
                        {
                            "category": "product_name",
                            "name": product,
                            "branches": [
                                {
                                    "category": "product_version",
                                    "name": "10.13",
                                    "branches": [
                                        {
                                            "category": "service_pack",
                                            "name": "10.13.1000",
                                            "product": {"product_id": "p", "name": "10.13.1000"},
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
            "full_product_names": [{"product_id": "p", "name": "10.13.1000"}],
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2024-12345",
                "product_status": {status: ["p"]},
                "notes": [{"category": "description", "text": "Only when feature X is enabled."}],
                "remediations": [
                    {
                        "category": "vendor_fix",
                        "product_ids": ["p"],
                        "details": "Upgrade to 10.13.1010 or later.",
                    }
                ],
            }
        ],
    }


def extract(d, url=URL, vendor="aruba"):
    from infrastructure_impact.adapters.switching import extract

    raw = json.dumps(d).encode()
    return extract(raw, url, vendor, standards.csaf(raw, url, vendor))


def report(d, url=URL, vendor="aruba"):
    db = connect(":memory:")
    ingest(db, json.dumps(d).encode(), url, standards.csaf, vendor)
    return evidence.project(evidence.inputs(db, latest(db)), publication=None, generated_at=AT)


def test_numeric_leaves_and_full_names_keep_explicit_model_and_literals():
    result = report(tree())
    evidence.validate_evidence(result, publication=None, generated_at=AT)
    c = result["claims"][0]
    assert c["product"] == "10.13.1000"
    assert c["version_expressions"] == ["10.13", "10.13.1000"]
    assert c["scope_level"] == "model_qualified"
    assert c["platform_bindings"][0]["model"] == "6410"
    assert (
        "/product_tree/branches/0/branches/0"
        in c["platform_bindings"][0]["source"]["source_locator"]
    )
    assert c["conditions"] == ["Only when feature X is enabled."]
    assert c["remediations"][0]["details"] == "Upgrade to 10.13.1010 or later."
    assert c["remediations"][0]["availability_date"] is None


def test_core_csaf_duplicate_full_name_does_not_erase_proven_ancestry():
    d = tree()
    c = standards.csaf(json.dumps(d).encode(), URL, "aruba")["assessments"][0]
    assert ("product_family", "AOS-CX") in c["product_context"]
    assert c["product_family"] == "CX 6410"


@pytest.mark.parametrize("product", ["AOS-CX", "CX 6400", "7500", "ESS9300", "IE9300"])
def test_family_and_nearby_names_do_not_qualify_models(product):
    c = report(tree(product))["claims"][0]
    assert c["scope_level"] == "os_family"
    assert not c["platform_bindings"]
    assert "model_binding_unresolved" in c["issues"]


def test_ambiguous_duplicate_id_never_selects_broader_branch():
    d = tree()
    branch = copy.deepcopy(d["product_tree"]["branches"][0])
    branch["branches"][0]["name"] = "CX 6300M"
    d["product_tree"]["branches"].append(branch)
    result = report(d)
    c = result["claims"][0]
    assert not c["platform_bindings"]
    assert "ambiguous_product_id" in c["issues"]
    assert c["family"] is None


def test_relationship_preserves_endpoints_and_ambiguous_endpoint_is_unresolved():
    d = tree("AOS-CX")
    d["product_tree"]["full_product_names"].append({"product_id": "hardware", "name": "CX 6410"})
    d["product_tree"]["relationships"] = [
        {
            "category": "installed_on",
            "product_reference": "p",
            "relates_to_product_reference": "hardware",
            "full_product_name": {"product_id": "combined", "name": "Software on chassis"},
        }
    ]
    d["vulnerabilities"][0]["product_status"] = {"known_affected": ["combined"]}
    d["vulnerabilities"][0]["remediations"] = []
    c = report(d)["claims"][0]
    assert c["platform_bindings"][0]["model"] == "6410"
    assert "/relationships/0" in c["source"]["source_locator"]
    d["product_tree"]["full_product_names"].append({"product_id": "hardware", "name": "CX 6300M"})
    c = report(d)["claims"][0]
    assert not c["platform_bindings"]
    assert "relationship_scope_unresolved" in c["issues"]


@pytest.mark.parametrize(
    "status,expected", [("fixed", "fixed"), ("known_not_affected", "unaffected")]
)
def test_separate_fixed_and_exclusion_rows_are_never_affected(status, expected):
    assert report(tree(status=status))["claims"][0]["status"] == expected


def test_conflicting_dispositions_remain_conflicting():
    d = tree()
    d["vulnerabilities"][0]["product_status"]["known_not_affected"] = ["p"]
    assert report(d)["claims"][0]["status"] == "conflicting"


def test_representations_keep_exact_latest_revision_and_literal_draft_status():
    db = connect(":memory:")
    draft, final = tree("EOS"), tree("EOS")
    draft["document"]["tracking"]["status"] = "draft"
    draft["document"]["tracking"]["id"] = final["document"]["tracking"]["id"] = "SA-123"
    urls = [
        "https://www.arista.com/security/draft.json",
        "https://www.arista.com/security/final.json",
    ]
    for d, url in zip((draft, final), urls):
        ingest(db, json.dumps(d).encode(), url, standards.csaf, "arista")
    assert len(latest(db)) == 1
    r = evidence.project(evidence.inputs(db, latest(db)), publication=None, generated_at=AT)
    assert {c["publisher"]["status"] for c in r["claims"]} == {"draft", "final"}
    assert {c["advisory_id"] for c in r["claims"]} == {"SA-123"}
    assert {c["revision"] for c in r["claims"]} == {"1", "2"}
    draft["document"]["tracking"]["version"] = "2.0"
    ingest(db, json.dumps(draft).encode(), urls[0], standards.csaf, "arista")
    r2 = evidence.project(evidence.inputs(db, latest(db)), publication=None, generated_at=AT)
    assert {c["revision"] for c in r2["claims"]} == {"2", "3"}
    assert (
        next(c for c in r2["claims"] if c["revision"] == "3")["source"]["source_sha256"]
        == sha256(json.dumps(draft).encode()).hexdigest()
    )
    assert not (
        {c["claim_id"] for c in r["claims"] if c["revision"] == "1"}
        & {c["claim_id"] for c in r2["claims"]}
    )


def test_external_plugin_without_hook_is_functional_and_hook_cannot_mutate_core():
    registry = PluginRegistry()
    plugin = VendorPlugin("example", "Example", ("example.invalid",), structured)
    registry.register(plugin)
    d = tree()
    raw = json.dumps(d).encode()
    core = registry.normalize(raw, "https://example.invalid/test", "example")
    assert registry.research_evidence(raw, "https://example.invalid/test", "example", core) is None

    def mutate(raw, url, vendor, document):
        document["assessments"].clear()
        return {"schema_version": 1, "claims": [], "bundles": [], "issues": []}

    other = PluginRegistry()
    other.register(replace(plugin, research_evidence=mutate))
    other.research_evidence(raw, "https://example.invalid/test", "example", core)
    assert core["assessments"]


def test_projection_recursively_allowlists_and_deduplicates():
    fixture = json.loads(open("tests/fixtures/switching-cases.json").read())["evidence"]
    incoming = copy.deepcopy(fixture)
    incoming["raw"] = "/private/secret"
    incoming["claims"][0]["source"]["path"] = "/private/secret"
    incoming["claims"][0]["raw"] = "/private/secret"
    incoming["claims"].append(copy.deepcopy(incoming["claims"][0]))
    result = evidence.project(incoming, publication=None, generated_at=AT)
    assert "/private/secret" not in json.dumps(result)
    assert len(result["claims"]) == 1
    evidence.validate_evidence(result)


@pytest.mark.parametrize(
    "filename",
    [
        "resources/switching-source-bindings.json",
        "resources/switching-study.json",
        "adapters/switching.py",
        "schemas/switching-evidence-v1.json",
    ],
)
def test_hook_fingerprint_tracks_resource_and_extractor(monkeypatch, filename):
    from pathlib import Path

    from infrastructure_impact.settings import PACKAGE

    registry = default_registry()
    original = Path.read_bytes
    before = {p.id: registry.fingerprint(p.id) for p in registry.all()}
    target = PACKAGE / filename
    monkeypatch.setattr(
        Path, "read_bytes", lambda p: original(p) + b" " if p == target else original(p)
    )
    after = {p.id: registry.fingerprint(p.id) for p in registry.all()}
    # Shared CVSS dispatch reads Aruba text, whose research hook reuses switching
    # claim templates. Code is therefore transitive; frozen study resources are
    # still dependencies only of plugins with research hooks.
    expected = set(before) if filename == "adapters/switching.py" else {"aruba", "arista", "cisco"}
    assert {k for k in before if before[k] != after[k]} == expected


def test_public_boundary_removes_internal_switching_inputs():
    from infrastructure_impact.application.publication import public_projection
    from infrastructure_impact.application.query import state

    db = connect(":memory:")
    data = state(db)
    assert "switching_input" in data["research"]
    data["research"]["switching_input"]["operator_path"] = "/private/forbidden"
    public = public_projection(data)
    assert "switching_input" not in public["research"]
    assert "/private/forbidden" not in json.dumps(public)


def test_stale_reviewed_html_hash_cannot_reuse_scope_or_bundle_membership():
    from infrastructure_impact.adapters.switching import bindings_resource, extract

    for entry in bindings_resource()["entries"]:
        result = extract(
            b"<html>changed bytes</html>",
            entry["source_url"],
            entry["vendor"],
            {"advisory_id": "synthetic"},
        )
        assert result["claims"] == []
        assert result["bundles"] == []
        assert result["issues"] == ["source_binding_stale"]


def test_explicit_bundle_membership_deduplicates_without_same_day_inference(monkeypatch):
    from infrastructure_impact.adapters import switching
    from infrastructure_impact.storage.repository import evidence as retain

    db = connect(":memory:")
    d = tree("IOS XE")
    d["product_tree"]["branches"][0]["name"] = "IOS XE"
    advisory_url = "https://sec.cloudapps.cisco.com/security/test.json"
    ingest(db, json.dumps(d).encode(), advisory_url, standards.csaf, "cisco")
    other = copy.deepcopy(d)
    other["document"]["tracking"]["id"] = "UNRELATED-SAME-DAY"
    ingest(db, json.dumps(other).encode(), advisory_url + "?other", standards.csaf, "cisco")
    raw = b"<html>synthetic explicit membership</html>"
    bundle_url = "https://sec.cloudapps.cisco.com/security/bundle"
    entry = dict(
        vendor="cisco",
        source_url=bundle_url,
        source_sha256=sha256(raw).hexdigest(),
        bundle=dict(
            publisher_id="BUNDLE-1",
            title="Synthetic",
            member_advisory_ids=["TEST-1", "TEST-1"],
            published_at="2024-01-01T00:00:00Z",
            source_locator="Details/table/row[1]",
        ),
    )
    monkeypatch.setattr(
        switching, "bindings_resource", lambda: {"schema_version": 1, "entries": [entry]}
    )
    retain(db, raw, bundle_url)
    result = evidence.project(evidence.inputs(db, latest(db)), publication=None, generated_at=AT)
    member = next(c for c in result["claims"] if c["advisory_id"] == "TEST-1")
    unrelated = next(c for c in result["claims"] if c["advisory_id"] == "UNRELATED-SAME-DAY")
    assert member["bundle"]["member_advisory_ids"] == ["TEST-1"]
    assert member["bundle"]["source"]["source_sha256"] == sha256(raw).hexdigest()
    assert unrelated["bundle"] is None


def test_projection_rejects_unbounded_evidence_text():
    fixture = json.loads(open("tests/fixtures/switching-cases.json").read())["evidence"]
    fixture["claims"][0]["conditions"] = ["x" * 100000]
    with pytest.raises(ValueError, match="bounded"):
        evidence.project(fixture, publication=None, generated_at=AT)


def test_relationship_repeated_name_conflict_is_not_repaired_in_core():
    d = tree()
    d["product_tree"]["full_product_names"].append({"product_id": "p", "name": "CX 6300M"})
    core = standards.csaf(json.dumps(d).encode(), URL, "aruba")
    assert core["assessments"][0]["product_context"] == []
    assert any("ambiguous_product_id" in w for w in core["warnings"])


def test_retained_unparsed_binding_requires_latest_observed_bytes_and_no_invented_revision(
    monkeypatch,
):
    from infrastructure_impact.adapters import switching
    from infrastructure_impact.storage.observations import observe
    from infrastructure_impact.storage.repository import evidence as retain

    db = connect(":memory:")
    d = tree("IOS XE")
    d["product_tree"]["branches"][0]["name"] = "IOS XE"
    ingest(
        db,
        json.dumps(d).encode(),
        "https://sec.cloudapps.cisco.com/security/test.json",
        standards.csaf,
        "cisco",
    )
    raw = b"<html>registered scoped statement</html>"
    url = "https://sec.cloudapps.cisco.com/security/retained-html"
    entry = dict(
        vendor="cisco",
        source_url=url,
        source_sha256=sha256(raw).hexdigest(),
        publisher={"id": "TEST-1", "sequence": "1", "status": "Final"},
        initial_published_at="2024-01-01T00:00:00Z",
        updated_at=None,
        claims=[
            dict(
                product="IOS XE",
                product_id=None,
                cve_id="CVE-2024-12345",
                family="cisco-iosxe",
                status="affected",
                scope="cve_specific",
                source_locator="div#vulnerableproducts",
                conditions=["Feature enabled"],
            )
        ],
    )
    monkeypatch.setattr(
        switching, "bindings_resource", lambda: {"schema_version": 1, "entries": [entry]}
    )

    def current():
        return evidence.project(evidence.inputs(db, latest(db)), publication=None, generated_at=AT)

    assert len(current()["claims"]) == 1  # A static template is not an observation.
    a = retain(db, raw, url)
    observe(db, "cisco", url, a["id"], 200)
    claim = next(c for c in current()["claims"] if c["source"]["source_url"] == url)
    assert claim["revision"] is None
    assert {"revision_missing", "source_normalization_unavailable"} <= set(claim["issues"])
    b = retain(db, b"<html>new unsupported body</html>", url)
    observe(db, "cisco", url, b["id"], 200)
    assert len(current()["claims"]) == 1
    assert "source_binding_stale" in current()["issues"]
    # Failed attempts are not successful source observations and cannot revive A.
    db.execute(
        "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details) VALUES(?,?,?,?,?)",
        ("cisco", url, AT, "error", "access failed"),
    )
    assert len(current()["claims"]) == 1
    # Replaying an old parser result is not a fresh retrieval of that body.
    normalized = standards.csaf(json.dumps(d).encode(), url, "cisco")
    ingest(db, raw, url, lambda raw, url, vendor: normalized, "cisco")
    assert len(current()["claims"]) == 1
    observe(db, "cisco", url, a["id"], 200)
    assert len(current()["claims"]) == 2
    assert (
        next(c for c in current()["claims"] if c["source"]["source_url"] == url)["source"][
            "source_sha256"
        ]
        == a["sha256"]
    )


def test_csaf_draft_without_products_keeps_identity_and_missing_scope():
    d = tree("EOS")
    d.pop("product_tree")
    d["document"]["tracking"]["status"] = "draft"
    d["vulnerabilities"] = [{"cve": "CVE-2024-12345"}]
    result = report(d, "https://www.arista.com/security/advance.json", "arista")
    c = result["claims"][0]
    assert c["publisher"]["status"] == "draft"
    assert c["product_id"] is None
    assert c["status"] == "unknown"
    assert "product_scope_unresolved" in c["issues"]


def test_unknown_status_does_not_get_dropped_beside_affected():
    d = tree()
    d["vulnerabilities"][0]["product_status"]["unsupported_disposition"] = ["p"]
    c = report(d)["claims"][0]
    assert c["status"] == "unknown"
    assert "product_status_unsupported" in c["issues"]


def same_row_report():
    fixture = json.loads(open("tests/fixtures/switching-cases.json").read())["evidence"]
    claim = fixture["claims"][0]
    claim["product_id"] = None
    claim["scores"] = []
    claim["source"]["source_locator"] = "div#vulnerableproducts tr[33]"
    rem = claim["remediations"][0]
    rem["product_ids"] = []
    rem["source"] = {
        **claim["source"],
        "source_locator": claim["source"]["source_locator"] + "/td[2]",
    }
    rem["scope_binding"] = dict(
        basis="same_source_row", cve_id=claim["cve_id"], source=copy.deepcopy(claim["source"])
    )
    return fixture


def test_same_row_remediation_binds_without_invented_product_id_or_date():
    result = evidence.project(same_row_report(), publication=None, generated_at=AT)
    claim = result["claims"][0]
    rem = claim["remediations"][0]
    assert rem["scope_binding"]["basis"] == "same_source_row"
    assert rem["product_ids"] == []
    assert claim["product_id"] is None
    assert rem["availability_date"] is None
    assert "availability_date_missing" in claim["issues"]
    assert "remediation_product_scope_unresolved" not in claim["issues"]
    evidence.validate_evidence(result)


@pytest.mark.parametrize(
    "mutation",
    ["row", "hash", "url", "cve", "remediation_row", "remediation_hash", "claim_cve_missing"],
)
def test_same_row_remediation_rejects_unrelated_source_scope(mutation):
    fixture = same_row_report()
    c = fixture["claims"][0]
    r = c["remediations"][0]
    if mutation == "row":
        r["scope_binding"]["source"]["source_locator"] = "div#vulnerableproducts tr[34]"
    elif mutation == "hash":
        r["scope_binding"]["source"]["source_sha256"] = "c" * 64
    elif mutation == "url":
        r["scope_binding"]["source"]["source_url"] += "-other"
    elif mutation == "cve":
        r["scope_binding"]["cve_id"] = "CVE-2024-99999"
    elif mutation == "remediation_row":
        r["source"]["source_locator"] = "div#vulnerableproducts tr[330]/td[2]"
    elif mutation == "remediation_hash":
        r["source"]["source_sha256"] = "c" * 64
    else:
        c["cve_id"] = None
    with pytest.raises(ValueError, match="row remediation"):
        evidence.project(fixture, publication=None, generated_at=AT)


def test_changed_reviewed_source_rejects_malformed_payload_before_parsing():
    from infrastructure_impact.adapters.switching import bindings_resource, extract

    entry = bindings_resource()["entries"][0]
    result = extract(
        b"{invalid payload",
        entry["source_url"],
        entry["vendor"],
        {"advisory_id": entry["publisher"]["id"]},
    )
    assert result["claims"] == []
    assert result["issues"] == ["source_binding_stale"]


@pytest.mark.parametrize("unsupported", [b"<html>unsupported replacement</html>", b"{invalid"])
def test_generic_csaf_latest_observation_suppresses_old_scope_until_observed_return(unsupported):
    from infrastructure_impact.storage.observations import observe
    from infrastructure_impact.storage.repository import evidence as retain

    db = connect(":memory:")
    raw = json.dumps(tree()).encode()
    alternate = URL + "?alternate"
    ingest(db, raw, URL, standards.csaf, "aruba")
    ingest(db, raw, alternate, standards.csaf, "aruba")
    a = retain(db, raw, URL)
    observe(db, "aruba", URL, a["id"], 200)

    def current():
        return evidence.project(evidence.inputs(db, latest(db)), publication=None, generated_at=AT)

    assert len(current()["claims"]) == 2
    b = retain(db, unsupported, URL)
    observe(db, "aruba", URL, b["id"], 200)

    def assert_suppressed():
        result = current()
        assert [c["source"]["source_url"] for c in result["claims"]] == [alternate]
        assert "source_normalization_unavailable" in result["issues"]
        coverage = next(row for row in result["coverage"] if row["source_url"] == URL)
        assert coverage["state"] == "partial"
        assert "source_normalization_unavailable" in coverage["issues"]

    assert_suppressed()

    # Force an actual parser revision of A without recording a new retrieval.
    def replay(raw, url, vendor):
        normalized = standards.csaf(raw, url, vendor)
        normalized["warnings"].append("Synthetic parser replay")
        return normalized

    ingest(db, raw, URL, replay, "aruba")
    replay_revision = latest(db)[0]["revision_id"]
    assert_suppressed()
    observe(db, "aruba", URL, a["id"], 200)
    result = current()
    assert len(result["claims"]) == 2
    returned = next(c for c in result["claims"] if c["source"]["source_url"] == URL)
    assert returned["source"]["source_sha256"] == a["sha256"]
    assert returned["revision"] == str(replay_revision)
    assert "source_normalization_unavailable" not in result["issues"]


@pytest.mark.parametrize("group_ids", [["missing"], ["known", "missing"]])
def test_unresolved_threat_groups_do_not_broaden_conditions(group_ids):
    d = tree()
    d["product_tree"]["product_groups"] = [{"group_id": "known", "product_ids": ["p"]}]
    d["vulnerabilities"][0]["threats"] = [
        {"category": "impact", "group_ids": group_ids, "details": "Scoped condition"}
    ]
    c = report(d)["claims"][0]
    assert "Scoped condition" not in c["conditions"]
    assert "threat_product_scope_unresolved" in c["issues"]


@pytest.mark.parametrize(
    "scope,applies",
    [
        ({}, True),
        ({"group_ids": ["known"]}, True),
        ({"group_ids": ["other"]}, False),
        ({"group_ids": ["empty"]}, False),
    ],
)
def test_resolved_threat_groups_and_unscoped_threats_keep_their_scope(scope, applies):
    d = tree()
    d["product_tree"]["product_groups"] = [
        {"group_id": "known", "product_ids": ["p"]},
        {"group_id": "other", "product_ids": ["different-product"]},
        {"group_id": "empty", "product_ids": []},
    ]
    d["vulnerabilities"][0]["threats"] = [
        {"category": "impact", "details": "Scoped condition", **scope}
    ]
    c = report(d)["claims"][0]
    assert ("Scoped condition" in c["conditions"]) is applies
    assert "threat_product_scope_unresolved" not in c["issues"]


@pytest.mark.parametrize("index", range(4))
def test_synthetic_arista_bridge_preserves_reviewed_adapter_boundary(index, monkeypatch):
    from pathlib import Path

    from infrastructure_impact.adapters.switching import extract
    from infrastructure_impact.plugins import arista

    case = json.loads(
        (Path(__file__).parent / "fixtures/switching-arista-bridge.json").read_text()
    )[index]
    assert case["kind"] == "synthetic"
    raw = case["raw"].encode()
    slug = case["slug"]
    url = "https://www.arista.com/en/support/advisories-notices/security-advisory/" + slug
    document = copy.deepcopy(case["document"])
    calls = []

    def reviewed_parser(actual_raw, actual_url, vendor):
        # This explicitly stubs the already-reviewed core normalizer contract.
        # It does not assert that synthetic bytes are a real supported advisory.
        assert (actual_raw, actual_url, vendor) == (raw, url, "arista")
        calls.append(vendor)
        return copy.deepcopy(case["document"])

    monkeypatch.setattr(arista, "parse", reviewed_parser)
    document["assessments"] = []  # Caller assessments cannot replace the core re-read.
    result = extract(raw, url, "arista", document)
    assert calls == ["arista"] and result["claims"]
    publisher = result["claims"][0]["publisher"]
    number = {"11996-security-advisory-56": "0056"}.get(slug, slug.rsplit("-", 1)[-1])
    assert publisher["id"] == "Security Advisory " + number
    assert publisher["sequence"] == {"0100": "1.5", "0101": "1.1"}.get(number, "1.0")
    assert publisher["status"] is None
    assert "Revision" in publisher["source"]["source_locator"]
    assert all(c["source"]["source_sha256"] == sha256(raw).hexdigest() for c in result["claims"])
    assert all(c["scope_level"] == "os_family" for c in result["claims"])
    assert all(c["bundle"] is None for c in result["claims"])
    if number == "0101":
        eos = next(c for c in result["claims"] if c["family"] == "arista-eos")
        assert eos["conditions"] and "720XP/722XPM Series" in eos["named_platforms"]
        assert eos["conditional_affected"] is True
        assert all(b["basis"] == "unresolved" for b in eos["platform_bindings"])
    if number == "0100":
        affected = [c for c in result["claims"] if c["status"] == "affected" and c["family"]]
        assert len(affected) == 2
        assert all(not c["named_platforms"] and not c["remediations"] for c in affected)
        assert len([c for c in result["claims"] if c["status"] == "fixed"]) == 2
    if number == "0056":
        assert all(c["initial_published_at"].startswith("2020") for c in result["claims"])
    document["source_format"] = "generic HTML"
    assert extract(raw, url, "arista", document)["claims"] == []
    assert calls == ["arista"]


def test_synthetic_html_cannot_bypass_the_real_reviewed_core_parser():
    from pathlib import Path

    from infrastructure_impact.adapters.switching import extract

    case = json.loads(
        (Path(__file__).parent / "fixtures/switching-arista-bridge.json").read_text()
    )[1]
    with pytest.raises(ValueError):
        extract(
            case["raw"].encode(),
            "https://www.arista.com/en/support/advisories-notices/security-advisory/"
            + case["slug"],
            "arista",
            case["document"],
        )


@pytest.mark.parametrize(
    "details,category,date,expected",
    [
        ("Vendor has released software updates.", "vendor_fix", None, "vendor_reports_fixed"),
        ("Update scheduled for a future release.", "vendor_fix", None, "planned"),
        ("Vendor update", "vendor_fix", "2027-01-01", "planned"),
        ("Partial mitigation only", "vendor_fix", None, "partial_mitigation"),
        ("Restrict SSH access", "workaround", None, "not_a_fix"),
        (None, "vendor_fix", None, "unknown"),
    ],
)
def test_switching_remediation_availability_is_typed_without_losing_literal(
    details, category, date, expected
):
    d = tree()
    pid = d["vulnerabilities"][0]["product_status"]["known_affected"][0]
    d["vulnerabilities"][0]["remediations"] = [
        dict(
            category=category,
            details=details,
            product_ids=[pid],
            **({"date": date} if date else {}),
        )
    ]
    from infrastructure_impact.adapters.switching import extract as switching_extract

    c = switching_extract(
        json.dumps(d).encode(), URL, "aruba", {"advisory_id": d["document"]["tracking"]["id"]}
    )["claims"][0]
    assert c["remediations"][0]["availability"] == expected
    assert c["remediations"][0]["published_availability"] == details
    assert c["remediations"][0]["availability_date"] == date


@pytest.mark.parametrize(
    "details,expected",
    [
        ("A fix is not currently available.", "unavailable"),
        ("No fixed releases are available.", "unavailable"),
        ("An update has not yet been released.", "unavailable"),
        ("A fixed release is unavailable.", "unavailable"),
        ("A fix is not generally available.", "unavailable"),
        ("A fix is expected to be available next month.", "planned"),
        ("A fixed release is planned.", "planned"),
        ("A fix will be available in a future release.", "planned"),
        ("A fix may be available.", "unknown"),
        ("A fix is not expected to be available.", "unknown"),
        ("Is a fixed release planned?", "unknown"),
        ("A fix may be available in a future release.", "unknown"),
        ("Is a fixed release available?", "unknown"),
        ("Information about fixed releases is available.", "unknown"),
        ("The released fix may not address this issue.", "unknown"),
        ("A fix isn't available for this product.", "unknown"),
        ("Fixed releases.", "unknown"),
        ("Vendor has released software updates.", "vendor_reports_fixed"),
        ("A fixed release is available.", "vendor_reports_fixed"),
    ],
)
def test_remediation_prose_cannot_create_false_events(details, expected):
    from infrastructure_impact.application import kev, switching_comparison

    document = tree()
    document["vulnerabilities"][0]["remediations"][0]["details"] = details
    projected = report(document)
    remediation = projected["claims"][0]["remediations"][0]
    assert remediation["published_availability"] == details
    assert remediation["availability"] == expected
    comparison = switching_comparison.build_report(
        projected,
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-04",
    )
    row = next(r for r in comparison["rows"] if r["vendor"] == "aruba")
    assert row["counts"]["affected_cves"] == 1
    assert row["counts"]["remediation_events"] == int(expected == "vendor_reports_fixed")


def reviewed_section_report(monkeypatch, *, fixed_only=False, mismatch=None):
    """Synthetic core-parser outputs exercise the bridge, never primary evidence."""
    from pathlib import Path

    from infrastructure_impact.adapters.switching import extract
    from infrastructure_impact.plugins import arista

    case = json.loads(
        (Path(__file__).parent / "fixtures/switching-arista-bridge.json").read_text()
    )[1]
    raw = (
        case["raw"]
        .replace("CVE-2025-12345", "CVE-2024-6387")
        .replace("CVE-2025-12346", "CVE-2024-6409")
        .encode()
    )
    document = copy.deepcopy(case["document"])
    for a in document["assessments"]:
        a["cve_id"] = {"CVE-2025-12345": "CVE-2024-6387", "CVE-2025-12346": "CVE-2024-6409"}[
            a["cve_id"]
        ]
        a["product_id"] = None
        if a["status"] == "affected":
            a["product"] = "EOS release (source platform scope applies)"
            a["evidence_locator"] = (
                "Affected Software / EOS release (source platform scope applies)"
            )
        else:
            a["evidence_locator"] = "Resolution / " + a["cve_id"] + " / Arista EOS-based products"
            a["remediations"][0]["source_locator"] = a["evidence_locator"]
    if fixed_only:
        document["assessments"] = [a for a in document["assessments"] if a["status"] == "fixed"]
    if mismatch:
        for a in document["assessments"]:
            if a["status"] == "fixed":
                a[mismatch[0]] = mismatch[1]
    monkeypatch.setattr(arista, "parse", lambda *_: copy.deepcopy(document))
    url = "https://www.arista.com/en/support/advisories-notices/security-advisory/" + case["slug"]
    result = extract(raw, url, "arista", document)

    def stamp(v):
        if isinstance(v, dict):
            if "retrieved_at" in v:
                v["retrieved_at"] = AT
            for x in v.values():
                stamp(x)
        elif isinstance(v, list):
            for x in v:
                stamp(x)

    stamp(result)
    for c in result["claims"]:
        c["revision"] = "synthetic-revision"
    result.pop("bundles")
    result["coverage"] = []
    return evidence.project(result, publication=None, generated_at=AT)


def test_reviewed_sections_link_only_explicit_eos_cve_fixes(monkeypatch):
    from infrastructure_impact.application.switching_comparison import build_report

    r = reviewed_section_report(monkeypatch)
    affected = [c for c in r["claims"] if c["status"] == "affected"]
    assert len(affected) == 2
    assert all(len(c["remediations"]) == 1 for c in affected)
    assert all(
        c["remediations"][0]["scope_binding"]["basis"] == "reviewed_source_sections"
        for c in affected
    )
    assert all(not c["named_platforms"] and c["product_id"] is None for c in affected)
    assert all(c["remediations"][0]["availability_date"] is None for c in affected)
    from infrastructure_impact.application import kev

    full = build_report(
        r,
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-04",
    )
    row = next(r for r in full["rows"] if r["vendor"] == "arista")
    assert row["counts"]["remediation_events"] == 1
    assert row["events"][0]["cve_ids"] == ["CVE-2024-6387", "CVE-2024-6409"]


def test_fixed_only_reviewed_sections_never_create_affectedness(monkeypatch):
    r = reviewed_section_report(monkeypatch, fixed_only=True)
    assert all(not c["remediations"][0].get("scope_binding") for c in r["claims"])


@pytest.mark.parametrize(
    "field,value", [("product", "Other EOS product"), ("evidence_locator", "Unreviewed section")]
)
def test_reviewed_sections_do_not_join_arbitrary_claims(monkeypatch, field, value):
    r = reviewed_section_report(monkeypatch, mismatch=(field, value))
    assert all(not c["remediations"] for c in r["claims"] if c["status"] == "affected")


@pytest.mark.parametrize(
    "mutation",
    [
        "cve",
        "product",
        "url",
        "hash",
        "revision",
        "fixed_source",
        "missing_fixed",
        "fixed_remediation",
    ],
)
def test_reviewed_section_binding_rejects_mismatched_evidence_in_both_runtimes(
    monkeypatch, mutation
):
    import subprocess

    from infrastructure_impact.application import kev, switching_comparison
    from infrastructure_impact.settings import PACKAGE

    r = reviewed_section_report(monkeypatch)
    assert any(c["remediations"] for c in r["claims"] if c["status"] == "affected")
    full = switching_comparison.build_report(
        r,
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-04",
    )
    script = """
const fs=require('fs'),vm=require('vm');global.window=global;
vm.runInThisContext(fs.readFileSync(process.argv[1],'utf8'));
try { InfrastructureSwitchingContracts.full(JSON.parse(fs.readFileSync(0,'utf8'))); console.log('accepted'); }
catch(e) { console.log('rejected'); }
"""

    def browser():
        return (
            subprocess.check_output(
                ["node", "-e", script, str(PACKAGE / "web/switching-contracts.js")],
                input=json.dumps(full).encode(),
            )
            .decode()
            .strip()
        )

    assert browser() == "accepted"
    fixed = next(c for c in r["claims"] if c["status"] == "fixed")
    affected = next(
        c for c in r["claims"] if c["status"] == "affected" and c["cve_id"] == fixed["cve_id"]
    )
    if mutation == "cve":
        fixed["cve_id"] = "CVE-2024-99999"
    elif mutation == "product":
        fixed["product"] = "Other EOS product"
    elif mutation == "url":
        fixed["source"]["source_url"] = "https://www.arista.com/other"
    elif mutation == "hash":
        fixed["source"]["source_sha256"] = "f" * 64
    elif mutation == "revision":
        fixed["revision"] = "other-revision"
    elif mutation == "fixed_source":
        affected["remediations"][0]["scope_binding"]["fixed_source"]["source_locator"] = (
            "Other section"
        )
    elif mutation == "fixed_remediation":
        fixed["remediations"] = []
    else:
        r["claims"].remove(fixed)
    for c in r["claims"]:
        c["claim_id"] = evidence.definition_sha256({k: v for k, v in c.items() if k != "claim_id"})
    full["inputs"]["evidence"] = r
    with pytest.raises(ValueError):
        evidence.validate_evidence(r)
    assert browser() == "rejected"


@pytest.mark.parametrize(
    "slug,format_name",
    [
        ("12135-security-advisory-61", "Arista reviewed older product/model HTML"),
        ("12166-security-advisory-62", "Arista reviewed older product/model HTML"),
        ("19221-security-advisory-0094", "Arista reviewed applicability boundaries HTML"),
        ("24074-security-advisory-0140", "Arista reviewed sibling software sections HTML"),
        ("24515-security-advisory-0147", "Arista CVE-grouped software HTML"),
    ],
)
def test_additional_reviewed_routes_preserve_core_scope_without_invented_ids(
    monkeypatch, slug, format_name
):
    from pathlib import Path

    from infrastructure_impact.adapters.switching import extract
    from infrastructure_impact.plugins import arista

    case = json.loads(
        (Path(__file__).parent / "fixtures/switching-arista-bridge.json").read_text()
    )[0]
    number = slug.rsplit("-", 1)[-1].zfill(4)
    raw = case["raw"].replace("Security Advisory 0101", "Security Advisory " + number).encode()
    document = copy.deepcopy(case["document"])
    document.update(advisory_id=slug, source_format=format_name)
    document["assessments"][0]["scope"] = "bulletin_shared"
    monkeypatch.setattr(arista, "parse", lambda *_: copy.deepcopy(document))
    url = "https://www.arista.com/en/support/advisories-notices/security-advisory/" + slug
    result = extract(raw, url, "arista", document)
    assert len(result["claims"]) == 1
    c = result["claims"][0]
    assert c["family"] == "arista-eos" and c["scope"] == "bulletin_shared"
    assert c["product_id"] is None and c["scope_level"] == "os_family"
    assert c["named_platforms"] == ["720XP/722XPM Series"]
    assert not c["remediations"] and not c.get("conditional_affected")
    document["source_format"] = "Vendor HTML"
    assert extract(raw, url, "arista", document)["claims"] == []


@pytest.mark.parametrize(
    "change,expected",
    [
        ("none", "vendor_reports_fixed"),
        ("unrelated", "vendor_reports_fixed"),
        ("no_list", "unknown"),
        ("negated", "unknown"),
        ("question", "unknown"),
        ("may", "unknown"),
        ("future", "planned"),
        ("planned", "planned"),
        ("future_date", "planned"),
        ("workaround", "not_a_fix"),
    ],
)
def test_scoped_patch_upgrade_statement_needs_explicit_releases_and_no_future_guard(
    change, expected
):
    from infrastructure_impact.adapters.switching import _availability

    # Project-authored synthetic release values, not a vendor capture.
    text = (
        "The vulnerabilities contained in this advisory can be addressed by patching or upgrading "
        "to one of the versions listed below\n\nAOS-CX 99.01.xxxx: 99.01.2345 and above"
    )
    if change == "unrelated":
        text += "\nNone of these releases address the unrelated issue in SYNTHETIC-OTHER."
    elif change == "no_list":
        text = text.split("\n")[0]
    elif change == "negated":
        text = text.replace("can be addressed", "cannot be addressed")
    elif change == "question":
        text += "?"
    elif change == "may":
        text = text.replace("can be addressed", "may be addressed")
    elif change == "future":
        text += "\nA future release will be required."
    elif change == "planned":
        text += "\nThese releases are planned."
    assert (
        _availability(
            text,
            "workaround" if change == "workaround" else "vendor_fix",
            "2099-02-01" if change == "future_date" else "2026-01-01",
            "2026-01-01",
        )
        == expected
    )


def test_patch_upgrade_event_retains_exact_product_binding_and_no_invented_date():
    from infrastructure_impact.application import kev, switching_comparison

    d = tree()
    rem = d["vulnerabilities"][0]["remediations"][0]
    rem["details"] = (
        "The vulnerabilities contained in this advisory can be addressed by patching or upgrading "
        "to one of the versions listed below\nAOS-CX 99.01.xxxx: 99.01.2345 and above"
    )
    for product_ids, expected in [(["p"], 1), ([], 0), (["unrelated"], 0)]:
        rem["product_ids"] = product_ids
        projected = report(d)
        c = projected["claims"][0]
        assert all(r["availability_date"] is None for r in c["remediations"])
        result = switching_comparison.build_report(
            projected,
            kev.build_report({}, [], publication=None, generated_at=AT),
            definition=evidence.definition(),
            publication=None,
            generated_at=AT,
            observation_end="2026-11-04",
        )
        assert (
            next(row for row in result["rows"] if row["vendor"] == "aruba")["counts"][
                "remediation_events"
            ]
            == expected
        )


def test_current_boundary_preserves_scores_from_unexcluded_alternate_representation():
    from infrastructure_impact.application.publication import public_projection
    from infrastructure_impact.application.query import state

    alternate, core = tree(), tree()
    alternate["vulnerabilities"][0]["scores"] = [
        {
            "products": ["p"],
            "cvss_v3": {
                "version": "3.1",
                "baseScore": 9.8,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
        }
    ]
    alternate_url = "https://support.hpe.com/security/alternate.json"
    with connect(":memory:") as db:
        ingest(db, json.dumps(alternate).encode(), alternate_url, standards.csaf, "aruba")
        ingest(db, json.dumps(core).encode(), URL, standards.csaf, "aruba")
        assert [r["source_url"] for r in latest(db)] == [URL]
        data = state(db)
    assert data["current_evidence"]["counts"]["excluded"] == 0
    assert alternate_url in {s["source_url"] for s in data["research"]["score_input"]["advisories"]}
    public = public_projection(data)
    assert any(m["source"]["source_url"] == alternate_url for m in public["records"][0]["metrics"])
    assert any(
        s["source_url"] == alternate_url and s["state"] == "available"
        for s in public["switching_evidence"]["score_availability"]
    )


def resolution_document(local="10.13.1000 and above", resolution=None):
    d = tree(status="fixed")
    d["vulnerabilities"][0]["remediations"][0]["details"] = (
        "HPE Aruba Networking\n\n- Other Product\n   - 1.2.3 and above\n\n"
        "- ArubaOS-CX Switches\n   - "
        + local
        + "\n\n- Another Product\n   - 2.3.4 and above\n\n"
        + (
            resolution
            or "Software versions with resolution/fixes for the vulnerabilities\n"
            "covered above, can be downloaded from the HPE Networking Support\nPortal."
        )
        + "\n\nHPE Aruba Networking does not evaluate or patch product branches\n"
        "that have reached their End of Maintenance (EoM) milestone."
    )
    return d


def test_csaf_source_local_fixed_resolution_survives_foreign_lifecycle_negation():
    claim = extract(resolution_document())["claims"][0]
    assert claim["remediations"][0]["availability"] == "vendor_reports_fixed"
    assert claim["remediations"][0]["product_ids"] == ["p"]
    assert claim["status"] == "fixed"


@pytest.mark.parametrize(
    "change",
    [
        "plan",
        "partial",
        "negated",
        "foreign",
        "lifecycle",
        "missing_ids",
        "affected",
        "resolution_plan",
        "resolution_partial",
    ],
)
def test_csaf_local_resolution_does_not_authorize_other_scopes(change):
    d = resolution_document()
    rem = d["vulnerabilities"][0]["remediations"][0]
    if change in {"plan", "partial"}:
        rem["details"] = rem["details"].replace(
            "10.13.1000 and above",
            "10.13.1000 and above " + ("planned" if change == "plan" else "(partial fix)"),
        )
    elif change in {"resolution_plan", "resolution_partial"}:
        rem["details"] = rem["details"].replace(
            "Software versions with",
            ("Planned: " if change == "resolution_plan" else "Partial fix: ")
            + "Software versions with",
        )
    elif change == "negated":
        rem["details"] = rem["details"].replace("can be downloaded", "cannot be downloaded")
    elif change == "foreign":
        rem["details"] = rem["details"].replace("ArubaOS-CX Switches", "Foreign Switches")
    elif change == "lifecycle":
        rem["details"] = (
            "- ArubaOS-CX Switches\n   - 10.13.1000 and above\n\nEnd of Maintenance products are not patched."
        )
    elif change == "missing_ids":
        rem.pop("product_ids")
    else:
        d["vulnerabilities"][0]["product_status"] = {"known_affected": ["p"]}
    assert extract(d)["claims"][0]["remediations"][0]["availability"] != "vendor_reports_fixed"


def test_local_resolution_uses_numeric_version_path_when_leaf_name_is_family():
    d = resolution_document()
    branch = d["product_tree"]["branches"][0]["branches"][0]["branches"][0]["branches"][0]
    branch["product"]["name"] = "AOS-CX"
    d["product_tree"]["full_product_names"][0]["name"] = "AOS-CX"
    assert extract(d)["claims"][0]["remediations"][0]["availability"] == "vendor_reports_fixed"
