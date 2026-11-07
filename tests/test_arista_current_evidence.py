"""Original synthetic frames exercise the exact reviewed conflict, never live captures."""

import base64
import copy
import importlib
import json
from hashlib import sha256

import pytest

from infrastructure_impact.application.current_evidence import partition
from infrastructure_impact.plugins.registry import default_registry

URL = "https://www.arista.com/en/support/advisories-notices/security-advisory/19917-security-advisory-0103"
CSAF = "https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_103.json"
AT = "2026-11-06T12:00:00Z"
MODULE = "infrastructure_impact.plugins.arista_current_evidence"


def primary_bytes():
    return f'''<div class="item-page"><div class="page-header">
    <h2>Security Advisory 0103 <a href="{CSAF}">CSAF</a></h2></div>
    <table><tr><td>1.0</td><td>July 23, 2024</td><td>Initial release</td></tr></table>
    <p>The CVE-ID tracking this issue: CVE-2024-6858</p>
    <h2>Description</h2><p>Authored synthetic source for scope comparison.</p>
    <h3>Affected Software</h3><div>EOS Versions</div>
    <ul><li>4.40.3F and below releases in the 4.40.x train.</li></ul>
    <h3>Affected Platforms</h3><p>Publisher platform qualification.</p>
    <h3>Required Configuration for Exploitation</h3><p>OpenConfig enabled.</p>
    </div>'''.encode()


def alternate_bytes():
    return json.dumps(
        {
            "document": {
                "title": "Original synthetic alternate",
                "tracking": {
                    "id": "Arista Networks Security Advisory 103",
                    "status": "draft",
                    "initial_release_date": "2024-07-17T18:48:35Z",
                },
            },
            "product_tree": {"full_product_names": [{"product_id": "eos", "name": "Arista EOS"}]},
            "vulnerabilities": [
                {"cve": "CVE-2023-5501", "product_status": {"known_affected": ["eos"]}}
            ],
        }
    ).encode()


def frame(raw, url, number):
    return {
        "source_url": url,
        "source_sha256": sha256(raw).hexdigest(),
        "evidence_id": number,
        "source_observed_at": AT,
        "raw_b64": base64.b64encode(raw).decode(),
    }


def replace_frame(case, index, raw):
    old = case["selection_context"]["sources"][index]
    new = frame(raw, old["source_url"], old["evidence_id"])
    case["selection_context"]["sources"][index] = new
    for record in case["records"]:
        if record.get("evidence_id") == old["evidence_id"]:
            record["sha256"] = new["source_sha256"]
    for selection in case["selection_context"]["selections"]:
        for view in selection["views"]:
            if view["evidence_id"] == old["evidence_id"]:
                view.update({k: v for k, v in new.items() if k != "raw_b64"})


@pytest.fixture
def arista_case(monkeypatch):
    sources = [frame(primary_bytes(), URL, 10), frame(alternate_bytes(), CSAF, 11)]
    # Only tests substitute the reviewed production anchor with a real synthetic hash.
    monkeypatch.setattr(
        importlib.import_module(MODULE), "REVIEWED_SHA256", sources[1]["source_sha256"]
    )
    registry = default_registry()
    records = [
        {
            "vendor": "arista",
            "advisory_id": "19917-security-advisory-0103",
            "revision_id": 20,
            "source_url": URL,
            "sha256": sources[0]["source_sha256"],
            "cves": ["CVE-2024-6858"],
            "evidence_id": 10,
            "source_observed_at": AT,
        },
        {
            "vendor": "arista",
            "advisory_id": "Arista Networks Security Advisory 103",
            "revision_id": 21,
            "source_url": CSAF,
            "sha256": sources[1]["source_sha256"],
            "cves": ["CVE-2023-5501"],
            "evidence_id": 11,
            "source_observed_at": AT,
        },
    ]
    return {
        "records": records,
        "selection_context": {
            "sources": sources,
            "selections": [
                {
                    "vendor": "arista",
                    "requested_url": URL,
                    "selected_at": AT,
                    "reason": "Synthetic reviewed HTML primary",
                    "views": [
                        {k: v for k, v in sources[0].items() if k != "raw_b64"} | {"selected": True}
                    ],
                }
            ],
        },
        "registry": registry,
        "publication": None,
        "generated_at": AT,
    }


def test_only_exact_legacy_scope_is_excluded(arista_case):
    before = copy.deepcopy((arista_case["records"], arista_case["selection_context"]))
    result = partition(**arista_case)
    assert result["retained_advisories"][0]["record"]["cves"] == ["CVE-2023-5501"]
    assert result["records"][0]["cves"] == ["CVE-2024-6858"]
    assert result["current_evidence"]["issues"] == []
    proofs = result["current_evidence"]["decisions"][0]["proofs"]
    assert {(p["source_url"], p["evidence_id"]) for p in proofs} == {(URL, 10), (CSAF, 11)}
    assert "raw_b64" not in json.dumps(result)
    assert (arista_case["records"], arista_case["selection_context"]) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("vendor", "cisco"),
        ("advisory_id", "Arista Networks Security Advisory 104"),
        ("source_url", CSAF.replace("_103.json", "_104.json")),
        ("cves", ["CVE-2023-5501", "CVE-2024-6858"]),
        ("sha256", "f" * 64),
    ],
)
def test_each_nonmatching_target_stays_current(arista_case, field, value):
    arista_case["records"][1][field] = value
    result = partition(**arista_case)
    assert result["retained_advisories"] == []
    assert len(result["records"]) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("evidence_id", 999),
        ("source_observed_at", "2026-11-05T12:00:00Z"),
    ],
)
def test_broken_target_frame_reference_is_unresolved(arista_case, field, value):
    arista_case["records"][1][field] = value
    result = partition(**arista_case)
    assert result["retained_advisories"] == []
    assert [i["code"] for i in result["current_evidence"]["issues"]] == ["proof_unresolved"]


def test_revision_identity_is_typed_and_decision_binds_actual_local_revision(arista_case):
    first = partition(**arista_case)["current_evidence"]["decisions"][0]["decision_id"]
    arista_case["records"][1]["revision_id"] = 22
    second = partition(**arista_case)["current_evidence"]["decisions"][0]["decision_id"]
    assert first != second
    arista_case["records"][1]["revision_id"] = True
    with pytest.raises(ValueError, match="revision"):
        partition(**arista_case)


@pytest.mark.parametrize(
    "field,value",
    [
        ("advisory_id", "19917-security-advisory-0104"),
        ("cves", ["CVE-2023-5501"]),
    ],
)
def test_selected_retained_scope_cannot_authenticate_itself(arista_case, field, value):
    arista_case["records"][0][field] = value
    result = partition(**arista_case)
    assert result["retained_advisories"] == []
    assert result["current_evidence"]["issues"][0]["code"] == "proof_unresolved"


def test_selected_primary_hash_must_match_retained_record(arista_case):
    arista_case["records"][0]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="selected"):
        partition(**arista_case)


@pytest.mark.parametrize("missing", ["selection", "alternate", "all"])
def test_missing_proof_stays_visibly_unresolved(arista_case, missing):
    if missing in {"selection", "all"}:
        arista_case["selection_context"]["selections"] = []
    if missing in {"alternate", "all"}:
        arista_case["selection_context"]["sources"] = arista_case["selection_context"]["sources"][
            :1
        ]
    result = partition(**arista_case)
    assert result["retained_advisories"] == []
    assert [i["code"] for i in result["current_evidence"]["issues"]] == ["proof_unresolved"]


def test_conflicting_selections_cannot_authorize_exclusion(arista_case):
    conflict = copy.deepcopy(arista_case["selection_context"]["selections"][0])
    conflict["requested_url"] = CSAF
    conflict["views"] = [
        {k: v for k, v in arista_case["selection_context"]["sources"][1].items() if k != "raw_b64"}
        | {"selected": True}
    ]
    arista_case["selection_context"]["selections"].append(conflict)
    result = partition(**arista_case)
    assert result["retained_advisories"] == []
    assert result["current_evidence"]["issues"][0]["code"] == "proof_unresolved"


@pytest.mark.parametrize(
    "before,after",
    [
        (b"Security Advisory 0103", b"Security Advisory 0104"),
        (b"CVE-2024-6858", b"CVE-2023-5501"),
        (b"EOS Versions", b"Unreviewed software"),
        (CSAF.encode(), CSAF.replace("_103.json", "_104.json").encode()),
    ],
)
def test_primary_bytes_are_independently_reviewed(arista_case, before, after):
    replace_frame(arista_case, 0, primary_bytes().replace(before, after))
    result = partition(**arista_case)
    assert result["retained_advisories"] == []
    assert result["current_evidence"]["issues"][0]["code"] == "proof_unresolved"


@pytest.mark.parametrize(
    "raw",
    [
        b"{malformed",
        alternate_bytes().replace(b"CVE-2023-5501", b"CVE-2024-6858"),
        alternate_bytes().replace(b"Advisory 103", b"Advisory 104"),
    ],
)
def test_alternate_bytes_must_independently_prove_literal_conflict(arista_case, monkeypatch, raw):
    replace_frame(arista_case, 1, raw)
    monkeypatch.setattr(importlib.import_module(MODULE), "REVIEWED_SHA256", sha256(raw).hexdigest())
    result = partition(**arista_case)
    assert result["retained_advisories"] == []
    assert result["current_evidence"]["issues"][0]["code"] == "proof_unresolved"


def test_same_cve_unrelated_record_and_later_hash_stay_current(arista_case):
    unrelated = copy.deepcopy(arista_case["records"][1])
    unrelated.update(advisory_id="Unrelated", revision_id=30)
    later = copy.deepcopy(arista_case["records"][1])
    later.update(revision_id=31, sha256=sha256(alternate_bytes() + b"\n").hexdigest())
    arista_case["records"].extend([unrelated, later])
    result = partition(**arista_case)
    assert len(result["retained_advisories"]) == 1
    assert [r["revision_id"] for r in result["records"]] == [20, 30, 31]


@pytest.mark.parametrize("field", ["evidence_id", "source_observed_at"])
def test_absent_capture_reference_is_unresolved(arista_case, field):
    del arista_case["records"][1][field]
    result = partition(**arista_case)
    assert result["retained_advisories"] == []
    assert result["current_evidence"]["issues"][0]["code"] == "proof_unresolved"


def test_database_evidence_and_normalized_history_remain_byte_identical(arista_case):
    from infrastructure_impact.application.current_evidence import collect_policy_input
    from infrastructure_impact.collection.service import resolve_document, retain_resolution
    from infrastructure_impact.plugins.shared import structured
    from infrastructure_impact.storage.repository import connect, evidence, ingest, latest

    registry = arista_case["registry"]
    with connect(":memory:") as db:
        # Reconstruct a legacy stored interpretation only in this synthetic test.
        legacy = registry.finalize(structured(alternate_bytes(), CSAF, "arista"), CSAF, "arista")
        ingest(db, alternate_bytes(), CSAF, lambda *_: legacy, "arista")
        ingest(db, primary_bytes(), URL, registry.normalize, "arista")
        resolution = resolve_document(
            db,
            URL,
            "arista",
            fetcher=lambda _db, url, _v: primary_bytes() if url == URL else alternate_bytes(),
        )
        retain_resolution(db, "arista", URL, resolution)
        before_records = latest(db)
        before_dump = list(db.iterdump())
        before_capture = dict(
            db.execute("SELECT * FROM evidence WHERE source_url=?", (CSAF,)).fetchone()
        )
        # Re-observing already captured bytes must keep the initial capture metadata.
        evidence(db, alternate_bytes(), CSAF)
        context = collect_policy_input(db, before_records, registry=registry)
        result = partition(
            before_records, context, registry=registry, publication=None, generated_at=AT
        )
        assert len(result["retained_advisories"]) == 1
        assert result["records"][0]["cves"] == ["CVE-2024-6858"]
        assert latest(db) == before_records
        assert list(db.iterdump()) == before_dump
        assert (
            dict(db.execute("SELECT * FROM evidence WHERE source_url=?", (CSAF,)).fetchone())
            == before_capture
        )
        assert registry.normalize(primary_bytes(), URL, "arista")["cves"] == ["CVE-2024-6858"]
        with pytest.raises(ValueError, match="selection"):
            registry.normalize(alternate_bytes(), CSAF, "arista")


def test_registered_policy_has_no_blanket_cve_retirement(arista_case):
    # Default wiring must execute this policy rather than a test replacement.
    assert (
        arista_case["registry"].get("arista").current_evidence_policy
        is importlib.import_module(MODULE).decide
    )
    arista_case["records"] = [arista_case["records"][1] | {"sha256": "f" * 64}]
    arista_case["selection_context"] = {"selections": [], "sources": []}
    result = partition(**arista_case)
    assert result["current_evidence"]["counts"] == {
        "current": 1,
        "retained_total": 1,
        "excluded": 0,
    }
    assert result["current_evidence"]["issues"] == []
