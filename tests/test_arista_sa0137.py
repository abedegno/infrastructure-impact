from pathlib import Path

import pytest

from infrastructure_impact.plugins.registry import default_registry

URL = "https://www.arista.com/en/support/advisories-notices/security-advisory/24005-security-advisory-0137"
RAW = Path(__file__).with_name("fixtures").joinpath("arista-sa0137-authored.html")


def test_reviewed_scope_and_research():
    registry = default_registry()
    raw = RAW.read_bytes()
    document = registry.normalize(raw, URL, "arista")
    assert len({(a["cve_id"], a["product_id"]) for a in document["assessments"]}) == len(
        document["assessments"]
    )
    assert document["source_format"] == "Arista reviewed SA-0137 tunnel applicability HTML"
    assert document["published_at"] == "2026-05-05"
    assert document["updated_at"] == "2026-08-10"
    affected = [a for a in document["assessments"] if a["status"] == "affected"]
    assert len(affected) == 7
    assert len(affected[0]["versions"]) == 9
    assert affected[0]["product"] == "Arista EOS"
    assert affected[3]["platforms"] == ["7500R/R2 Series"]
    assert "Limited exposure" in affected[4]["exposure"][-1]["details"]
    assert all(not a["versions"] for a in document["assessments"] if a["status"] == "unaffected")
    assert not any(
        r["category"] == "vendor_fix" for a in document["assessments"] for r in a["remediations"]
    )
    research = registry.get("arista").research_evidence(raw, URL, "arista", document)
    assert len(research["claims"]) == len(document["assessments"])
    assert (
        sum(
            c["family"] == "arista-eos"
            and c["product"] == "Arista EOS"
            and c["status"] == "affected"
            for c in research["claims"]
        )
        == 1
    )
    assert all(c["product_id"] is None for c in research["claims"])
    assert all(c["conditional_affected"] for c in research["claims"] if c["status"] == "affected")
    assert all(
        b["basis"] == "unresolved" for c in research["claims"] for b in c["platform_bindings"]
    )


@pytest.mark.parametrize(
    "before,after",
    [
        (b"Limited exposure (IP-in-IPv6 and GUEv6) on:", b"Changed scope"),
        (b"<h4>EOS Versions</h4>", b"<h4>Other Versions</h4>"),
        (b"CVE-2026-7473", b"CVE-2026-9999"),
        (b"not affected by this vulnerability:", b"affected by this vulnerability:"),
    ],
)
def test_changed_boundaries_fail_closed(before, after):
    with pytest.raises(ValueError):
        default_registry().normalize(RAW.read_bytes().replace(before, after), URL, "arista")


def synthetic_alternate():
    import json

    from infrastructure_impact.adapters.arista_sa0137 import CSAF_ID

    tree = {
        "branches": [
            {
                "category": "vendor",
                "name": "Arista Networks, Inc.",
                "branches": [
                    {
                        "category": "product_family",
                        "name": "Software Products",
                        "branches": [
                            {
                                "category": "product_name",
                                "name": "EOS",
                                "branches": [
                                    {
                                        "category": "product_version",
                                        "name": "EOS version 1.0.0",
                                        "product": {
                                            "name": "EOS version 1.0.0",
                                            "product_id": "CSAFPID-0",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    return json.dumps(
        {
            "document": {
                "title": "Authored alternate",
                "tracking": {
                    "id": CSAF_ID,
                    "status": "draft",
                    "initial_release_date": "2026-07-28T19:58:28Z",
                },
                "references": [{"category": "self", "url": URL}],
            },
            "product_tree": tree,
            "vulnerabilities": [
                {"cve": "CVE-2026-7473", "product_status": {"first_affected": ["CSAFPID-0"]}}
            ],
        }
    ).encode()


@pytest.mark.parametrize("route", ["html", "csaf"])
def test_both_entry_routes_pair_literal_identities(monkeypatch, route):
    from hashlib import sha256

    from infrastructure_impact.adapters import arista_sa0137 as module
    from infrastructure_impact.plugins.arista_selection import resolve

    alternate = synthetic_alternate()
    monkeypatch.setattr(module, "REVIEWED_SHA256", sha256(alternate).hexdigest())
    sources = {URL: RAW.read_bytes(), module.CSAF: alternate}
    requested = URL if route == "html" else module.CSAF
    result = resolve(sources[requested], requested, sources.__getitem__)
    assert result.selected.url == URL
    assert len(result.alternatives) == 1
    assert result.alternatives[0].url == module.CSAF


@pytest.mark.parametrize("mutation", ["hash", "final", "cve", "id"])
def test_alternate_changes_are_visible(monkeypatch, mutation):
    from hashlib import sha256

    from infrastructure_impact.adapters import arista_sa0137 as module
    from infrastructure_impact.plugins.arista_selection import resolve

    raw = synthetic_alternate()
    monkeypatch.setattr(module, "REVIEWED_SHA256", sha256(raw).hexdigest())
    changed = {
        "hash": raw + b" ",
        "final": raw.replace(b"draft", b"final"),
        "cve": raw.replace(b"CVE-2026-7473", b"CVE-2026-9999"),
        "id": raw.replace(b"Advisory 137", b"Advisory 138"),
    }[mutation]
    result = resolve(RAW.read_bytes(), URL, lambda _: changed)
    assert result.alternatives == ()
    assert result.unavailable


@pytest.fixture
def policy_case(monkeypatch):
    from hashlib import sha256

    from test_arista_current_evidence import AT, frame

    from infrastructure_impact.adapters import arista_sa0137 as module

    raw = synthetic_alternate()
    monkeypatch.setattr(module, "REVIEWED_SHA256", sha256(raw).hexdigest())
    sources = [frame(RAW.read_bytes(), URL, 71), frame(raw, module.CSAF, 72)]
    records = [
        dict(
            vendor="arista",
            advisory_id=advisory_id,
            revision_id=80 + i,
            source_url=f["source_url"],
            sha256=f["source_sha256"],
            cves=module.CVES.copy(),
            evidence_id=f["evidence_id"],
            source_observed_at=AT,
        )
        for i, (f, advisory_id) in enumerate(zip(sources, [module.ID, module.CSAF_ID]))
    ]
    context = {
        "sources": sources,
        "selections": [
            {
                "vendor": "arista",
                "requested_url": URL,
                "selected_at": AT,
                "reason": "Authored reviewed pair",
                "views": [
                    {k: v for k, v in f.items() if k != "raw_b64"} | {"selected": i == 0}
                    for i, f in enumerate(sources)
                ],
            }
        ],
    }
    return records, context


def test_exact_complete_pair_only_is_excluded(policy_case):
    import copy
    import json

    from test_arista_current_evidence import AT

    from infrastructure_impact.application.current_evidence import partition

    records, context = policy_case
    before = copy.deepcopy(policy_case)
    result = partition(
        records, context, registry=default_registry(), publication=None, generated_at=AT
    )
    assert len(result["records"]) == len(result["retained_advisories"]) == 1
    assert (
        result["retained_advisories"][0]["record"]["advisory_id"]
        == "Arista Networks Security Advisory 137"
    )
    assert result["current_evidence"]["issues"] == []
    assert len(result["current_evidence"]["decisions"][0]["proofs"]) == 2
    assert "raw_b64" not in json.dumps(result)
    assert before == policy_case


@pytest.mark.parametrize(
    "mutation",
    [
        "selection",
        "alternate_view",
        "alternate_frame",
        "primary_frame",
        "primary_record",
        "receipt",
        "time",
        "selected_receipt",
        "selected_time",
        "hash",
        "id",
        "cve",
        "duplicate_selected",
        "unlinked_alternate",
    ],
)
def test_incomplete_or_changed_proof_remains_unresolved(policy_case, mutation):
    from infrastructure_impact.plugins.arista_current_evidence import decide

    records, context = policy_case
    if mutation == "selection":
        context["selections"] = []
    elif mutation == "alternate_view":
        context["selections"][0]["views"].pop()
    elif mutation == "alternate_frame":
        context["sources"].pop()
    elif mutation == "primary_frame":
        context["sources"].pop(0)
    elif mutation == "primary_record":
        records[0]["advisory_id"] = "Unrelated"
    elif mutation in {"receipt", "time"}:
        records[1]["evidence_id" if mutation == "receipt" else "source_observed_at"] = (
            999 if mutation == "receipt" else "2026-11-01T12:00:00Z"
        )
    elif mutation in {"selected_receipt", "selected_time"}:
        records[0]["evidence_id" if mutation == "selected_receipt" else "source_observed_at"] = (
            999 if mutation == "selected_receipt" else "2026-11-01T12:00:00Z"
        )
    elif mutation == "hash":
        records[1]["sha256"] = "f" * 64
    elif mutation == "id":
        records[1]["advisory_id"] = "Arista Networks Security Advisory 138"
    elif mutation == "cve":
        records[1]["cves"] = ["CVE-2026-9999"]
    elif mutation == "duplicate_selected":
        context["selections"][0]["views"][1]["selected"] = True
    else:
        context["selections"][0]["views"][1]["evidence_id"] = 999
    result = decide(records, context)
    assert result["decisions"] == []
    assert [i["code"] for i in result["issues"]] == ["proof_unresolved"]


@pytest.mark.parametrize(
    "before,after",
    [
        (b"draft", b"final"),
        (b"1.0.0", b"2.0.0"),
        (b"first_affected", b"known_affected"),
        (b"Advisory 137", b"Advisory 138"),
        (b"CVE-2026-7473", b"CVE-2026-9999"),
        (URL.encode(), b"https://www.arista.com/other"),
    ],
)
def test_draft_shape_is_independent_proof(policy_case, monkeypatch, before, after):
    from hashlib import sha256

    from test_arista_current_evidence import frame

    from infrastructure_impact.adapters import arista_sa0137 as module
    from infrastructure_impact.plugins.arista_current_evidence import decide

    records, context = policy_case
    raw = synthetic_alternate().replace(before, after)
    new = frame(raw, module.CSAF, 72)
    context["sources"][1] = new
    context["selections"][0]["views"][1].update({k: v for k, v in new.items() if k != "raw_b64"})
    records[1]["sha256"] = new["source_sha256"]
    monkeypatch.setattr(module, "REVIEWED_SHA256", sha256(raw).hexdigest())
    assert decide(records, context)["decisions"] == []
    assert decide(records, context)["issues"][0]["code"] == "proof_unresolved"


def test_advertised_pair_must_be_inside_heading(policy_case):
    from test_arista_current_evidence import frame

    from infrastructure_impact.adapters import arista_sa0137 as module
    from infrastructure_impact.plugins.arista_current_evidence import decide

    records, context = policy_case
    raw = (
        RAW.read_bytes().replace(module.CSAF.encode(), b"https://www.arista.com/other.json")
        + f'<footer><a href="{module.CSAF}">CSAF</a></footer>'.encode()
    )
    new = frame(raw, URL, 71)
    context["sources"][0] = new
    context["selections"][0]["views"][0].update({k: v for k, v in new.items() if k != "raw_b64"})
    records[0]["sha256"] = new["source_sha256"]
    assert decide(records, context)["decisions"] == []
    assert decide(records, context)["issues"][0]["code"] == "proof_unresolved"


def test_database_capture_and_normalized_history_are_retained(monkeypatch):
    from hashlib import sha256

    from test_arista_current_evidence import AT

    from infrastructure_impact.adapters import arista_sa0137 as module
    from infrastructure_impact.application.current_evidence import collect_policy_input, partition
    from infrastructure_impact.collection.service import resolve_document, retain_resolution
    from infrastructure_impact.plugins.shared import structured
    from infrastructure_impact.storage.repository import connect, ingest, latest

    raw = synthetic_alternate()
    monkeypatch.setattr(module, "REVIEWED_SHA256", sha256(raw).hexdigest())
    registry = default_registry()
    with connect(":memory:") as db:
        legacy = registry.finalize(structured(raw, module.CSAF, "arista"), module.CSAF, "arista")
        ingest(db, raw, module.CSAF, lambda *_: legacy, "arista")
        ingest(db, RAW.read_bytes(), URL, registry.normalize, "arista")
        resolution = resolve_document(
            db,
            URL,
            "arista",
            fetcher=lambda _db, url, _vendor: {URL: RAW.read_bytes(), module.CSAF: raw}[url],
        )
        retain_resolution(db, "arista", URL, resolution)
        records = latest(db)
        before = list(db.iterdump())
        context = collect_policy_input(db, records, registry=registry)
        result = partition(records, context, registry=registry, publication=None, generated_at=AT)
        assert len(result["retained_advisories"]) == 1
        assert result["retained_advisories"][0]["record"]["document_status"] == "draft"
        assert [r["advisory_id"] for r in result["records"]] == [module.ID]
        assert latest(db) == records
        assert list(db.iterdump()) == before
        with pytest.raises(ValueError, match="selection"):
            registry.normalize(raw, module.CSAF, "arista")


@pytest.mark.parametrize(
    "before,after",
    [
        (b'<div class="clear5"></div>', b""),
        (b"<h4>EOS Versions</h4>", b"<h4>EOS Versions</h4><ul><li>All versions</li></ul>"),
        (b"<h3>Affected Platforms</h3>", b"<h3>Unknown group</h3><h3>Affected Platforms</h3>"),
        (
            b"<li>Arista EOS-based products:<br>",
            b"<li>Arista EOS-based products: extra qualifier<br>",
        ),
        (
            b'<div class="clear10"></div><ul><li>Arista EOS-based products:</li>',
            b'<div class="clear10"></div><ul>extra qualifier<li>Arista EOS-based products:</li>',
        ),
    ],
)
def test_unreviewed_local_boundaries_cannot_be_ignored(before, after):
    raw = RAW.read_bytes()
    assert before in raw
    with pytest.raises(ValueError):
        default_registry().normalize(raw.replace(before, after), URL, "arista")


def test_actual_source_validation_cases_remain_awaiting_human_review():
    from infrastructure_impact.application.switching_validation import definition, report

    cases = [c for c in definition()["cases"] if c["id"].startswith("switching-arista-sa0137-")]
    assert len(cases) == 3
    assert all(c["source_url"] == URL for c in cases)
    assert report([], [])["independent_human_review_completed"] is False


def test_positive_platforms_preserve_explicit_eos_parent():
    from infrastructure_impact.adapters.arista_sa0137 import AFFECTED

    registry = default_registry()
    raw = RAW.read_bytes()
    document = registry.normalize(raw, URL, "arista")
    owned = [a for a in document["assessments"] if a["product"] in AFFECTED]
    assert len(owned) == 6
    assert all(a["product_context"] == [["product_family", "Arista EOS"]] for a in owned)
    claims = registry.research_evidence(raw, URL, "arista", document)["claims"]
    assert len(claims) == 52
    assert sum(c["family"] == "arista-eos" for c in claims) == 36
    assert sum(c["status"] == "affected" for c in claims) == 7
    assert all(c["family"] == "arista-eos" for c in claims if c["status"] == "affected")
    assert sum(c["family"] == "arista-eos" and c["status"] == "unaffected" for c in claims) == 29
    assert all(
        c["family"] is None
        for c in claims
        if c["status"] == "unaffected" and c["product"] != "Arista EOS"
    )
    assert all(
        b["basis"] == "unresolved" and b["model"] is None
        for c in claims
        for b in c["platform_bindings"]
    )
    assert not any(r["category"] == "vendor_fix" for c in claims for r in c["remediations"])
