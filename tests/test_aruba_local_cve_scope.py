"""Authored text exercises attribution; cached-primary acceptance lives in the audit.

Only the reviewed byte/section pins are replaced for these authored inputs. This
does not prove publisher bytes; the separate real-byte replay uses production pins.
"""

import copy
import json
from hashlib import sha256

import pytest
from test_aruba_text_coverage import CVES, URL, signed_text
from test_switching_aruba_fix_links import AT, browser

from infrastructure_impact import publication_codec
from infrastructure_impact.adapters import aruba_text, cvss
from infrastructure_impact.application import kev, switching_comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.application import switching_releases as releases
from infrastructure_impact.application.publication_reader import PublicationReader
from infrastructure_impact.plugins import default_registry

IDS = ["CVE-2020-25705", "CVE-2021-29143", "CVE-2021-29148", "CVE-2021-29149"]
LOCAL = {"CVE-2021-29143", "CVE-2021-29149"}
CLAUSES = {
    "CVE-2021-29143": (
        "An AOS-CX device has a command injection vulnerability. "
        "Exploitation requires admin credentials and external storage."
    ),
    "CVE-2021-29149": (
        "An AOS-CX device has a physical update vulnerability. "
        "The attacker needs admin credentials and ISP update access."
    ),
}


def authored():
    raw = signed_text().replace(b"Last Update: 2022-Jan-11\n", b"")
    raw = raw.replace(b"Revision: 3", b"Revision: 1")
    for before, after in zip(CVES, IDS):
        raw = raw.replace(before.encode(), after.encode())
    for i in (1, 3):
        raw = raw.replace(f"Synthetic condition {i}.".encode(), CLAUSES[IDS[i]].encode())
    return raw


@pytest.fixture
def reviewed(monkeypatch):
    raw = authored()
    _, _, _, sections = aruba_text._read(raw, URL, "aruba")
    monkeypatch.setattr(aruba_text, "LOCAL_AFFECTED_URL", URL, raising=False)
    monkeypatch.setattr(aruba_text, "LOCAL_AFFECTED_SHA256", sha256(raw).hexdigest(), raising=False)
    monkeypatch.setattr(
        aruba_text,
        "LOCAL_AFFECTED_SECTIONS",
        {cid: sha256(sections[cid].encode()).hexdigest() for cid in LOCAL},
        raising=False,
    )
    return raw


def extracted(raw, url=URL):
    registry = default_registry()
    document = registry.normalize(raw, url, "aruba")
    return registry.research_evidence(raw, url, "aruba", document)


def local_claims(result):
    return [c for c in result["claims"] if c["scope"] == "cve_specific"]


def projected(result, raw=None):
    result = copy.deepcopy(result)
    if raw is not None:
        document = default_registry().normalize(raw, URL, "aruba")
        scores = cvss.extract(raw, URL, "aruba", document)
        evidence._attach_scores(
            result["claims"],
            dict(
                advisories=[dict(vendor="aruba", advisory_id=document["advisory_id"], **scores)],
                vendor_severity=scores["vendor_severity"],
                fallback=dict(claims=[]),
            ),
        )

    def stamp(value):
        if isinstance(value, dict):
            if "retrieved_at" in value:
                value["retrieved_at"] = AT
            for child in value.values():
                stamp(child)
        elif isinstance(value, list):
            for child in value:
                stamp(child)

    stamp(result)
    for claim in result["claims"]:
        claim["revision"] = "authored-revision"
    result.pop("bundles")
    return evidence.project(result, publication=None, generated_at=AT)


def native_scored_stream(report, monkeypatch):
    """Existing decoded-transport seam, including its numeric-kind observer."""
    reader = PublicationReader.__new__(PublicationReader)
    reader.identity = dict(publication=None, generated_at=AT)
    reader.limits = dict(selected=128000000, stream=128000000)
    raw = [json.dumps(c, ensure_ascii=True).encode() for c in report["claims"]]
    monkeypatch.setattr(reader, "field", lambda root, key: report[key])
    monkeypatch.setattr(
        reader,
        "_claim_routes",
        lambda: [(c["claim_id"], i, i + 1, len(raw[i])) for i, c in enumerate(report["claims"])],
    )

    def stream(root, first, end, *args, number_observer, **kwargs):
        def number(kind, text):
            number_observer(publication_codec.LogicalNumber(kind, text))
            return 0

        json.loads(
            raw[first], parse_int=lambda s: number("i", s), parse_float=lambda s: number("f", s)
        )
        yield raw[first]

    monkeypatch.setattr(reader, "_stream", stream)
    return list(reader.iter_claims())


def test_owned_local_clauses_append_two_family_claims_without_strengthening_shared_facts(reviewed):
    result = extracted(reviewed)
    local = local_claims(result)
    assert {c["cve_id"] for c in local} == LOCAL
    assert len(result["claims"]) == 6
    shared = [c for c in result["claims"] if c["scope"] == "bulletin_shared"]
    assert {c["cve_id"] for c in shared} == set(IDS)
    assert all(c["version_expressions"] and c["remediations"] for c in shared)
    assert all("conditional_affected" not in c for c in shared)
    assert {c["initial_published_at"] for c in result["claims"]} == {"2021-07-13"}
    for c in local:
        assert (c["product"], c["family"], c["status"]) == ("AOS-CX", "aruba-aoscx", "affected")
        assert c["source"]["source_locator"] == "text/Details/" + c["cve_id"]
        assert c["conditions"][0].startswith(CLAUSES[c["cve_id"]])
        assert c.get("conditional_affected") is True
        assert not c["remediations"] and not c["version_expressions"]
        assert not c["named_platforms"] and not c["platform_bindings"]
        assert c["product_id"] is None and c["updated_at"] is None
        assert releases._claim_candidates(c, "2026-11-14") == ([], [])


def test_shared_claims_remain_identical_when_local_attribution_is_enabled(reviewed, monkeypatch):
    enabled = extracted(reviewed)
    monkeypatch.setattr(aruba_text, "LOCAL_AFFECTED_SHA256", "0" * 64, raising=False)
    shared_only = extracted(reviewed)
    assert [c for c in enabled["claims"] if c["scope"] == "bulletin_shared"] == shared_only[
        "claims"
    ]
    assert not local_claims(shared_only)


@pytest.mark.parametrize("mutation", ["hash", "url", "identity", "publication", "revision"])
def test_other_source_or_header_cannot_authorize_local_attribution(reviewed, monkeypatch, mutation):
    raw, url = reviewed, URL
    if mutation == "hash":
        raw += b"\n"
    elif mutation == "url":
        url = URL.replace("2021-013.txt", "2021-014.txt")
        raw = raw.replace(b"ARUBA-PSA-2021-013", b"ARUBA-PSA-2021-014")
    elif mutation == "identity":
        # The parser owns identity too: header/URL mismatch must reject.
        raw = raw.replace(b"ARUBA-PSA-2021-013", b"ARUBA-PSA-2021-014")
        with pytest.raises(ValueError):
            extracted(raw)
        return
    elif mutation == "publication":
        raw = raw.replace(b"2021-July-13", b"2021-July-14")
    elif mutation == "revision":
        raw = raw.replace(b"Revision: 1", b"Revision: 2")
    if mutation != "hash":
        monkeypatch.setattr(aruba_text, "LOCAL_AFFECTED_SHA256", sha256(raw).hexdigest())
    assert not local_claims(extracted(raw, url))


@pytest.mark.parametrize("mutation", ["clause", "precondition", "negation", "cve"])
def test_owned_section_drift_does_not_promote_changed_cve(reviewed, monkeypatch, mutation):
    if mutation == "clause":
        raw = reviewed.replace(b"command injection vulnerability", b"unrelated diagnostic")
    elif mutation == "precondition":
        raw = reviewed.replace(b"admin credentials and external storage", b"no prerequisites")
    elif mutation == "negation":
        raw = reviewed.replace(
            b"has a command injection vulnerability", b"has no such vulnerability"
        )
    else:
        raw = reviewed.replace(b"CVE-2021-29143", b"CVE-2021-99999")
    # Even a newly reviewed document hash alone must not bypass CVE-local pins.
    monkeypatch.setattr(aruba_text, "LOCAL_AFFECTED_SHA256", sha256(raw).hexdigest())
    assert {c["cve_id"] for c in local_claims(extracted(raw))} == {"CVE-2021-29149"}


def test_other_cves_never_inherit_local_product_mentions(reviewed, monkeypatch):
    raw = reviewed.replace(b"Synthetic condition 0.", CLAUSES["CVE-2021-29143"].encode())
    raw = raw.replace(b"Synthetic condition 2.", CLAUSES["CVE-2021-29149"].encode())
    monkeypatch.setattr(aruba_text, "LOCAL_AFFECTED_SHA256", sha256(raw).hexdigest())
    assert {c["cve_id"] for c in local_claims(extracted(raw))} == LOCAL


def test_unaffected_advisory_never_becomes_affected_from_local_rule(reviewed):
    raw = signed_text(excluded=True).replace(b"2021-013", b"2021-019")
    url = URL.replace("2021-013", "2021-019")
    result = extracted(raw, url)
    assert not local_claims(result)
    assert all(c["status"] == "unaffected" for c in result["claims"])


def test_local_assertions_keep_only_existing_same_cve_source_scores(reviewed):
    report = projected(extracted(reviewed), reviewed)
    for c in local_claims(report):
        shared = next(
            s
            for s in report["claims"]
            if s["scope"] == "bulletin_shared" and s["cve_id"] == c["cve_id"]
        )
        assert len(c["scores"]) == 1
        assert c["scores"] == shared["scores"]
        score = c["scores"][0]
        assert score["scope"] == "cve_specific" and score["cve_id"] == c["cve_id"]
        assert score["source"]["source_url"] == c["source"]["source_url"]
        assert score["source"]["source_sha256"] == c["source"]["source_sha256"]
        assert score["value"] == 9.8 and score["preferred"] is True
        assert all(v["scope"] == "advisory" for v in c["vendor_severity"])


def test_two_explicit_cves_cross_python_native_and_browser_boundaries(reviewed, monkeypatch):
    report = projected(extracted(reviewed), reviewed)
    evidence.validate_evidence(report)
    full = switching_comparison.build_report(
        report,
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-09",
    )
    selected = switching_comparison.select_report(
        full, vendor="aruba", window="2021", evaluated_at=AT
    )["rows"][0]
    assert selected["affected_cve_ids"] == ["CVE-2021-29143", "CVE-2021-29149"]
    assert selected["conditional_cve_ids"] == ["CVE-2021-29143", "CVE-2021-29149"]
    assert selected["counts"]["conditional_cves"] == 2
    assert selected["counts"]["conditionality_unclassified_cves"] == 0
    assert selected["counts"]["affected_advisories"] == 1
    assert selected["counts"]["fixed_only_claims"] == 0
    assert selected["counts"]["remediation_events"] == 0
    assert native_scored_stream(report, monkeypatch) == report["claims"]
    assert browser(report) == browser(report, stream=True) == "accepted"
