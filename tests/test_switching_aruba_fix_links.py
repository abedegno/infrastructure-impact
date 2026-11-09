"""Authored/typed Aruba linkage cases; synthetic bytes are never primary evidence."""

import copy
import json
import subprocess

import pytest
from jsonschema import ValidationError

from infrastructure_impact.adapters import switching
from infrastructure_impact.application import kev, switching_comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.application.publication_reader import PublicationReader
from infrastructure_impact.settings import PACKAGE

URL = "https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04669.json"
DIGEST = "07e221b234c64d09ef18a2d291639e2bbca2d6f4bd511dbb6325fee088daa138"
AT = "2026-11-09T12:00:00Z"
PAIRS = [
    (">=10.14.0000|<=10.14.0006_aos-cx", "10.14.0007_aos-cx", 3, 0),
    (">=10.13.0000|<=10.13.1030_aos-cx", "10.13.1031_aos-cx", 4, 1),
    (">=10.10.0000|<=10.10.1130_aos-cx", "10.10.1131_aos-cx", 7, 2),
]
IDS = [p[1] for p in PAIRS] + [
    PAIRS[0][0],
    PAIRS[1][0],
    ">=10.12.0000|<=10.12.1050_aos-cx",
    ">=10.11.0000|<=10.11.1070_aos-cx",
    PAIRS[2][0],
    ">=10.0.0000|<10.10.0000_aos-cx_legacy",
]


def authored_csaf():
    children = []
    for index, pid in enumerate(IDS):
        children.append(
            dict(
                category="product_version" if index < 3 else "product_version_range",
                name=pid.removesuffix("_aos-cx")
                if index < 3
                else "vers:semver/" + pid.removesuffix("_aos-cx").removesuffix("_aos-cx_legacy"),
                product=dict(name="AOS-CX", product_id=pid),
            )
        )
    details = (
        "HPE Aruba Networking\n\n- ArubaOS-CX Switches\n"
        "   - 10.14.0007 and above\n   - 10.13.1031 and above\n   - 10.10.1131 and above\n\n"
        "Software versions with resolution/fixes for the vulnerabilities "
        "covered above, can be downloaded from the HPE Networking Support Portal."
    )
    return dict(
        document=dict(
            tracking=dict(
                id="HPESBNW04669",
                version="2",
                status="final",
                initial_release_date="2024-07-09T17:00:00.000Z",
                current_release_date="2024-07-31T20:00:00.000Z",
            )
        ),
        product_tree=dict(
            branches=[
                dict(
                    category="vendor",
                    name="HPE Aruba Networking",
                    branches=[dict(category="product_name", name="AOS-CX", branches=children)],
                )
            ]
        ),
        vulnerabilities=[
            dict(
                cve="CVE-2024-6387",
                product_status=dict(
                    fixed=IDS[:3], known_affected=IDS[3:8], known_not_affected=IDS[8:]
                ),
                remediations=[
                    dict(
                        category="vendor_fix",
                        product_ids=IDS[:3],
                        details=details,
                        date="2024-07-09T17:00:00.000Z",
                    )
                ],
            )
        ],
    )


def extracted(data=None, *, digest=DIGEST, url=URL):
    # Inject the reviewed digest only at the typed CSAF seam. Real-byte acceptance
    # is checked by the separate operator replay, never by this authored fixture.
    return switching._csaf(
        json.dumps(data or authored_csaf()).encode(),
        url,
        "aruba",
        {"advisory_id": "HPESBNW04669"},
        digest,
    )


def projected():
    result = extracted()

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
        claim["revision"] = "typed-revision-2"
    result.pop("bundles")
    return evidence.project(result, publication=None, generated_at=AT)


def reidentify(report):
    for claim in report["claims"]:
        claim["claim_id"] = evidence.definition_sha256(
            {key: value for key, value in claim.items() if key != "claim_id"}
        )


def browser(report, *, stream=False):
    script = """
const fs=require('fs'), vm=require('vm'); global.window=global;
for(const name of ['lossless-json','switching-contracts'])
 vm.runInThisContext(fs.readFileSync(process.argv[1]+'/'+name+'.js','utf8'));
const {report,study,stream,full}=JSON.parse(fs.readFileSync(0,'utf8'));
try {
 const c=InfrastructureSwitchingContracts;
 if(stream) {const s=c.evidenceStream(report,study); for(const claim of report.claims)s.add(claim);s.finish();}
 else c.full(full);
 console.log('accepted');
} catch(e) {console.log('rejected');}
"""
    full = switching_comparison.build_report(
        projected(),
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-09",
    )
    full["generated_at"] = report["generated_at"]
    full["inputs"]["kev"]["generated_at"] = report["generated_at"]
    full["inputs"]["evidence"] = report
    return (
        subprocess.check_output(
            ["node", "-e", script, str(PACKAGE / "web")],
            input=json.dumps(
                dict(report=report, study=evidence.definition(), stream=stream, full=full)
            ).encode(),
        )
        .decode()
        .strip()
    )


def native_stream(report, monkeypatch):
    # Supply a decoded transport at the reader boundary; exercise its real shape,
    # identity, per-claim semantics, bounded retention and final sibling validation.
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
    monkeypatch.setattr(reader, "_stream", lambda root, first, end, *a, **kw: iter([raw[first]]))
    return list(reader.iter_claims())


def test_three_exact_links_leave_two_ranges_and_legacy_unlinked(monkeypatch):
    report = projected()
    claims = {c["product_id"]: c for c in report["claims"]}
    assert sum(bool(c["remediations"]) for c in claims.values() if c["status"] == "affected") == 3
    for affected, fixed, _, _ in PAIRS:
        rem = claims[affected]["remediations"][0]
        assert rem["scope_binding"]["fixed_product_id"] == fixed
        assert rem["product_ids"] == []
        assert rem["version_expressions"] == [fixed.removesuffix("_aos-cx")]
        assert rem["availability"] == "vendor_reports_fixed"
        assert rem["availability_date"] == "2024-07-09T17:00:00.000Z"
        assert claims[fixed]["remediations"][0]["product_ids"] == [fixed]
    assert claims[IDS[5]]["remediations"] == claims[IDS[6]]["remediations"] == []
    assert claims[IDS[8]]["status"] == "unaffected"
    assert claims[IDS[8]]["remediations"] == []
    assert all(
        c["family"] == "aruba-aoscx"
        and not c["platform_bindings"]
        and c["scope_level"] == "os_family"
        for c in claims.values()
    )
    evidence.validate_evidence(report)
    assert native_stream(report, monkeypatch) == report["claims"]
    assert browser(report) == browser(report, stream=True) == "accepted"


def test_unreviewed_bytes_cannot_attach_even_with_recognized_resolution():
    data = authored_csaf()
    raw = json.dumps(data).encode()
    result = switching.extract(raw, URL, "aruba", {"advisory_id": "HPESBNW04669"})
    assert not any(r.get("scope_binding") for c in result["claims"] for r in c["remediations"])


@pytest.mark.parametrize("change", ["negated", "planned", "truncated", "lifecycle", "foreign"])
def test_changed_resolution_requires_a_new_reviewed_digest(change):
    data = authored_csaf()
    data["vulnerabilities"][0]["remediations"][0]["details"] += {
        "negated": "\n\nA fix is not available.",
        "planned": "\n\nA fix is planned.",
        "truncated": "x" * 4001,
        "lifecycle": "\n\nThese releases are unsupported.",
        "foreign": "\n\n- Other products\n   - AOS-CX updates are unavailable.",
    }[change]
    result = switching.extract(
        json.dumps(data).encode(), URL, "aruba", {"advisory_id": "HPESBNW04669"}
    )
    assert not any(r.get("scope_binding") for c in result["claims"] for r in c["remediations"])


@pytest.mark.parametrize(
    "mutation",
    [
        "cve",
        "revision",
        "publisher",
        "url",
        "hash",
        "parent",
        "fixed_id",
        "locator",
        "version",
        "availability",
        "date",
        "details",
        "missing",
        "duplicate",
        "unresolved_train",
        "binding_id",
        "product_scope",
        "binding_missing_id",
        "duplicate_version",
        "all_hashes",
    ],
)
def test_forged_fixed_siblings_are_rejected_by_all_boundaries(monkeypatch, mutation):
    report = projected()
    affected = next(c for c in report["claims"] if c["product_id"] == PAIRS[0][0])
    assert affected["remediations"], "reviewed association must exist before mutation"
    fixed = next(c for c in report["claims"] if c["product_id"] == PAIRS[0][1])
    rem = affected["remediations"][0]
    if mutation in {
        "cve",
        "revision",
        "publisher",
        "url",
        "hash",
        "parent",
        "fixed_id",
        "locator",
        "version",
    }:
        if mutation == "cve":
            fixed["cve_id"] = "CVE-2024-99999"
        elif mutation == "revision":
            fixed["revision"] = "other"
        elif mutation == "publisher":
            fixed["publisher"]["sequence"] = "3"
        elif mutation == "url":
            fixed["source"]["source_url"] = URL + "?other"
        elif mutation == "hash":
            fixed["source"]["source_sha256"] = "f" * 64
        elif mutation == "parent":
            fixed["product"] = "Other product"
        elif mutation == "fixed_id":
            fixed["product_id"] = "other"
        elif mutation == "locator":
            fixed["source"]["source_locator"] += "/other"
        else:
            fixed["version_expressions"] = ["10.14.9999"]
    elif mutation in {"availability", "date", "details"}:
        key, value = {
            "availability": ("availability", "planned"),
            "date": ("availability_date", "2027-01-01"),
            "details": ("details", "No fix is available."),
        }[mutation]
        fixed["remediations"][0][key] = value
    elif mutation == "missing":
        report["claims"].remove(fixed)
    elif mutation in {"duplicate", "duplicate_version"}:
        duplicate = copy.deepcopy(fixed)
        if mutation == "duplicate_version":
            duplicate["version_expressions"] = ["10.14.9999"]
        else:
            duplicate["conditions"].append("conflicting retained sibling")
        report["claims"].append(duplicate)
    elif mutation == "all_hashes":

        def alter(value):
            if isinstance(value, dict):
                if "source_sha256" in value:
                    value["source_sha256"] = "e" * 64
                for child in value.values():
                    alter(child)
            elif isinstance(value, list):
                for child in value:
                    alter(child)

        alter(report)
    elif mutation == "unresolved_train":
        affected["product_id"] = IDS[5]
    elif mutation == "binding_id":
        rem["scope_binding"]["fixed_product_id"] = IDS[1]
    elif mutation == "product_scope":
        rem["product_ids"] = [affected["product_id"]]
    else:
        del rem["scope_binding"]["fixed_product_id"]
    reidentify(report)
    for compiled in (False, True):
        shape = evidence._compiled_validators() if compiled else evidence._validators()
        with pytest.raises((ValueError, ValidationError)):
            shape["switching-evidence-v1.json"].validate(report)
            evidence._validate_evidence_semantics(report)
    with pytest.raises((ValueError, ValidationError)):
        native_stream(report, monkeypatch)
    assert browser(report) == browser(report, stream=True) == "rejected"


def test_comparison_uses_only_the_three_owned_affected_scopes():
    report = projected()
    full = switching_comparison.build_report(
        report,
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-09",
    )
    row = next(row for row in full["rows"] if row["vendor"] == "aruba")
    assert row["counts"]["remediation_events"] == 1
    assert row["events"][0]["claim_ids"] == sorted(
        c["claim_id"] for c in report["claims"] if c["product_id"] in {p[0] for p in PAIRS}
    )


@pytest.mark.parametrize("mutation", ["parent", "cve", "fixed_version", "fixed_status", "url"])
def test_typed_csaf_does_not_join_other_source_sections(mutation):
    data = authored_csaf()
    url = URL
    if mutation == "parent":
        data["product_tree"]["branches"][0]["branches"][0]["name"] = "Other product"
    elif mutation == "cve":
        data["vulnerabilities"][0]["cve"] = "CVE-2024-99999"
    elif mutation == "fixed_version":
        data["product_tree"]["branches"][0]["branches"][0]["branches"][0]["name"] = "10.14.9999"
    elif mutation == "fixed_status":
        data["vulnerabilities"][0]["product_status"]["fixed"].remove(IDS[0])
    else:
        url += "?other"
    result = extracted(data, url=url)
    linked = {
        c["product_id"]
        for c in result["claims"]
        if any(r.get("scope_binding") for r in c["remediations"])
    }
    assert PAIRS[0][0] not in linked
    if mutation in {"parent", "cve", "url"}:
        assert not linked


def test_arista_reviewed_case_cannot_adopt_the_new_aruba_binding(monkeypatch):
    from test_switching_evidence import reviewed_section_report

    report = reviewed_section_report(monkeypatch)
    assert browser(report) == browser(report, stream=True) == "accepted"
    for claim in report["claims"]:
        if claim["status"] == "fixed":
            claim["product"] = "AOS-CX"
        else:
            for rem in claim["remediations"]:
                rem["scope_binding"]["fixed_product"] = "AOS-CX"
                rem["scope_binding"]["fixed_product_id"] = IDS[0]
    reidentify(report)
    with pytest.raises(ValueError):
        evidence.validate_evidence(report)
    assert browser(report) == browser(report, stream=True) == "rejected"
