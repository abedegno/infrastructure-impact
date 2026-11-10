"""Synthetic articles exercise literal reviewed clauses; cached byte replay is separate."""

import copy
import json

import pytest
from jsonschema import ValidationError
from test_switching_arista_fix_links import browser
from test_switching_aruba_fix_links import AT, native_stream, reidentify

from infrastructure_impact.adapters import switching
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.plugins.arista import parse
from infrastructure_impact.settings import PACKAGE

SAMPLES = json.loads((PACKAGE.parent / "tests/fixtures/reviewed-arista-authored.json").read_text())[
    "samples"
]
CASES = [(s, b) for s in SAMPLES for b in s["bindings"]]


def listing(values):
    return "<ul>" + "".join("<li>" + v + "</li>" for v in values) + "</ul>"


def authored(sample):
    software = ""
    for a in sample["assessments"]:
        if sample["advisory_id"].endswith("0099"):
            software += "<p>The following EOS versions are affected for " + a["cve_id"] + "</p>"
        software += "<div>EOS Versions</div>" + listing(a["versions"])
    return (
        '<div class="item-page"><div class="page-header"><h2>Security Advisory '
        + sample["advisory_id"].split("-")[-1]
        + "</h2></div><p>The CVE-ID tracking this issue: "
        + ", ".join(sample["expected_cves"])
        + "</p><h2>Description</h2><p>Authored scope fixture.</p><h3>Affected Software</h3>"
        + software
        + "<h3>Affected Platforms</h3><p>Publisher platform qualification.</p>"
        + "<h3>Required Configuration for Exploitation</h3><p>Publisher configuration qualification.</p>"
        + sample["resolution_html"]
        + "<h3>For More Information</h3><p>Support.</p>"
        + "<table><tr><th>Revision</th><th>Date</th><th>Changes</th></tr>"
        + "<tr><td>1.0</td><td>January 1, 2026</td><td>Initial</td></tr></table></div>"
    ).encode()


def extracted(sample, raw=None):
    raw = authored(sample) if raw is None else raw
    return switching.extract(
        raw, sample["source_url"], "arista", parse(raw, sample["source_url"], "arista")
    )


def projected(sample):
    result = extracted(sample)

    def stamp(v):
        if isinstance(v, dict):
            if "retrieved_at" in v:
                v["retrieved_at"] = AT
            for c in v.values():
                stamp(c)
        elif isinstance(v, list):
            for c in v:
                stamp(c)

    stamp(result)
    for c in result["claims"]:
        c["revision"] = "authored-revision"
    result.pop("bundles")
    return evidence.project(result, publication=None, generated_at=AT)


@pytest.mark.parametrize("sample,binding", CASES, ids=[b["cve_id"] for _, b in CASES])
def test_cve_owned_literal_fixed_list_passes_all_boundaries(sample, binding, monkeypatch):
    report = projected(sample)
    affected = next(
        c
        for c in report["claims"]
        if c["cve_id"] == binding["cve_id"] and c["status"] == "affected"
    )
    fixed = next(
        c for c in report["claims"] if c["cve_id"] == binding["cve_id"] and c["status"] == "fixed"
    )
    assert fixed["version_expressions"] == binding["fixed_versions"]
    assert fixed["product_id"] is None and fixed["platform_bindings"] == []
    assert len(fixed["remediations"]) == len(affected["remediations"]) == 1
    original, copied = fixed["remediations"][0], affected["remediations"][0]
    assert original["details"] == original["published_availability"] == binding["statement"]
    assert (
        original["version_expressions"]
        == copied["version_expressions"]
        == binding["fixed_versions"]
    )
    assert original["publisher_id"] is original["availability_date"] is None
    assert original["product_ids"] == copied["product_ids"] == []
    assert original["availability"] == "vendor_reports_fixed"
    assert "fixed_product_id" not in copied["scope_binding"]
    evidence.validate_evidence(report)
    evidence._compiled_validators()["switching-evidence-v1.json"].validate(report)
    evidence._validate_evidence_semantics(report)
    assert native_stream(report, monkeypatch) == report["claims"]
    assert browser(report) == browser(report, True) == "accepted"


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s["advisory_id"])
@pytest.mark.parametrize(
    "change",
    [
        "negated",
        "planned",
        "qualifier",
        "foreign",
        "duplicate_marker",
        "duplicate_list",
        "merged",
        "missing_list",
        "indirect_list",
        "foreign_marker",
        "resolution",
        "hotfix",
        "mos",
        "terminattr",
        "marker_tag",
        "marker_attributes",
        "list_attributes",
        "li_attributes",
        "nested_li",
        "hotfix_boundary",
    ],
)
def test_fix_only_drift_preserves_affected_evidence(sample, change):
    baseline = extracted(sample)
    b = sample["bindings"][0]
    marker = "<div>" + b["statement"] + "</div>"
    versions = listing(b["fixed_versions"])
    resolution = sample["resolution_html"]
    if change == "negated":
        resolution = resolution.replace("has been fixed", "has not been fixed")
    elif change == "planned":
        resolution = resolution.replace("has been fixed", "will be fixed")
    elif change in {"qualifier", "foreign", "mos", "terminattr"}:
        resolution = resolution.replace(
            b["fixed_versions"][0],
            {
                "qualifier": b["fixed_versions"][0] + " except some configurations",
                "foreign": "CloudVision " + b["fixed_versions"][0],
                "mos": "MOS " + b["fixed_versions"][0],
                "terminattr": "TerminAttr " + b["fixed_versions"][0],
            }[change],
        )
    elif change == "duplicate_marker":
        resolution = resolution.replace(marker, marker * 2)
    elif change == "duplicate_list":
        resolution = resolution.replace(versions, versions * 2)
    elif change == "merged":
        resolution = resolution.replace(versions, listing([" ".join(b["fixed_versions"])]))
    elif change == "missing_list":
        resolution = resolution.replace(versions, "")
    elif change == "indirect_list":
        resolution = resolution.replace(versions, "<div>" + versions + "</div>")
    elif change == "foreign_marker":
        resolution = resolution.replace(marker, marker.replace(b["cve_id"], "CVE-2026-99999"))
    elif change == "resolution":
        resolution += "<p>Only a partial fix.</p>"
    elif change == "hotfix":
        resolution += "<p>A different hotfix.</p>"
    elif change == "marker_tag":
        resolution = resolution.replace(marker, "<p>" + b["statement"] + "</p>")
    elif change == "marker_attributes":
        resolution = resolution.replace(marker, marker.replace("<div>", '<div hidden="">'))
    elif change == "list_attributes":
        resolution = resolution.replace(versions, versions.replace("<ul>", '<ul hidden="">'))
    elif change == "li_attributes":
        resolution = resolution.replace(versions, versions.replace("<li>", '<li hidden="">', 1))
    elif change == "nested_li":
        resolution = resolution.replace(
            versions, versions.replace("<li>", "<li><b>", 1).replace("</li>", "</b></li>", 1)
        )
    elif change == "hotfix_boundary":
        resolution = (
            resolution.replace("<h3>Hotfix</h3>", "<div>Hotfix</div>")
            if "<h3>Hotfix</h3>" in resolution
            else resolution.replace(versions, "<h3>Hotfix</h3>" + versions)
        )
    altered = authored(sample).replace(sample["resolution_html"].encode(), resolution.encode())
    result = extracted(sample, altered)
    assert not any(c["status"] == "fixed" for c in result["claims"])
    assert "reviewed_fix_source_drift" in result["issues"]

    def affected(value):
        value = copy.deepcopy(
            [dict(c, remediations=[]) for c in value["claims"] if c["status"] == "affected"]
        )
        for c in value:
            c["source"].pop("source_sha256", None)
            c["publisher"]["source"].pop("source_sha256", None)
        return value

    assert affected(result) == affected(baseline)


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s["advisory_id"])
@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "duplicate",
        "conflicting",
        "source",
        "cve",
        "revision",
        "publisher",
        "versions",
        "joint_versions",
        "joint_details",
        "joint_date",
        "joint_published",
        "product_ids",
        "binding_id",
    ],
)
def test_forged_links_fail_python_compiled_browser_and_native(sample, change, monkeypatch):
    report = projected(sample)
    c = next(c for c in report["claims"] if c["status"] == "affected")
    f = next(f for f in report["claims"] if f["status"] == "fixed" and f["cve_id"] == c["cve_id"])
    r, fr = c["remediations"][0], f["remediations"][0]
    if change == "missing":
        report["claims"].remove(f)
    elif change in {"duplicate", "conflicting"}:
        dupe = copy.deepcopy(f)
        dupe["conditions"].append("distinct sibling")
        if change == "conflicting":
            dupe["version_expressions"] = ["99.0"]
        report["claims"].append(dupe)
    elif change == "source":
        f["source"]["source_url"] += "/foreign"
    elif change == "cve":
        f["cve_id"] = "CVE-2026-99999"
    elif change == "revision":
        f["revision"] = "foreign"
    elif change == "publisher":
        f["publisher"]["sequence"] = "foreign"
    elif change == "versions":
        r["version_expressions"] = ["99.0"]
    elif change == "joint_versions":
        r["version_expressions"] = fr["version_expressions"] = f["version_expressions"] = ["99.0"]
    elif change == "joint_details":
        r["details"] = fr["details"] = "A fix is planned."
    elif change == "joint_date":
        r["availability_date"] = fr["availability_date"] = "2026-01-01"
    elif change == "joint_published":
        r["published_availability"] = fr["published_availability"] = "A fix is planned."
    elif change == "product_ids":
        fr["product_ids"] = ["invented"]
    elif change == "binding_id":
        r["scope_binding"]["fixed_product_id"] = "invented"
    reidentify(report)
    with pytest.raises((ValueError, ValidationError)):
        evidence.validate_evidence(report)
    with pytest.raises((ValueError, ValidationError)):
        evidence._compiled_validators()["switching-evidence-v1.json"].validate(report)
        evidence._validate_evidence_semantics(report)
    with pytest.raises((ValueError, ValidationError)):
        native_stream(report, monkeypatch)
    assert browser(report) == browser(report, True) == "rejected"


def test_0099_reversed_numeric_cve_order_and_swapped_source_drift():
    sample = next(s for s in SAMPLES if s["advisory_id"].endswith("0099"))
    html = sample["resolution_html"]
    assert html.index("CVE-2024-27892") < html.index("CVE-2024-27890")
    result = extracted(sample)
    assert {
        c["cve_id"]: c["version_expressions"][0] for c in result["claims"] if c["status"] == "fixed"
    } == {
        "CVE-2024-27890": "4.30.0M and onwards",
        "CVE-2024-27892": "4.31.3M and later releases in the 4.31.x train",
    }
    groups = [
        "<div>" + b["statement"] + "</div>" + listing(b["fixed_versions"])
        for b in sample["bindings"]
    ]
    swapped = (
        html.replace(groups[0], "PLACEHOLDER")
        .replace(groups[1], groups[0])
        .replace("PLACEHOLDER", groups[1])
    )
    changed = extracted(sample, authored(sample).replace(html.encode(), swapped.encode()))
    assert not any(c["status"] == "fixed" for c in changed["claims"])
    assert changed["issues"] == ["reviewed_fix_source_drift"]


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s["advisory_id"])
def test_wrapper_edits_preserve_owned_sections(sample):
    assert any(
        c["status"] == "fixed"
        for c in extracted(sample, b"<main>" + authored(sample) + b"</main>")["claims"]
    )


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s["advisory_id"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("source_url", "https://www.arista.com/foreign"),
        ("advisory_id", "foreign"),
        ("source_format", "Vendor HTML"),
        ("cves", ["CVE-2026-99999"]),
        ("vendor", "aruba"),
    ],
)
def test_fix_parser_rechecks_owned_source_identity(sample, field, value):
    from infrastructure_impact.adapters.common import HTML
    from infrastructure_impact.adapters.reviewed_fixes import arista_assessments

    raw = authored(sample)
    parsed = parse(raw, sample["source_url"], "arista")
    parsed[field] = value
    assert arista_assessments(HTML(raw).root, parsed, sample["advisory_id"]) == (
        [],
        ["reviewed_fix_source_drift"],
    )


def test_0140_truncated_affected_context_keeps_fix_unlinked():
    from infrastructure_impact.application import kev, switching_comparison

    sample = next(s for s in SAMPLES if s["advisory_id"].endswith("0140"))
    raw = authored(sample).replace(b"Publisher platform qualification.", b"x" * 4001)
    result = extracted(sample, raw)
    affected = next(c for c in result["claims"] if c["status"] == "affected")
    fixed = next(c for c in result["claims"] if c["status"] == "fixed")
    assert affected["issues"] == ["evidence_text_truncated"]
    assert affected["remediations"] == []
    assert fixed["version_expressions"] == sample["bindings"][0]["fixed_versions"]
    assert fixed["remediations"][0]["availability"] == "vendor_reports_fixed"
    assert result["issues"] == []
    # Publication identity is added downstream, preserving the affected guard.
    for c in result["claims"]:
        c["revision"] = "authored-revision"
        c["source"]["retrieved_at"] = AT
        c["publisher"]["source"]["retrieved_at"] = AT
        for r in c["remediations"]:
            r["source"]["retrieved_at"] = AT
    result.pop("bundles")
    report = evidence.project(result, publication=None, generated_at=AT)
    full = switching_comparison.build_report(
        report,
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    row = next(row for row in full["rows"] if row["vendor"] == "arista")
    assert row["counts"]["remediation_events"] == 0


def test_0140_unwrapped_resolution_qualification_is_not_discarded():
    sample = next(s for s in SAMPLES if s["advisory_id"].endswith("0140"))
    raw = authored(sample).replace(
        b"<h2>Resolution</h2>", b"<h2>Resolution</h2>Only a partial fix. "
    )
    result = extracted(sample, raw)
    assert [c["status"] for c in result["claims"]] == ["affected"]
    assert result["issues"] == ["reviewed_fix_source_drift"]
