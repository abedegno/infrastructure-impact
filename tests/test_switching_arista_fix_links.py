"""Authored HTML excerpts test finite reviewed section ownership, never raw captures."""

import copy
import json
import subprocess

import pytest
from jsonschema import ValidationError
from test_switching_aruba_fix_links import native_stream, reidentify

from infrastructure_impact.adapters.switching import extract
from infrastructure_impact.application import kev, switching_comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.plugins.arista import parse
from infrastructure_impact.settings import PACKAGE

PREFIX = "https://www.arista.com/en/support/advisories-notices/security-advisory/"
AT = "2026-11-09T12:00:00Z"
CASES = [
    ("23115-security-advisory-0128", "0128", "CVE-2025-8872"),
    ("24847-security-advisory-0201", "0201", "CVE-2026-111943"),
    ("15438-security-advisory-0075", "0075", "CVE-2022-0778"),
]
VERSIONS = {
    "0128": [
        "4.34.2F and later releases in the 4.34.x train",
        "4.33.5M and later releases in the 4.33.x train",
        "4.32.8M and later releases in the 4.32.x train",
        "4.31.9M and later releases in the 4.31.x train",
    ],
    "0201": [
        "4.37.0F and later releases in the 4.37.x train",
        "4.36.3.2M and later releases in the 4.36.x train",
        "4.35.7.2M and later releases in the 4.35.x train",
        "4.34.9.2M and later releases in the 4.34.x train",
        "4.33.11.2M and later releases in the 4.33.x train",
    ],
    "0075": [
        "4.27.4 and later releases in the 4.27.x train",
        "4.26.6 and later releases in the 4.26.x train",
        "4.25.9 and later releases in the 4.25.x train",
        "4.24.10 and later release in the 4.24.x train",
        "4.23.12 and later release in the 4.23.x train",
    ],
}
RECOMMENDED = "The recommended resolution is to upgrade to a remediated software version at your earliest convenience."
LATEST = "Arista recommends customers move to the latest version of each release that contains all the fixes listed below."
HOTFIX = """Hotfix For an immediate remediation until EOS can be upgraded, the following hotfixes are available. The hotfix can be installed as an EOS extension and is applicable across all affected EOS versions. The SWIX installation is hitless with SuperServer and Aaa agents being restarted. The existing session should not get interrupted but it's suggested to re-login after the hotfix installation. Release versions: 4.24.0 and later affected releases Hotfix SWIX URL: SecurityAdvisory0075Hotfix.swix Hotfix SWIX hash: (SHA-512)9fc1a8257e1a1c74e34af51ae2e0b270c0ab5d0fc391239a5b7f4d2d6bcd097010343cd447834105aca68c4fb273002a1cc9a1a3e0e3dc5ef63858abd2575474 Release versions: 4.23.0-4.23.11 Hotfix SWIX URL: SecurityAdvisory0075Hotfix_4.23.swix Hotfix SWIX hash: (SHA-512)4c6adb4f1323185f137dc3327cb4cb5e56d36bbeedf4667eccdcb8c842c7957ef979bcdc12c05e8eeefec2c39c55527a02194feb453dd01cf9a78b4fe9ddbfc6 For instructions on installation and verification of the hotfix patch, refer to the “ managing eos extensions ” section in the EOS User Manual. Ensure that the patch is made persistent across reboots by running the command “ copy installed-extensions boot-extensions ”."""


def listing(versions):
    return "<ul>" + "".join("<li>" + v + "</li>" for v in versions) + "</ul>"


def authored(case):
    slug, number, cid = case
    title = f"<h2>Security Advisory {number}<span>PDF</span></h2>"
    metadata = f"<p>The CVE-ID tracking this issue: {cid}</p>"
    if number == "0075":
        metadata = f"<h4>{cid}</h4>"
        affected = f"<h3>Vulnerability Assessment</h3><h4>The following products are affected by {cid}:</h4><ul><li>Arista EOS-based products{listing(['4.27.3 and below releases in the 4.27.x train'])}</li><li>Arista 7130 Systems running MOS{listing(['MOS-0.36.2'])}</li></ul><h4>The following products are NOT affected by {cid}:</h4>{listing(['Wireless Access Points'])}<h3>Mitigation</h3><p>Use ACLs.</p>"
        resolution = f"<h3>Resolution</h3><p>{RECOMMENDED}</p><h4>Arista EOS-based products</h4><p>This vulnerability has been fixed in the following EOS version:</p>{listing(VERSIONS[number])}<p>{HOTFIX}</p><h4>Arista 7130 Systems running MOS</h4><p>This vulnerability has been fixed in the following MOS version:</p>{listing(['MOS-0.36.3 and later MOS releases'])}<h3>References</h3>"
    else:
        agent = (
            "<div>Streaming Telemetry Agent (TerminAttr) Versions:</div>"
            + listing(["v1.46.2 and below releases in the v1.46 train"])
            if number == "0201"
            else ""
        )
        affected = (
            "<h2>Vulnerability Assessment</h2><h3>Affected Software</h3><div>EOS Versions</div>"
            + listing(["4.34.1F and below releases in the 4.34.x train"])
            + agent
            + "<h3>Affected Platforms</h3>"
            + listing(["720XP/722XPM Series", "750X Series"])
        )
        if number == "0128":
            resolution = f"<h2>Resolution</h2><p>{RECOMMENDED}</p><p>{LATEST}</p><p>For more information about upgrading see: EOS User Manual: Upgrades and Downgrades</p><div>{cid} has been fixed in the following releases:</div>{listing(VERSIONS[number])}<h3>For More Information</h3>"
        else:
            resolution = f"<h2>Resolution</h2><p>{RECOMMENDED} {LATEST}</p><p>The issue is fixed in the following product releases:</p><h3>EOS</h3>{listing(VERSIONS[number])}<h3>Streaming Telemetry Agent (TerminAttr)</h3>{listing(['TerminAttr v1.46.3, which supports EOS 4.30.0F through 4.36.3M'])}<p>An agent-only upgrade has limited scope.</p><h3>CloudVision Portal</h3><p>This section will be updated once fixed releases are available.</p><h2>References</h2>"
    return (
        "<!-- Authored structure with literal reviewed public clauses. -->"
        + title
        + metadata
        + affected
        + resolution
        + "<table><tr><th>Revision</th><th>Date</th><th>Changes</th></tr><tr><td>1.0</td><td>January 1, 2026</td><td>Initial</td></tr></table>"
    ).encode()


def extracted(case, raw=None):
    raw = raw if raw is not None else authored(case)
    url = PREFIX + case[0]
    return extract(raw, url, "arista", parse(raw, url, "arista"))


def projected(case):
    result = extracted(case)

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
        claim["revision"] = "reviewed-revision"
    result.pop("bundles")
    return evidence.project(result, publication=None, generated_at=AT)


def browser(report, stream=False):
    script = """
const fs=require('fs'),vm=require('vm');global.window=global;
for(const n of ['lossless-json','switching-contracts'])vm.runInThisContext(fs.readFileSync(process.argv[1]+'/'+n+'.js','utf8'));
const {report,study,stream,full}=JSON.parse(fs.readFileSync(0,'utf8'));
try{const c=InfrastructureSwitchingContracts;if(stream){const s=c.evidenceStream(report,study);for(const x of report.claims)s.add(x);s.finish();}else c.full(full);console.log('accepted');}catch(e){console.log('rejected');}
"""
    full = switching_comparison.build_report(
        projected(CASES[0]),
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-09",
    )
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


@pytest.mark.parametrize("case", CASES)
def test_owned_literal_eos_fixes_pass_all_four_boundaries(case, monkeypatch):
    report = projected(case)
    affected = next(
        c for c in report["claims"] if c["family"] == "arista-eos" and c["status"] == "affected"
    )
    fixed = next(c for c in report["claims"] if c["status"] == "fixed")
    assert fixed["version_expressions"] == VERSIONS[case[1]]
    assert fixed["product"] == "Arista EOS"
    assert fixed["product_id"] is None
    assert len(affected["remediations"]) == len(fixed["remediations"]) == 1
    rem = affected["remediations"][0]
    assert rem["version_expressions"] == VERSIONS[case[1]]
    assert rem["availability"] == "vendor_reports_fixed"
    assert rem["availability_date"] is None
    assert rem["product_ids"] == []
    assert rem["scope_binding"]["fixed_source"] == fixed["source"]
    assert "fixed_product_id" not in rem["scope_binding"]
    assert all(c["product_id"] is None and not c["platform_bindings"] for c in report["claims"])
    assert all(not c["remediations"] for c in report["claims"] if c["family"] is None)
    evidence.validate_evidence(report)
    assert native_stream(report, monkeypatch) == report["claims"]
    assert browser(report) == browser(report, True) == "accepted"


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize(
    "change",
    [
        "negated",
        "planned",
        "qualifier",
        "foreign",
        "duplicate",
        "multi_cve",
        "metadata",
        "missing_list",
    ],
)
def test_changed_resolution_or_identity_fails_visibly(case, change):
    raw = authored(case)
    needle = VERSIONS[case[1]][0].encode()
    if change == "negated":
        raw = raw.replace(b"has been fixed", b"has not been fixed").replace(
            b"The issue is fixed", b"The issue is not fixed"
        )
    elif change == "planned":
        raw = raw.replace(b"has been fixed", b"will be fixed").replace(
            b"The issue is fixed", b"The issue will be fixed"
        )
    elif change == "qualifier":
        raw = raw.replace(needle, needle + b" except some configurations")
    elif change == "foreign":
        raw = raw.replace(needle, b"TerminAttr " + needle)
    elif change == "duplicate":
        raw = raw.replace(
            listing(VERSIONS[case[1]]).encode(), (listing(VERSIONS[case[1]]) * 2).encode()
        )
    elif change == "multi_cve":
        raw = raw.replace(case[2].encode(), (case[2] + " CVE-2026-99999").encode())
    elif change == "metadata":
        raw = (
            raw.replace(b"The CVE-ID tracking this issue:", b"Background mentions:")
            if case[1] != "0075"
            else raw.replace(f"<h4>{case[2]}</h4>".encode(), b"<p>OpenSSL</p>")
        )
    elif change == "missing_list":
        raw = raw.replace(listing(VERSIONS[case[1]]).encode(), b"<p>Pending source review.</p>")
    with pytest.raises(ValueError):
        extracted(case, raw)


@pytest.mark.parametrize("case", CASES)
def test_wrapper_edits_do_not_depend_on_capture_digest(case):
    raw = b"<div class='new-site-wrapper'>" + authored(case) + b"</div>"
    assert any(c["status"] == "fixed" for c in extracted(case, raw)["claims"])


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "duplicate",
        "conflicting",
        "foreign",
        "cve",
        "revision",
        "locator",
        "versions",
        "date",
        "product_id",
    ],
)
def test_forged_or_ambiguous_sibling_rejected_everywhere(case, change, monkeypatch):
    report = projected(case)
    affected = next(
        c for c in report["claims"] if c["status"] == "affected" and c["family"] == "arista-eos"
    )
    fixed = next(c for c in report["claims"] if c["status"] == "fixed")
    rem = affected["remediations"][0]
    if change == "missing":
        report["claims"].remove(fixed)
    elif change in {"duplicate", "conflicting"}:
        sibling = copy.deepcopy(fixed)
        sibling["issues"].append("source_duplicate")
        if change == "conflicting":
            sibling["version_expressions"] = ["99.0"]
        report["claims"].append(sibling)
    elif change == "foreign":
        fixed["product"] = "TerminAttr"
    elif change == "cve":
        fixed["cve_id"] = "CVE-2026-99999"
    elif change == "revision":
        fixed["revision"] = "foreign"
    elif change == "locator":
        rem["source"]["source_locator"] += " / foreign"
    elif change == "versions":
        rem["version_expressions"] = ["99.0"]
    elif change == "date":
        rem["availability_date"] = fixed["remediations"][0]["availability_date"] = "2026-01-01"
    elif change == "product_id":
        rem["scope_binding"]["fixed_product_id"] = "invented"
    reidentify(report)
    with pytest.raises((ValueError, ValidationError)):
        evidence.validate_evidence(report)
    with pytest.raises((ValueError, ValidationError)):
        native_stream(report, monkeypatch)
    assert browser(report) == browser(report, True) == "rejected"


@pytest.mark.parametrize("slug", ["13425-security-advisory-0070", "16339-security-advisory-0081"])
def test_eos_unaffected_routes_do_not_acquire_fixes(slug):
    raw = (
        authored(CASES[2])
        .replace(b"Security Advisory 0075", ("Security Advisory " + slug[-4:]).encode())
        .replace(b"products are affected by", b"products are NOT affected by")
    )
    result = extract(raw, PREFIX + slug, "arista", parse(raw, PREFIX + slug, "arista"))
    assert not result["claims"]
    assert result["issues"]


def test_descending_0075_history_retains_actual_latest_row_locator():
    raw = authored(CASES[2]).replace(
        b"<tr><td>1.0</td>",
        b"<tr><td>1.2</td><td>March 1, 2026</td><td>Hotfix update</td></tr><tr><td>1.0</td>",
    )
    result = extracted(CASES[2], raw)
    assert result["claims"][0]["publisher"]["sequence"] == "1.2"
    assert result["claims"][0]["publisher"]["source"]["source_locator"].endswith("/tr[1]")
    assert result["claims"][0]["initial_published_at"] == "2026-01-01"
    assert result["claims"][0]["updated_at"] == "2026-03-01"


@pytest.mark.parametrize("case", CASES)
def test_merged_fixed_list_items_require_new_source_review(case):
    raw = authored(case).replace(
        listing(VERSIONS[case[1]]).encode(), listing([" ".join(VERSIONS[case[1]])]).encode()
    )
    with pytest.raises(ValueError):
        extracted(case, raw)


@pytest.mark.parametrize("case", CASES)
def test_jointly_forged_sibling_and_copied_versions_rejected(case, monkeypatch):
    report = projected(case)
    affected = next(
        c for c in report["claims"] if c["status"] == "affected" and c["family"] == "arista-eos"
    )
    fixed = next(c for c in report["claims"] if c["status"] == "fixed")
    affected["remediations"][0]["version_expressions"] = fixed["version_expressions"] = ["99.0"]
    reidentify(report)
    with pytest.raises(ValueError):
        evidence.validate_evidence(report)
    with pytest.raises(ValueError):
        native_stream(report, monkeypatch)
    assert browser(report) == browser(report, True) == "rejected"


def test_0128_shared_resolution_cannot_be_owned_by_global_eos_family_text():
    raw = authored(CASES[0]).replace(
        b"<h3>Affected Platforms</h3>",
        b"<div>Other Product Versions</div><ul><li>1.0</li></ul><h3>Affected Platforms</h3>",
    )
    with pytest.raises(ValueError):
        extracted(CASES[0], raw)


@pytest.mark.parametrize("case", CASES)
def test_reference_only_cve_text_is_not_advisory_identity_metadata(case):
    raw = authored(case)
    metadata = (
        f"<h4>{case[2]}</h4>"
        if case[1] == "0075"
        else f"<p>The CVE-ID tracking this issue: {case[2]}</p>"
    ).encode()
    raw = raw.replace(metadata, b"") + metadata
    with pytest.raises(ValueError):
        extracted(case, raw)
