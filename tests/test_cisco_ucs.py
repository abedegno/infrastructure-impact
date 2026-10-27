"""Synthetic PDF boundaries exercise reviewed UCS fixed-only assertions."""

from hashlib import sha256

import pytest

from infrastructure_impact.adapters import cisco_ucs as ucs
from infrastructure_impact.application.component_studies import cell
from infrastructure_impact.application.families import definition
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.storage.repository import connect, ingest, latest


def document():
    return (
        ucs.TITLE + " First Published: 2023-01-06 Last Modified: 2026-08-05 "
        "Synthetic whole-document reference CVE-2099-99999. "
        "Security Fixes in Release 4.2(3m) "
        "Defect ID - SYNTHETIC-INTEL M5-only synthetic issue CVE-2099-11111. "
        "Defect ID - CSCwk62266 "
        "Synthetic UCS server security statement CVE-2024-6387. "
        "Background regression CVE-2006-5051. "
        "Security Fixes in Release 4.2(3l) "
        "Defect ID - CSCwi59840 "
        "Synthetic IMC security statement CVE-2023-48795; upstream before 9.6. "
        + ucs.TITLE
        + " 26 \fSecurity Fixes in Release 4.2(3k) "
        "Synthetic continuation: algorithm constraints, no installed version. "
        "Security Fixes in Release 4.2(3k) "
        "Defect ID - CSCwj41082 Synthetic S3260-only sibling CVE-2024-20356."
    )


@pytest.fixture
def reviewed(monkeypatch):
    text = " ".join(document().split())
    profiles = []
    for profile in ucs.PROFILES:
        prefix, rest = text.split("Defect ID - " + profile["defect"])
        section_prefix = prefix.rsplit("Security Fixes in Release " + profile["release"], 1)[
            1
        ].strip()
        body = rest.split("Defect ID - " + profile["next_defect"])[0].strip()
        profiles.append(
            {
                **profile,
                "section_prefix_sha256": sha256(section_prefix.encode()).hexdigest(),
                "body_sha256": sha256(body.encode()).hexdigest(),
            }
        )
    # Synthetic text has its own reviewed hashes. Production source spans are
    # separately verified against retained official PDF bytes, never copied here.
    monkeypatch.setattr(ucs, "PROFILES", tuple(profiles))
    monkeypatch.setattr(ucs, "pdf_text", lambda raw, layout=False: document())
    return monkeypatch


def parse():
    return default_registry().normalize(b"%PDF-synthetic", ucs.URL, "cisco")


def test_explicit_release_rows_do_not_import_neighbouring_cves_or_versions(reviewed):
    record = parse()
    assert record["cves"] == ["CVE-2023-48795", "CVE-2024-6387"]
    assert record["published_at"] is None and record["updated_at"] is None
    claims = {c["cve_id"]: c for c in record["assessments"]}
    assert len(claims) == 2
    for cid, product, release in [
        ("CVE-2024-6387", "Cisco UCS servers", "4.2(3m)"),
        ("CVE-2023-48795", "Cisco IMC", "4.2(3l)"),
    ]:
        claim = claims[cid]
        assert claim["product"] == product and claim["status"] == "fixed"
        assert claim["scope"] == "cve_specific"
        assert claim["versions"] == [{"expression": release}]
        assert claim["remediations"][0]["availability"] == "vendor_reports_fixed"
        assert claim["exposure"][0]["category"] == "fixed_only_statement"
        assert "9.6" not in str(claim) and "M5" not in str(claim) and "S3260" not in str(claim)


@pytest.mark.parametrize(
    "old,new",
    [
        (ucs.TITLE, "Different release-note document"),
        ("Security Fixes in Release 4.2(3m)", "Security Fixes in Release 4.2(3n)"),
        ("Security Fixes in Release 4.2(3l)", "Security Fixes in Release 4.2(3p)"),
        ("CSCwk62266", "CHANGED-DEFECT"),
        ("CSCwi59840", "CHANGED-DEFECT"),
        ("CSCwj41082", "CHANGED-BOUNDARY"),
        ("CVE-2024-6387", "CVE-2099-12345"),
        ("CVE-2023-48795", "CVE-2099-12345"),
        ("Synthetic UCS server security statement", "Future UCS security statement will be fixed"),
        ("Synthetic IMC security statement", "Only M5 IMC hardware is covered"),
        ("Synthetic continuation: algorithm constraints", "Changed continuation: CVE-2099-54321"),
        ("Defect ID - CSCwk62266", "New group-wide M5-only restriction. Defect ID - CSCwk62266"),
        ("Background regression CVE-2006-5051.", "Now also affected: CVE-2006-5051."),
    ],
)
def test_source_or_scope_changes_fail_closed(reviewed, old, new):
    changed = document().replace(old, new)
    reviewed.setattr(ucs, "pdf_text", lambda raw, layout=False: changed)
    with pytest.raises(ValueError, match="Reviewed UCS"):
        parse()


def test_duplicate_defect_is_not_silently_selected(reviewed):
    changed = document() + " Defect ID - CSCwk62266 Duplicate reference."
    reviewed.setattr(ucs, "pdf_text", lambda raw, layout=False: changed)
    with pytest.raises(ValueError, match="ambiguous"):
        parse()


def test_cover_date_changes_cannot_create_a_cve_disclosure_timestamp(reviewed):
    changed = document().replace("2023-01-06", "2020-01-01").replace("2026-08-05", "2027-01-01")
    reviewed.setattr(ucs, "pdf_text", lambda raw, layout=False: changed)
    record = parse()
    assert record["published_at"] is None and record["updated_at"] is None
    assert all(c["status"] == "fixed" for c in record["assessments"])


@pytest.mark.parametrize("suffix", ["?view=other", "#unreviewed"])
def test_route_variants_require_review(reviewed, suffix):
    with pytest.raises(ValueError, match="URL parameters"):
        ucs.security_fixes(b"%PDF-synthetic", ucs.URL + suffix, "cisco")


def test_unrelated_pdf_is_not_claimed_and_wrong_vendor_or_body_is_rejected(reviewed):
    assert ucs.security_fixes(b"%PDF-synthetic", "https://www.cisco.com/other.pdf", "cisco") is None
    for raw, vendor in [(b"<html>error</html>", "cisco"), (b"%PDF-synthetic", "juniper")]:
        with pytest.raises(ValueError, match="Cisco PDF"):
            ucs.security_fixes(raw, ucs.URL, vendor)


def test_capture_is_idempotent_and_does_not_establish_asa_family_impact(reviewed):
    registry = default_registry()
    with connect(":memory:") as db:
        assert ingest(db, b"%PDF-synthetic", ucs.URL, registry.normalize, "cisco")
        assert not ingest(db, b"%PDF-synthetic", ucs.URL, registry.normalize, "cisco")
        record = latest(db)[0]
    family = next(f for f in definition()["families"] if f["vendor"] == "cisco")
    result = cell({"records": [record]}, family, "CVE-2024-6387")
    assert result["statements"] == 0 and not result["explicit_statuses"]
