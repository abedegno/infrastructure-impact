"""Project-authored examples of the reviewed Aruba signed-text structures."""

from hashlib import sha256

import pytest

from infrastructure_impact.adapters import cvss
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.plugins import default_registry
from infrastructure_impact.storage.repository import connect, ingest, latest

DIRECTORY = "https://csaf.arubanetworking.hpe.com/2021/"
URL = DIRECTORY + "hpe_aruba_networking_-_2021-013.txt"
CVES = [f"CVE-2021-9000{i}" for i in range(1, 5)]
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def section(name, text):
    return f"\n{name}\n{'=' * len(name)}\n{text}\n"


def signed_text(*, excluded=False):
    """Synthetic content; framing/section conventions follow reviewed captures."""
    header = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Aruba Product Security Advisory
===============================
Advisory ID: ARUBA-PSA-2021-013
CVE: CVE-2021-90001, CVE-2021-90002,
     CVE-2021-90003, CVE-2021-90004
Publication Date: 2021-July-13
Last Update: 2022-Jan-11
Status: Confirmed
Severity: High
Revision: 3
"""
    text = header + section("Title", "Synthetic switching vulnerabilities")
    text += section(
        "Overview",
        "Aruba has released updates for wired switch products running AOS-CX\n"
        "that address multiple security vulnerabilities.",
    )
    if excluded:
        text += section("Affected Products", "  -- Aruba IntroSpect: Versions 2.5.0.0 to 2.5.0.6")
        text += section(
            "Unaffected Products",
            "  -- ArubaOS-CX Switches\n  -- ArubaOS-S Switches\n\n"
            "Other Aruba products not listed above are also not known to be affected by\n"
            "the vulnerability.",
        )
        text += section(
            "Details",
            "The conclusion of the investigation is that the products listed above under\n"
            "the Unaffected Products section are not vulnerable to these vulnerabilities.",
        )
        text += section("Resolution", "Aruba IntroSpect: Version 2.5.0.7 and above")
    else:
        text += section(
            "Affected Products",
            "Aruba 8400/8360/8325/8320 switch series and Aruba 6400/6300/6200F switch\n"
            "series running the following version of the AOS-CX firmware:\n"
            "10.04.xxxx - versions prior to 10.04.3070\n"
            "10.05.xxxx - versions prior to 10.05.0070",
        )
        text += section(
            "Unaffected Products", "Any other Aruba products not listed above are not affected."
        )
        details = []
        for i, cid in enumerate(CVES):
            vector = VECTOR if i != 1 else VECTOR.replace("3.1", "3.0")
            details.append(
                f"  Synthetic flaw {i} ({cid})\n  {'-' * 65}\n"
                f"    Synthetic condition {i}.\n    Severity: High\n"
                f"    CVSSv3 Overall Score: 9.8\n    CVSS Vector: {vector}\n"
            )
        text += section("Details", "\n".join(details))
        text += section(
            "Resolution",
            "Upgrade AOS-CX devices to the following version based on your current version:\n"
            "10.05.xxxx - 10.05.0070 and above.\n\n"
            "Affected Aruba devices on version 10.04.xxxx will need to upgrade to 10.05.0070\n"
            "to address all of the vulnerabilities.",
        )
        text += section("Workaround", f"For {CVES[0]}, disable the synthetic feature.")
    text += section("Exploitation and Public Discussion", "Synthetic discussion.")
    text += section(
        "Revision History",
        "Revision 1 / 2021-July-13 / Initial release\nRevision 3 / 2022-Jan-11 / Synthetic update",
    )
    text += section("Aruba SIRT Security Procedures", "Synthetic reporting procedures.")
    return (
        text + "-----BEGIN PGP SIGNATURE-----\n\nSYNTHETIC\n-----END PGP SIGNATURE-----\n"
    ).encode()


def listing(*names):
    links = "".join(f'<a href="{n}">{n}</a> 01-Jan-2024 00:00 100\n' for n in names)
    return (
        "<html><head><title>Index of /2021/</title></head><body>"
        '<h1>Index of /2021/</h1><hr><pre><a href="../">../</a>\n'
        + links
        + "</pre><hr></body></html>"
    ).encode()


def normalize(raw):
    return default_registry().normalize(raw, URL, "aruba")


def test_aruba_historical_text_shared_scope_and_per_cve_metrics():
    raw = signed_text()
    doc = normalize(raw)
    assert doc["cves"] == CVES
    assert (doc["published_at"], doc["updated_at"]) == ("2021-07-13", "2022-01-11")
    assert len(doc["assessments"]) == 4
    assert {a["status"] for a in doc["assessments"]} == {"affected"}
    assert {a["cve_id"] for a in doc["assessments"]} == set(CVES)
    assert "6400/6300/6200F" in doc["assessments"][0]["product"]
    assert any("not listed above" in n["text"] for n in doc["notes"])
    scores = cvss.extract(raw, URL, "aruba", doc)
    assert len(scores["claims"]) == 4
    assert [s["version"] for s in scores["claims"]] == ["3.1", "3.0", "3.1", "3.1"]
    assert all(s["validation"] == "valid" and not s["product_ids"] for s in scores["claims"])
    assert all(s["cve_id"] in s["source"]["source_locator"] for s in scores["claims"])
    doc["metrics"] = [{"forged": True}]
    assert cvss.extract(raw, URL, "aruba", doc) == scores


def test_aruba_historical_text_retains_source_and_projects_study_claims():
    raw = signed_text()
    with connect(":memory:") as db:
        assert ingest(db, raw, URL, default_registry().normalize, "aruba")
        report = evidence.project(
            evidence.inputs(db, latest(db)), publication=None, generated_at="2026-11-05T12:00:00Z"
        )
        evidence.validate_evidence(report)
        claims = report["claims"]
        assert len(claims) == 4
        assert all(c["family"] == "aruba-aoscx" for c in claims)
        assert all(c["product_id"] is None and not c["platform_bindings"] for c in claims)
        assert all(c["scope_level"] == "os_family" for c in claims)
        assert all(c["source"]["source_sha256"] == sha256(raw).hexdigest() for c in claims)
        assert all(len(c["scores"]) == 1 for c in claims)
        assert all(c["remediations"][0]["availability_date"] is None for c in claims)
        assert all(
            c["remediations"][0]["source"]["source_locator"] == "text/Overview; text/Resolution"
            for c in claims
        )
        assert all(c["publisher"]["sequence"] == "3" for c in claims)
        assert (
            sum(any(r["category"] == "workaround" for r in c["remediations"]) for c in claims) == 1
        )
        assert db.execute("SELECT raw FROM evidence").fetchone()[0] == raw


def test_aruba_historical_text_unaffected_is_explicit_not_generic_other_products():
    raw = signed_text(excluded=True)
    doc = normalize(raw)
    result = default_registry().research_evidence(raw, URL, "aruba", doc)
    cx = [c for c in result["claims"] if c["family"] == "aruba-aoscx"]
    assert len(cx) == 4
    assert all(c["status"] == "unaffected" and c["product"] == "ArubaOS-CX Switches" for c in cx)
    assert all(not c["remediations"] for c in cx)
    assert not any("Other Aruba" in c["product"] for c in result["claims"])


@pytest.mark.parametrize(
    "before,after",
    [
        (b"Affected Products\n", b"Potentially Affected Products\n"),
        (b"to address all of the vulnerabilities.", b"to address one vulnerability."),
        (b"-----END PGP SIGNATURE-----", b""),
        (b"Synthetic flaw 1 (CVE-2021-90002)", b"Synthetic flaw 1 (CVE-2021-90001)"),
    ],
)
def test_aruba_historical_text_rejects_unknown_or_ambiguous_structure(before, after):
    with pytest.raises(ValueError):
        normalize(signed_text().replace(before, after))


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.invalid/2021/hpe_aruba_networking_-_2021-013.txt",
        DIRECTORY.replace("https://", "https://user@") + "hpe_aruba_networking_-_2021-013.txt",
        URL + "?x=1",
        URL + "#x",
        URL.replace("/2021/", "/2020/"),
    ],
)
def test_aruba_historical_text_rejects_other_routes(target):
    with pytest.raises(ValueError):
        default_registry().normalize(signed_text(), target, "aruba")


def test_aruba_historical_text_invalid_metric_remains_diagnosed():
    raw = signed_text().replace(b"CVSSv3 Overall Score: 9.8", b"CVSSv3 Overall Score: 12", 1)
    scores = cvss.extract(raw, URL, "aruba", normalize(raw))
    assert scores["claims"][0]["validation"] == "invalid"
    assert len(cvss.public_metrics(scores["claims"])) == 3
    assert scores["issues"]


def test_aruba_listing_duplicates_do_not_imply_vendor_totals():
    name = "hpe_aruba_networking_-_2021-013.txt"
    page = default_registry().get("aruba").parse_archive(listing(name, name), DIRECTORY, "aruba")
    assert page.urls == (URL,)
    assert page.entry_count == 2
    assert page.next_pages == ()


@pytest.mark.parametrize(
    "name",
    [
        "../hpe_aruba_networking_-_2021-013.txt",
        "%2e%2e/hpe_aruba_networking_-_2021-013.txt",
        "hpe_aruba_networking_-_2020-013.txt",
        URL,
        URL + "?x=1",
        URL + "#x",
        "https://evil.invalid/test.txt",
        "https://user@csaf.arubanetworking.hpe.com/2021/test.txt",
    ],
)
def test_aruba_listing_rejects_unreviewed_links(name):
    parser = default_registry().get("aruba").parse_archive
    assert callable(parser)
    with pytest.raises(ValueError):
        parser(listing(name), DIRECTORY, "aruba")


@pytest.mark.parametrize(
    "raw,url",
    [
        (listing("hpe_aruba_networking_-_2021-013.txt").replace(b"<pre>", b"<div>"), DIRECTORY),
        (listing("hpe_aruba_networking_-_2021-013.txt"), DIRECTORY.replace("2021", "2020")),
        (b"<h1>Index of /2021/</h1>", DIRECTORY),
    ],
)
def test_aruba_listing_changed_layout_is_unsupported(raw, url):
    parser = default_registry().get("aruba").parse_archive
    assert callable(parser)
    with pytest.raises(ValueError):
        parser(raw, url, "aruba")


@pytest.mark.parametrize(
    "change",
    [
        lambda raw: raw.replace(b"</pre>", b""),
        lambda raw: raw.replace(b"</pre>", b"hpe_aruba_networking_-_2021-019.txt</pre>"),
    ],
)
def test_aruba_listing_malformed_or_unlinked_rows_do_not_claim_exhaustion(change):
    raw = change(listing("hpe_aruba_networking_-_2021-013.txt"))
    with pytest.raises(ValueError):
        default_registry().get("aruba").parse_archive(raw, DIRECTORY, "aruba")


def test_aruba_historical_text_metrics_require_matching_major_version_and_complete_fields():
    raw = signed_text().replace(b"CVSSv3 Overall Score: 9.8", b"CVSSv2 Overall Score: 9.8", 1)
    result = cvss.extract(raw, URL, "aruba", normalize(raw))
    assert result["claims"][0]["validation"] == "invalid"
    raw = signed_text().replace(("    CVSS Vector: " + VECTOR + "\n").encode(), b"", 1)
    result = cvss.extract(raw, URL, "aruba", normalize(raw))
    assert result["claims"][0]["validation"] != "valid"
    assert len(result["claims"]) == 4


def test_aruba_historical_text_unknown_dates_and_source_identity_stay_unknown():
    raw = (
        signed_text()
        .replace(b"2021-July-13", b"date unknown")
        .replace(b"Last Update: 2022-Jan-11\n", b"")
    )
    doc = normalize(raw)
    assert doc["published_at"] is None and doc["updated_at"] is None
    doc["advisory_id"] = "FORGED"
    with pytest.raises(ValueError):
        default_registry().research_evidence(raw, URL, "aruba", doc)
    assert not cvss.extract(raw, URL, "aruba", doc)["claims"]


def test_aruba_historical_text_does_not_accept_negated_scope_sentence():
    raw = signed_text(excluded=True).replace(
        b"The conclusion of the investigation is that", b"It is not established that"
    )
    with pytest.raises(ValueError):
        normalize(raw)


@pytest.mark.parametrize(
    "statement,state",
    [
        ("The updates will be available in a future release.", "planned"),
        ("The fix is not available.", "unavailable"),
        ("This is a partial mitigation.", "partial_mitigation"),
    ],
)
def test_aruba_historical_text_remediation_qualifications_survive(statement, state):
    raw = signed_text().replace(
        b"10.05.xxxx - 10.05.0070 and above.",
        ("10.05.xxxx - 10.05.0070 and above.\n" + statement).encode(),
    )
    doc = normalize(raw)
    assert all(a["remediations"][0]["availability"] == state for a in doc["assessments"])


def test_aruba_historical_text_unknown_unaffected_wrapping_does_not_truncate_products():
    raw = signed_text(excluded=True).replace(
        b"  -- ArubaOS-CX Switches", b"  -- ArubaOS-CX Switches\n     with a synthetic qualifier"
    )
    with pytest.raises(ValueError):
        normalize(raw)
