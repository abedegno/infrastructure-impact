"""Original synthetic PDF text exercises F5's reviewed scope and failure boundary."""

from copy import deepcopy
from hashlib import sha256
from unittest.mock import patch

import pytest

from infrastructure_impact.adapters import f5_pdf
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.collection.service import run
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.source_policy import allowed
from infrastructure_impact.storage.repository import connect, latest

RAW = b"%PDF-SYNTHETIC-ONLY"
PHP = "K000163821"
SSH = "K000140222"


def synthetic(identity=PHP):
    profile = f5_pdf.PROFILES[identity]
    return (
        f"{identity}: {profile['title']}\n{f5_pdf.ARTICLE_PREFIX}{identity}\n"
        "Published Date: Jan 01, 2025 UTC Updated Date: Jan 02, 2025 UTC\n"
        "Evaluated products\nSynthetic evaluated version list\n"
        + f5_pdf.START
        + "\nSynthetic description with background CVE-2006-5051.\n"
        "Impact\nSynthetic authentication prerequisites.\n"
        "Security Advisory Status\nSynthetic reviewed table and lifecycle footnotes.\n"
        + f5_pdf.END
        + "\nSynthetic mitigation text; not an appliance fix.\n"
    )


def reviewed(text, identity=PHP):
    profiles = deepcopy(f5_pdf.PROFILES)
    before, critical = f5_pdf.reviewed_scope(text)
    profiles[identity]["scope_sha256"] = sha256(critical.encode()).hexdigest()
    evaluated = " ".join(before.split("Evaluated products", 1)[1].split())
    profiles[identity]["evaluated_sha256"] = sha256(evaluated.encode()).hexdigest()
    return patch.object(f5_pdf, "PROFILES", profiles)


def normalize(identity):
    text = synthetic(identity)
    with reviewed(text, identity), patch.object(f5_pdf, "pdf_text", return_value=text):
        return default_registry().normalize(RAW, f5_pdf.PDF_PREFIX + identity, "f5")


def test_php_keeps_shared_table_roles_branch_ranges_and_literal_fix_candidates():
    doc = normalize(PHP)
    assert len(doc["assessments"]) == 38
    assert doc["cves"] == ["CVE-2026-109618", "CVE-2026-109619"]
    assert all(a["scope"] == "bulletin_shared" for a in doc["assessments"])
    affected = [a for a in doc["assessments"] if a["status"] == "affected"]
    assert len(affected) == 8 and all(a["status"] != "fixed" for a in doc["assessments"])
    data_plane = [a for a in affected if a["product"] == "BIG-IP APM"]
    control_plane = [a for a in affected if a["product"] == "BIG-IP (all modules)"]
    assert all("remote unauthenticated" in a["exposure"][-1]["details"] for a in data_plane)
    assert all("remote authenticated" in a["exposure"][-1]["details"] for a in control_plane)
    branch = next(a for a in affected if a["product_id"].endswith(":17.x"))
    assert [v["expression"] for v in branch["versions"]] == ["17.5.0 - 17.5.1", "17.1.0 - 17.1.3"]
    fixes = branch["remediations"]
    assert len(fixes) == 4 and all(r["availability"] == "vendor_reports_fixed" for r in fixes)
    assert all("ENG4" not in r["details"] for r in fixes)
    assert any(r["details"].endswith("-ENG") for r in fixes)
    assert all(
        "publisher_lifecycle_limit" in {e["category"] for e in a["exposure"]} for a in affected
    )
    assert doc["published_at"] == "2025-01-01"
    assert "day precision" in " ".join(doc["warnings"])


def test_openssh_keeps_next_separate_and_does_not_expand_background_cve_scope():
    doc = normalize(SSH)
    assert doc["cves"] == ["CVE-2024-6387"]
    assert len(doc["assessments"]) == 13
    assert all(a["scope"] == "cve_specific" for a in doc["assessments"])
    assert (
        next(a for a in doc["assessments"] if a["product"] == "BIG-IP (all modules)")["status"]
        == "unaffected"
    )
    affected = [a for a in doc["assessments"] if a["status"] == "affected"]
    assert len(affected) == 5 and all(a["product"].startswith("BIG-IP Next") for a in affected)
    spk = next(a for a in affected if a["product"] == "BIG-IP Next SPK")
    assert spk["remediations"][0]["availability"] == "no_fix_planned"
    cnf = [a for a in affected if a["product"] == "BIG-IP Next CNF"]
    assert len(cnf) == 2 and len({a["product_id"] for a in cnf}) == 2
    assert all(a["remediations"][0]["availability"] == "unknown" for a in cnf)
    assert all("f5-debug-sidecar" in a["exposure"][-1]["details"] for a in cnf)


@pytest.mark.parametrize("identity", [PHP, SSH])
def test_unaffected_all_is_lifecycle_limited_and_services_do_not_acquire_versions(identity):
    doc = normalize(identity)
    for a in doc["assessments"]:
        if a["status"] != "unaffected":
            continue
        assert a["versions"] == [] and a["remediations"] == []
        assert "not an affected-products list" in a["exposure"][0]["details"]
        if a["product_id"].endswith(":service"):
            assert a["product_context"] == [["product_name", a["product"]]]
        else:
            assert "every historical release" in a["exposure"][1]["details"]


@pytest.mark.parametrize(
    "part",
    [
        "Synthetic evaluated version",
        "Synthetic authentication",
        "Synthetic reviewed table",
        "background CVE-2006-5051",
    ],
)
def test_changed_evaluated_impact_table_or_description_text_requires_review(part):
    original = synthetic()
    changed = original.replace(part, "Changed unreviewed scope")
    with reviewed(original), patch.object(f5_pdf, "pdf_text", return_value=changed):
        with pytest.raises(ValueError, match="scope changed"):
            f5_pdf.advisory(RAW, f5_pdf.PDF_PREFIX + PHP, "f5")


@pytest.mark.parametrize("part", [f5_pdf.START, f5_pdf.END, "Evaluated products"])
def test_duplicate_semantic_boundaries_fail_closed(part):
    text = synthetic()
    with reviewed(text), patch.object(f5_pdf, "pdf_text", return_value=text + part):
        with pytest.raises(ValueError):
            f5_pdf.advisory(RAW, f5_pdf.PDF_PREFIX + PHP, "f5")


def test_formatting_only_changes_do_not_reinterpret_scope():
    text = synthetic()
    with reviewed(text), patch.object(f5_pdf, "pdf_text", return_value=text.replace(" ", "  ")):
        doc = f5_pdf.advisory(RAW, f5_pdf.PDF_PREFIX + PHP, "f5")
    assert len(doc["assessments"]) == 38


@pytest.mark.parametrize("change", ["identity", "title", "date_order", "date_precision"])
def test_identity_and_date_claims_are_checked_separately(change):
    text = synthetic()
    replacement = {
        "identity": text.replace(PHP, SSH),
        "title": text.replace("PHP vulnerabilities", "Different vulnerabilities"),
        "date_order": text.replace("Jan 02, 2025", "Dec 31, 2024"),
        "date_precision": text.replace("Jan 02, 2025 UTC", "Jan 2025 UTC"),
    }[change]
    with reviewed(text), patch.object(f5_pdf, "pdf_text", return_value=replacement):
        with pytest.raises(ValueError):
            f5_pdf.advisory(RAW, f5_pdf.PDF_PREFIX + PHP, "f5")


@pytest.mark.parametrize("suffix", ["&other=1", "#table", "&article=" + PHP])
def test_unreviewed_route_parameters_are_rejected(suffix):
    url = f5_pdf.PDF_PREFIX + PHP + suffix
    assert not allowed(url, "f5")
    with pytest.raises(ValueError, match="route"):
        f5_pdf.advisory(RAW, url, "f5")


def test_source_policy_and_input_formats_do_not_follow_arbitrary_f5_content():
    assert allowed(f5_pdf.PDF_PREFIX + PHP, "f5")
    assert allowed(f5_pdf.ARTICLE_PREFIX + PHP, "f5")
    assert not allowed("https://support.apis.f5.com/articles/rss/v4/feed", "f5")
    assert not allowed(f5_pdf.PDF_PREFIX + "K999999999", "f5")
    assert not allowed((f5_pdf.PDF_PREFIX + PHP).replace("https:", "http:"), "f5")
    for raw in [b"<html>Application shell</html>", b"%PDF" + b"x" * 3_000_000]:
        with pytest.raises(ValueError, match="PDF within"):
            f5_pdf.advisory(raw, f5_pdf.PDF_PREFIX + PHP, "f5")
    with pytest.raises(ValueError, match="route"):
        f5_pdf.advisory(RAW, f5_pdf.PDF_PREFIX + PHP, "another")


def test_failed_scope_refresh_retains_previous_claims_and_public_projection(tmp_path, monkeypatch):
    url = f5_pdf.PDF_PREFIX + PHP
    config = dict(vendors=[], pinned=[dict(vendor="f5", url=url)])
    db_path = tmp_path / "vault.sqlite3"
    text = synthetic()
    monkeypatch.setattr(
        "infrastructure_impact.collection.service.resolve_document", lambda *_: (url, RAW)
    )
    with reviewed(text), patch.object(f5_pdf, "pdf_text", return_value=text):
        assert run(config, db_path=db_path) == (1, 0)
    monkeypatch.setattr(
        "infrastructure_impact.collection.service.resolve_document", lambda *_: (url, RAW + b"NEW")
    )
    with (
        reviewed(text),
        patch.object(
            f5_pdf,
            "pdf_text",
            return_value=text.replace("Synthetic reviewed table", "Changed table"),
        ),
    ):
        assert run(config, db_path=db_path) == (0, 1)
    with connect(db_path) as db:
        record = latest(db)[0]
        assert record["sha256"] == sha256(RAW).hexdigest()
        data = state(db, ["CVE-2026-109618"])
    generation = publish(data, tmp_path / "publications")
    exported = (generation / "snapshot.json").read_text()
    assert "Synthetic description with background" not in exported
    assert "Synthetic evaluated version list" not in exported


def test_pdf_resolution_does_not_interpret_embedded_bytes_as_html_links():
    from infrastructure_impact.collection.service import resolve_document

    url = f5_pdf.PDF_PREFIX + PHP
    raw = b'%PDF-SYNTHETIC <a href="https://attacker.example/csaf.json">not HTML</a>'
    calls = []

    def fetcher(db, target, vendor):
        calls.append((target, vendor))
        assert target == url
        return raw

    with connect(":memory:") as db:
        assert resolve_document(db, url, "f5", fetcher=fetcher) == (url, raw)
    assert calls == [(url, "f5")]


def test_changed_pdf_bytes_with_identical_claims_create_no_disclosure_signal():
    from infrastructure_impact.storage.repository import ingest

    text = synthetic()
    url = f5_pdf.PDF_PREFIX + PHP
    with connect(":memory:") as db:
        with reviewed(text), patch.object(f5_pdf, "pdf_text", return_value=text):
            for raw in (RAW, RAW + b"SYNTHETIC CHANGED PDF METADATA"):
                assert ingest(db, raw, url, default_registry().normalize, "f5")
        assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM changes").fetchone()[0] == 0


def test_date_only_publisher_claims_cannot_create_numeric_timing_offsets():
    from infrastructure_impact.application.comparison import advisory_delays
    from infrastructure_impact.application.eligibility import eligibility, timestamp

    doc = normalize(SSH)
    assert doc["published_at"] == "2025-01-01" and doc["updated_at"] == "2025-01-02"
    assert timestamp(doc["published_at"]) is None
    upstream = {
        cid: dict(published_at="2024-12-31T12:00:00+00:00", source_url="https://example.test/cve")
        for cid in doc["cves"]
    }
    assert advisory_delays([doc], upstream) == []
    doc["sha256"] = "a" * 64
    for reference in upstream.values():
        reference["sha256"] = "b" * 64
    report = eligibility(
        dict(
            generated_at="2025-06-01T12:00:00Z",
            vendors={"f5": "F5"},
            records=[doc],
            all_cves=doc["cves"],
            upstream=upstream,
        )
    )
    assert all(case["publication_observations"] == [] for case in report["vendors"][0]["cases"])
    assert all(
        "vendor_timestamp_not_precise" in case["timing_reasons"]
        for case in report["vendors"][0]["cases"]
    )
