"""Reduced publisher-shaped fixtures; actual capture validation is the offline replay."""

import copy
import json
from hashlib import sha256
from pathlib import Path

import pytest

from infrastructure_impact.adapters import arista_chronology as chronology
from infrastructure_impact.application import switching_evidence
from infrastructure_impact.domain import validate_advisory
from infrastructure_impact.plugins.arista import research_evidence
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.storage.repository import connect, ingest, latest

FIXTURES = Path(__file__).parent / "fixtures/arista-chronology"
AT = "2026-11-13T20:00:00Z"


def receipt(raw, url):
    return dict(url=url, sha256=sha256(raw).hexdigest(), retrieved_at=AT)


def inputs(n=165):
    urls = json.loads((FIXTURES / f"{n}-sources.json").read_text())
    html = (FIXTURES / f"{n}.html").read_bytes()
    raw = (FIXTURES / f"{n}.json").read_bytes()
    record = structured(raw, urls["csaf"], "arista")
    return record, dict(html_raw=html, html_source=receipt(html, urls["html"]), csaf_raw=raw)


@pytest.mark.parametrize(
    ("n", "expected"), [(165, "2026-09-09"), (183, "2026-09-22"), (188, "2026-10-06")]
)
def test_owned_html_initial_changes_only_date_and_adds_labeled_observations(n, expected):
    record, kw = inputs(n)
    before = copy.deepcopy(record)
    result = chronology.reconcile(record, **kw)
    assert result["status"] == "corrected"
    fixed = result["corrected_record"]
    assert fixed["published_at"] == expected
    assert fixed["updated_at"] == before["updated_at"]
    assert fixed["timeline"] == before["timeline"]
    assert record == before
    meta = fixed.pop("publisher_chronology")
    fixed["published_at"] = before["published_at"]
    assert fixed == before
    assert meta["original_published_at"] == before["published_at"]
    assert meta["original_updated_at"] == before["updated_at"]
    assert meta["html_source"]["sha256"] == sha256(kw["html_raw"]).hexdigest()
    assert {o["event"] for o in meta["observations"]} >= {
        "html_revision",
        "csaf_initial",
        "csaf_current",
        "csaf_revision",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_cve",
        "footer_link",
        "duplicate_initial",
        "partial_date",
        "conflicting_date",
        "wrong_receipt",
        "wrong_identity",
    ],
)
def test_ambiguous_or_unowned_pair_is_unchanged(mutation):
    record, kw = inputs()
    html = kw["html_raw"].decode()
    if mutation == "wrong_cve":
        html = html.replace("CVE-2026-73454", "CVE-2026-99999")
    if mutation == "footer_link":
        import re

        link = re.search(r'<a title="Download CSAF".*?</a>', html).group()
        html = html.replace(link, "") + "</div><footer>" + link + "</footer>"
    if mutation == "duplicate_initial":
        html = html.replace("<td>1.1</td>", "<td>1.0</td>")
    if mutation == "partial_date":
        html = html.replace("September 9, 2026", "September 2026")
    if mutation == "conflicting_date":
        html = html.replace("Date: September 9, 2026", "Date: September 10, 2026")
    if mutation == "wrong_identity":
        record["advisory_id"] = "Arista Networks Security Advisory 166"
    kw["html_raw"] = html.encode()
    kw["html_source"] = receipt(kw["html_raw"], kw["html_source"]["url"])
    if mutation == "wrong_receipt":
        kw["html_source"]["sha256"] = "0" * 64
    result = chronology.reconcile(record, **kw)
    assert result["status"] == "unchanged" and result["issues"]
    assert result["corrected_record"] == record


def test_real_ingest_retains_revision_and_study_dates_are_corrected_before_identity():
    record, kw = inputs()
    url = record["source_url"]
    raw = kw["csaf_raw"]
    fixed = chronology.reconcile(record, **kw)["corrected_record"]
    validate_advisory(fixed)
    db = connect(":memory:")
    ingest(db, raw, url, structured, "arista")
    old = latest(db)[0]
    assert ingest(db, raw, url, lambda *_: fixed, "arista")
    assert db.execute("select count(*) from revisions").fetchone()[0] == 2
    report = switching_evidence.project(
        switching_evidence.inputs(db, latest(db)), publication=None, generated_at=AT
    )
    assert report["claims"] and {c["initial_published_at"] for c in report["claims"]} == {
        "2026-09-09"
    }
    for c in report["claims"]:
        assert c["initial_date_provenance"]["html_source"]["retrieved_at"] == AT
        assert c["claim_id"] == switching_evidence.definition_sha256(
            {k: v for k, v in c.items() if k != "claim_id"}
        )
    assert old["published_at"] == record["published_at"]
    db.execute(
        "INSERT INTO evidence(source_url,sha256,observed_at,raw,media_type) VALUES(?,?,?,?,?)",
        (kw["html_source"]["url"], kw["html_source"]["sha256"], AT, kw["html_raw"], "text/html"),
    )
    db.commit()
    assert not ingest(db, raw, url, lambda *_: fixed, "arista")


def test_claim_copy_has_no_scope_or_fix_transfer_and_refuses_finalized_claims():
    record, kw = inputs()
    fixed = chronology.reconcile(record, **kw)["corrected_record"]
    original = research_evidence(kw["csaf_raw"], record["source_url"], "arista", record)
    repaired = research_evidence(kw["csaf_raw"], record["source_url"], "arista", fixed)
    for before, after in zip(original["claims"], repaired["claims"], strict=True):
        assert after.pop("initial_date_provenance") == fixed["publisher_chronology"]
        assert after.pop("initial_published_at") == "2026-09-09"
        expected = copy.deepcopy(before)
        expected.pop("initial_published_at")
        assert after == expected
    original["claims"][0]["claim_id"] = "accepted"
    with pytest.raises(ValueError, match="finalized"):
        chronology.apply_claim_chronology(original, fixed, kw["csaf_raw"])


@pytest.mark.parametrize("layout", ["tracked_paragraphs", "description_headings"])
def test_multiple_cves_require_complete_owned_intro_scope(layout):
    record, kw = inputs()
    data = json.loads(kw["csaf_raw"])
    data["vulnerabilities"].append({"cve": "CVE-2026-99999"})
    kw["csaf_raw"] = json.dumps(data).encode()
    record = structured(kw["csaf_raw"], record["source_url"], "arista")
    text = kw["html_raw"].decode()
    if layout == "tracked_paragraphs":
        text = text.replace(
            "</div></main>", "<p>The CVE-ID tracking this issue: CVE-2026-99999</p></div></main>"
        )
    else:
        import re

        text = re.sub(
            r"<p>The CVE-ID.*?</p>",
            "<h2>Description</h2><h4>CVE-2026-73454</h4><h4>CVE-2026-99999</h4><h2>Vulnerability Assessment</h2>",
            text,
            flags=re.S,
        )
    kw["html_raw"] = text.encode()
    kw["html_source"] = receipt(kw["html_raw"], kw["html_source"]["url"])
    result = chronology.reconcile(record, **kw)
    assert result["status"] == "corrected"
    assert result["chronology"]["cve_ids"] == ["CVE-2026-73454", "CVE-2026-99999"]


def test_replay_verifies_manifest_before_writing_and_exports_explicit_paths(tmp_path):
    from infrastructure_impact.application.arista_chronology_repair import replay

    record, kw = inputs()
    manifest = []
    for kind, raw, url in [
        ("html", kw["html_raw"], kw["html_source"]["url"]),
        ("csaf", kw["csaf_raw"], record["source_url"]),
    ]:
        path = tmp_path / kind
        path.write_bytes(raw)
        manifest.append(
            dict(
                number=165,
                kind=kind,
                path=str(path),
                url=url,
                status=200,
                bytes=len(raw),
                sha256=sha256(raw).hexdigest(),
                retrieved_at=AT,
            )
        )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    result = replay(path, database=tmp_path / "scratch.sqlite")
    assert result["rows"][0]["effective_initial"] == "2026-09-09"
    assert result["rows"][0]["claim_initials"] == ["2026-09-09"]
    assert result["rows"][0]["human_review"] == "pending"
    assert result["verified_captures"] == 2
    assert result["finalized_claim_count"] > 0
    assert result["rows"][0]["finalized_claim_initials"] == ["2026-09-09"]
    assert [s["retrieved_at"] for s in result["sources"]] == [AT, AT]
    from infrastructure_impact.application.replay import replay_report
    from infrastructure_impact.plugins.registry import default_registry

    dbpath = tmp_path / "scratch.sqlite"
    registry = default_registry()
    with connect(dbpath) as db:
        before = latest(db)[0]
        assert not ingest(db, kw["csaf_raw"], record["source_url"], registry.normalize, "arista")
        assert latest(db)[0]["publisher_chronology"] == before["publisher_chronology"]
    assert replay(path, database=dbpath, staging=True)["ingested_revisions"] == 0
    maintenance = replay_report(db_path=dbpath, vendor="arista", force=True)
    assert maintenance["unchanged"] == 1
    assert maintenance["reparsed_revisions"] == 0
    with connect(dbpath) as db:
        after = latest(db)[0]
        assert after["publisher_chronology"] == before["publisher_chronology"]
        assert after["source_observed_at"] == AT
        with pytest.raises(ValueError, match="chronology"):
            ingest(db, kw["csaf_raw"] + b" ", record["source_url"], registry.normalize, "arista")
        html = before["publisher_chronology"]["html_source"]
        db.execute("UPDATE evidence SET raw=? WHERE source_url=?", (b"missing proof", html["url"]))
        db.commit()
        with pytest.raises(ValueError, match="chronology"):
            ingest(db, kw["csaf_raw"], record["source_url"], registry.normalize, "arista")
    unresolved = replay_report(db_path=dbpath, vendor="arista", force=True)
    assert unresolved["failed"] == 1
    assert unresolved["failures"][0]["error_code"] == "chronology_unresolved_requires_review"
    manifest[0]["bytes"] += 1
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="receipt"):
        replay(path, database=tmp_path / "must-not-exist.sqlite")
    assert not (tmp_path / "must-not-exist.sqlite").exists()


@pytest.mark.parametrize(
    "change",
    ["private_path", "foreign_html", "wrong_primary", "wrong_cve", "wrong_day", "missing_event"],
)
def test_schema_and_semantics_reject_forged_chronology(change):
    record, kw = inputs()
    fixed = chronology.reconcile(record, **kw)["corrected_record"]
    meta = fixed["publisher_chronology"]
    if change == "private_path":
        meta["html_source"]["path"] = "/private/secret"
    if change == "foreign_html":
        meta["html_source"]["url"] = (
            "https://www.arista.com/en/support/advisories-notices/security-advisory/999-security-advisory-0166"
        )
    if change == "wrong_primary":
        meta["csaf_source"]["url"] = (
            "https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_166_CSAF.json"
        )
    if change == "wrong_cve":
        meta["cve_ids"] = ["CVE-2026-99999"]
    if change == "wrong_day":
        meta["effective_initial"] = "2026-09-10"
    if change == "missing_event":
        meta["observations"] = [o for o in meta["observations"] if o["event"] != "csaf_initial"]
    with pytest.raises(ValueError):
        validate_advisory(fixed)


def repaired_report():
    record, kw = inputs()
    fixed = chronology.reconcile(record, **kw)["corrected_record"]
    db = connect(":memory:")
    ingest(db, kw["csaf_raw"], record["source_url"], lambda *_: fixed, "arista")
    return switching_evidence.project(
        switching_evidence.inputs(db, latest(db)), publication=None, generated_at=AT
    )


def test_public_projection_copies_provenance_and_generation_guard_remains():
    raw = repaired_report()
    before = copy.deepcopy(raw)
    raw["claims"][0]["initial_date_provenance"]["html_source"]["private_path"] = "/private/secret"
    projected = switching_evidence.project(raw, publication=None, generated_at=AT)
    assert projected == before
    projected["claims"][0]["initial_date_provenance"]["html_source"]["sha256"] = "0" * 64
    assert raw["claims"][0]["initial_date_provenance"]["html_source"]["sha256"] != "0" * 64
    with pytest.raises(ValueError, match="generation|Generated|generated|publication"):
        switching_evidence.validate_evidence(
            before, publication=None, generated_at="2026-11-14T00:00:00Z"
        )


@pytest.mark.parametrize(
    "mutation", [None, "foreign_html", "wrong_cve", "wrong_day", "wrong_sha", "missing_event"]
)
def test_chronology_contracts_agree_in_python_compiled_and_browser(mutation):
    import subprocess

    from infrastructure_impact.application import kev, switching_comparison
    from infrastructure_impact.settings import PACKAGE

    report = repaired_report()
    c = report["claims"][0]
    m = c["initial_date_provenance"]
    if mutation == "foreign_html":
        m["html_source"]["url"] = m["html_source"]["url"].replace("0165", "0166")
    if mutation == "wrong_cve":
        m["cve_ids"] = ["CVE-2026-99999"]
    if mutation == "wrong_day":
        m["effective_initial"] = "2026-09-10"
    if mutation == "wrong_sha":
        m["csaf_source"]["sha256"] = "0" * 64
    if mutation == "missing_event":
        m["observations"] = [o for o in m["observations"] if o["event"] != "csaf_initial"]
    c["claim_id"] = switching_evidence.definition_sha256(
        {k: v for k, v in c.items() if k != "claim_id"}
    )
    # Both Python schema engines see identical optional fields; semantic checks
    # reject even a caller who recomputes the deterministic claim identifier.
    switching_evidence._validators()["switching-evidence-v1.json"].validate(report)
    switching_evidence._compiled_validators()["switching-evidence-v1.json"].validate(report)
    if mutation:
        with pytest.raises(ValueError):
            switching_evidence.validate_evidence(report)
    else:
        switching_evidence.validate_evidence(report)
    valid = repaired_report()
    full = switching_comparison.build_report(
        valid,
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=switching_evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-13",
    )
    full["inputs"]["evidence"] = report
    script = """
const fs=require('fs'),vm=require('vm');global.window=global;
vm.runInThisContext(fs.readFileSync(process.argv[1],'utf8'));
try { InfrastructureSwitchingContracts.full(JSON.parse(fs.readFileSync(0,'utf8'))); console.log('accepted'); }
catch(e) { console.log('rejected'); }
"""
    result = (
        subprocess.check_output(
            ["node", "-e", script, str(PACKAGE / "web/switching-contracts.js")],
            input=json.dumps(full).encode(),
        )
        .decode()
        .strip()
    )
    assert result == ("rejected" if mutation else "accepted")


def test_repair_refuses_materialized_revision_identity():
    record, kw = inputs()
    record["revision_id"] = 123
    record["evidence_id"] = 7
    result = chronology.reconcile(record, **kw)
    assert result["status"] == "unchanged"
    assert "materialized_revision_requires_fresh_normalization" in result["issues"]


def test_rss_is_its_own_event_and_csaf_conflict_does_not_relabel_updated():
    record, kw = inputs(188)
    data = json.loads(kw["csaf_raw"])
    data["document"]["tracking"]["revision_history"].append(
        dict(date="2026-10-13T01:02:03Z", number="2", summary="Separate revision")
    )
    kw["csaf_raw"] = json.dumps(data).encode()
    record = structured(kw["csaf_raw"], record["source_url"], "arista")
    rss = (
        "<rss><channel><item><link>"
        + kw["html_source"]["url"]
        + "</link><pubDate>Fri, 02 Oct 2026 15:29:01 +0000</pubDate></item></channel></rss>"
    ).encode()
    result = chronology.reconcile(
        record, **kw, rss_raw=rss, rss_source=receipt(rss, chronology.RSS_URL)
    )
    assert result["status"] == "corrected"
    assert "csaf_current_revision_conflict" in result["issues"]
    assert result["corrected_record"]["updated_at"] == "2026-10-05T20:27:47Z"
    event = next(o for o in result["chronology"]["observations"] if o["event"] == "rss_publication")
    assert event["value"] == "2026-10-02T15:29:01+00:00"
    assert result["corrected_record"]["published_at"] == "2026-10-06"


@pytest.mark.parametrize(
    "number,expected", [(165, "2026-09-09"), (183, "2026-09-22"), (188, "2026-10-06")]
)
def test_source_pinned_validation_rejects_incorrect_finalized_date(number, expected):
    from infrastructure_impact.application.arista_chronology_repair import validate_cases
    from infrastructure_impact.settings import PACKAGE

    cases = json.loads((PACKAGE / "resources/arista-chronology-validation.json").read_text())[
        "cases"
    ]
    case = next(c for c in cases if c["number"] == number)
    row = dict(
        number=number,
        source_hashes=case["source_hashes"],
        status="corrected",
        effective_initial=expected,
        csaf_initial=case["csaf_initial"],
        rss_publication=case["rss_publication"],
        claim_initials=[expected],
        finalized_claim_initials=[expected],
        claim_scope_and_fixes_unchanged=True,
    )
    result = next(c for c in validate_cases([row]) if c["number"] == number)
    assert result == dict(number=number, automated_validation="passed", human_review="pending")
    row.pop("finalized_claim_initials")
    assert (
        next(c for c in validate_cases([row]) if c["number"] == number)["automated_validation"]
        == "failed"
    )
    row["finalized_claim_initials"] = ["2026-01-01"]
    result = next(c for c in validate_cases([row]) if c["number"] == number)
    assert result == dict(number=number, automated_validation="failed", human_review="pending")


@pytest.mark.parametrize("change", ["identity", "cve", "url", "metadata", "missing_html"])
def test_retained_chronology_rejects_changed_binding_without_source_disclosure(change):
    from infrastructure_impact.adapters.arista_chronology import retained_chronology
    from infrastructure_impact.plugins.registry import default_registry

    record, kw = inputs()
    record = default_registry().normalize(kw["csaf_raw"], record["source_url"], "arista")
    fixed = chronology.reconcile(record, **kw)["corrected_record"]
    candidate = copy.deepcopy(record)
    if change == "identity":
        candidate["advisory_id"] += " changed"
    elif change == "cve":
        candidate["cves"] = ["CVE-2026-99999"]
    elif change == "url":
        candidate["source_url"] += "?changed"
    elif change == "metadata":
        fixed["publisher_chronology"]["effective_initial"] = "2026-01-01"

    def lookup(_receipt):
        if change == "missing_html":
            raise ValueError("/private/customer/raw bytes")
        return kw["html_raw"]

    with pytest.raises(ValueError, match="^chronology_unresolved_requires_review$"):
        retained_chronology(kw["csaf_raw"], candidate, fixed, lookup)


def test_staging_repair_requires_current_primary_ownership(tmp_path):
    from infrastructure_impact.application.arista_chronology_repair import replay
    from infrastructure_impact.plugins.registry import default_registry

    record, kw = inputs()
    manifest = []
    for kind, raw, url in [
        ("html", kw["html_raw"], kw["html_source"]["url"]),
        ("csaf", kw["csaf_raw"], record["source_url"]),
    ]:
        path = tmp_path / kind
        path.write_bytes(raw)
        manifest.append(
            dict(
                number=165,
                kind=kind,
                path=str(path),
                url=url,
                status=200,
                bytes=len(raw),
                sha256=sha256(raw).hexdigest(),
                retrieved_at=AT,
            )
        )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    dbpath = tmp_path / "staging.sqlite"
    with connect(dbpath) as db:
        ingest(
            db, kw["csaf_raw"] + b" ", record["source_url"], default_registry().normalize, "arista"
        )
        original = latest(db)[0]
    with pytest.raises(ValueError, match="ownership"):
        replay(path, database=dbpath, staging=True)
    with connect(dbpath) as db:
        assert latest(db)[0] == original
        assert db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
        ingest(db, kw["csaf_raw"], record["source_url"], default_registry().normalize, "arista")
        capture_time = latest(db)[0]["source_observed_at"]
    assert replay(path, database=dbpath, staging=True)["ingested_revisions"] == 1
    with connect(dbpath) as db:
        assert latest(db)[0]["source_observed_at"] == capture_time
        assert not ingest(
            db, kw["csaf_raw"], record["source_url"], default_registry().normalize, "arista"
        )
