"""Source-scope, contextual benchmark and non-inferential case-file boundaries."""

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import ValidationError

from infrastructure_impact.adapters.common import assessment, base
from infrastructure_impact.application.casefiles import casefiles, select_casefiles
from infrastructure_impact.application.evaluation import evaluate
from infrastructure_impact.application.source_audit import source_audit
from infrastructure_impact.collection.config import validate_config
from infrastructure_impact.collection.discovery import discovery, inventory
from infrastructure_impact.settings import PACKAGE
from infrastructure_impact.storage.repository import connect, evidence

URL = "https://csaf.arubanetworking.hpe.com/index.txt"
CID = "CVE-2024-6387"


def test_atom_inventory_keeps_next_pages_outside_the_selected_document_sample():
    raw = b'<feed xmlns="http://www.w3.org/2005/Atom"><link rel="next" href="page2"/><entry><link rel="self" href="entry.json"/><link rel="alternate" href="advisory"/></entry><entry><title>No link</title></entry></feed>'
    result = inventory(raw, URL, "rss")
    assert result["entry_count"] == 2
    assert result["entries_without_links"] == 1
    assert result["next_pages"] == ["https://csaf.arubanetworking.hpe.com/page2"]
    assert discovery(raw, URL, "rss", 4) == ["https://csaf.arubanetworking.hpe.com/advisory"]


def test_index_audit_distinguishes_bytes_from_extracted_product_claims():
    config = {"vendors": [dict(vendor="aruba", url=URL, kind="index", limit=4)]}
    with connect(":memory:") as db:
        raw = b"one.json\ntwo.json\nthree.json\n"
        ev = evidence(db, raw, URL)
        db.execute("INSERT INTO http_cache VALUES(?,?,?,?)", (URL, None, None, ev["id"]))
        evidence(
            db,
            b"raw retained but not necessarily parsed",
            "https://csaf.arubanetworking.hpe.com/one.json",
        )
        audit = source_audit(db, [], config)
        feed = next(v for v in audit["vendors"] if v["vendor"] == "aruba")["feeds"][0]
        assert feed["entry_count"] == feed["unique_links"] == 3
        assert feed["raw_documents_retained"] == 1
        assert feed["product_advisories_current"] == 0
        assert feed["pagination_followed"] is False
        assert feed["archive_enumerated"] is False


def test_malformed_or_html_feed_is_an_audit_gap_not_an_empty_archive():
    config = {"vendors": [dict(vendor="aruba", url=URL, kind="rss")]}
    with connect(":memory:") as db:
        ev = evidence(db, b"<html><title>Not a feed</title></html>", URL)
        db.execute("INSERT INTO http_cache VALUES(?,?,?,?)", (URL, None, None, ev["id"]))
        audit = source_audit(db, [], config)
        feed = next(v for v in audit["vendors"] if v["vendor"] == "aruba")["feeds"][0]
        assert feed["evidence_state"] == "unusable_retained_response"
        with pytest.raises(ValueError, match="no JSON"):
            inventory(b"<html>Application shell</html>", URL, "index")
        with pytest.raises(ValueError):
            validate_config(
                {"vendors": [dict(vendor="aruba", url=URL, kind="index", order="guess")]}
            )


def test_context_boundary_does_not_mix_affected_and_fixed_release_branches():
    case = dict(
        id="boundary",
        vendor="aruba",
        source_url=URL,
        cve_id=CID,
        product_pattern="^AOS-CX$",
        claim_context=[["product_version", "10.13.1031"]],
        expected_status="fixed",
        forbidden_statuses=["affected"],
    )
    fixed = assessment(CID, "AOS-CX", "fixed", "synthetic")
    fixed["product_context"] = [["product_version", "10.13.1031"]]
    affected = assessment(CID, "AOS-CX", "affected", "synthetic")
    affected["product_context"] = [["product_version_range", "10.13.1030 and below"]]
    record = dict(vendor="aruba", source_url=URL, sha256="a" * 64, assessments=[fixed, affected])
    definition = dict(cases=[case], limitations=[])
    assert evaluate([record], definition=definition)["passed"] == 1
    fixed["status"] = "affected"
    assert evaluate([record], definition=definition)["cases"][0]["outcome"] == "forbidden_claim"


def case_data():
    url = "https://docs.fortinet.com/document/fortiproxy/7.2.8/release-notes/534553/resolved-issues"
    r = base("fortinet", url, "SYNTHETIC-CASE", "Example fix")
    r.update(
        cves=["CVE-2023-38545", "CVE-2023-38546"],
        document_status="final",
        sha256="b" * 64,
        evidence_id=1,
        source_observed_at="2026-10-26T00:00:00Z",
        notes=[{"text": "PRIVATE_CASE_NOTE"}],
    )
    r["assessments"] = [
        assessment(r["cves"][0], "FortiProxy 7.2.8", "fixed", "synthetic"),
        assessment(r["cves"][1], "FortiProxy 7.2.8", "unknown", "synthetic"),
    ]
    return dict(records=[r], health=[], timeline={"events": []})


def test_casefiles_keep_unsupported_chronology_separate_from_exposure():
    result = casefiles(case_data())
    case = next(c for c in result["cases"] if c["vendor"] == "fortinet")
    assert case["exposure"]["publisher_statement_retained"]
    assert not case["independent_release_availability_verified"]
    assert not case["earliest_disclosure_established"]
    assert case["finding"] == "no_concealment_finding"
    assert "PRIVATE_CASE_NOTE" not in json.dumps(result)
    selected = select_casefiles(result, ["CVE-2023-38545"])["cases"][0]
    assert selected["exposure"]["observed_statuses"] == ["fixed"]
    assert selected["selected_cve_ids"] == ["CVE-2023-38545"]
    assert selected["exposure"]["prior_affectedness_inferred"] is False
    definition = json.loads((PACKAGE / "resources/disclosure-cases.json").read_text())
    definition["cases"][0]["finding"] = "concealment"
    with pytest.raises(ValidationError):
        casefiles(case_data(), definition)


@pytest.mark.skipif(
    shutil.which("node") is None, reason="Node required for case-file selection parity"
)
def test_browser_casefile_selection_matches_python_with_mixed_cve_states():
    data = case_data()
    data.update(
        casefiles=casefiles(data),
        all_cves=["CVE-2023-38545", "CVE-2023-38546"],
        vendors={"fortinet": "Fortinet"},
        coverage=[],
        comparison={},
        delays=[],
    )
    ids = ["CVE-2023-38545"]
    script = "const fs=require('fs'),vm=require('vm');const c={window:{},Set,URL,Response,Blob};vm.createContext(c);vm.runInContext(fs.readFileSync('infrastructure_impact/web/research-dossiers.js','utf8'),c);vm.runInContext(fs.readFileSync('infrastructure_impact/web/snapshot.js','utf8'),c);const x=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(c.selectSnapshot(x.data,x.ids).casefiles));"
    result = subprocess.run(
        ["node", "-e", script],
        input=json.dumps(dict(data=data, ids=ids)),
        text=True,
        capture_output=True,
        check=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    assert json.loads(result.stdout) == select_casefiles(copy.deepcopy(data["casefiles"]), ids)


def test_casefiles_and_source_audit_survive_publication_and_api_filters(tmp_path):
    from infrastructure_impact.application.publication import publish
    from infrastructure_impact.application.query import state
    from infrastructure_impact.http import Application
    from infrastructure_impact.storage.repository import ingest

    record = case_data()["records"][0]
    for key in ("sha256", "evidence_id", "source_observed_at"):
        record.pop(key)
    with connect(":memory:") as db:
        ingest(db, b"synthetic-publication", record["source_url"], lambda *_: record, "fortinet")
        data = state(db)
    data["casefiles"]["cases"][0]["private_note"] = "PRIVATE_CASE_OVERRIDE"
    generation = publish(data, root=tmp_path)
    assert "PRIVATE_CASE_OVERRIDE" not in (generation / "snapshot.json").read_text()
    app = Application(tmp_path)
    status, _, body = app.route(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/v1/casefiles",
            "QUERY_STRING": "cves=CVE-2023-38545&vendor=fortinet",
        }
    )
    assert status == 200
    result = json.loads(body)
    assert len(result["cases"]) == 1
    assert result["cases"][0]["exposure"]["observed_statuses"] == ["fixed"]
    for endpoint in ("/api/v1/source-audit", "/source-audit.json", "/casefiles.json"):
        assert app.route({"REQUEST_METHOD": "GET", "PATH_INFO": endpoint})[0] == 200
