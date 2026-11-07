"""Synthetic collection-to-publication KEV and installed adapter parity."""

import copy
import csv
import hashlib
import io
import json
import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from test_kev_collection import CONFIG, RAW, collect

from infrastructure_impact.adapters.common import assessment, base
from infrastructure_impact.application.kev import validate_report
from infrastructure_impact.application.publication import public_projection, publish, write_bundle
from infrastructure_impact.application.query import state
from infrastructure_impact.exports import FIELDS, csv_export, select
from infrastructure_impact.http import Application
from infrastructure_impact.settings import PACKAGE
from infrastructure_impact.storage.repository import connect, ingest

CID = "CVE-2024-6387"
OTHER = "CVE-2025-12345"
OUTSIDE = "CVE-2099-99999"


@pytest.fixture
def collected(tmp_path, monkeypatch, request):
    path = tmp_path / "synthetic.sqlite"
    assert collect(path, RAW) == (0, 0)
    monkeypatch.setattr("infrastructure_impact.collection.config.load_config", lambda: CONFIG)
    with connect(path) as db:
        record = base(
            "hpe",
            "https://support.hpe.com/synthetic/kev",
            "SYNTHETIC",
            "Synthetic",
            "2025-01-01T00:00:00Z",
        )
        record["cves"] = getattr(request, "param", [CID, OTHER])
        record["assessments"] = [
            assessment(cid, "Synthetic product", "affected", "Synthetic") for cid in record["cves"]
        ]
        ingest(db, b"synthetic advisory", record["source_url"], lambda *_: record, "hpe")
        return state(db)


def request(app, path, query=""):
    replies = []
    body = b"".join(
        app(
            dict(REQUEST_METHOD="GET", PATH_INFO=path, QUERY_STRING=query),
            lambda status, headers: replies.append(status),
        )
    )
    return int(replies[0].split()[0]), body


ADAPTER = r"""
const fs=require('fs'),vm=require('vm'),{webcrypto}=require('crypto');
const x=JSON.parse(fs.readFileSync(0,'utf8')),handlers={},blobs=[];
URL.createObjectURL=(blob)=>{blobs.push(blob);return 'blob:synthetic';};URL.revokeObjectURL=()=>{};
const original=async(input)=>{
 const u=new URL(typeof input==='string'?input:input.url,'https://example.test');
 const p=x.root+'/'+u.pathname.replace(/^\/site\//,'');
 try{return new Response(fs.readFileSync(p));}catch{return new Response('',{status:404});}
};
const c={window:{fetch:original},document:{baseURI:'https://example.test/site/',addEventListener:(name,callback)=>handlers[name]=callback,createElement:()=>({click(){}}),querySelector:()=>({textContent:''})},setTimeout:fn=>fn(),location:{origin:'https://example.test'},Set,Map,URL,Response,Blob,TextEncoder,TextDecoder,Uint8Array,crypto:webcrypto};
vm.createContext(c);
for(const f of ['lossless-json.js','switching-contracts.js','current-evidence.js','kev.js','research-dossiers.js','delivery.js','snapshot.js'])vm.runInContext(fs.readFileSync(x.web+'/'+f,'utf8'),c);
(async()=>{if(x.race){await Promise.all(x.queries.map(q=>c.window.fetch(q)));await handlers.click({target:{closest:()=>({id:'json-export'})},preventDefault(){}});process.stdout.write(JSON.stringify(blobs.length?JSON.parse(await blobs[0].text()):null));return;}const out=[];for(const q of x.queries){const r=await c.window.fetch(q);out.push({status:r.status,body:await r.text()});}process.stdout.write(JSON.stringify(out));})();
"""


def static_requests(generation, queries, **options):
    return json.loads(
        subprocess.check_output(
            ["node", "-e", ADAPTER],
            input=json.dumps(
                dict(root=str(generation), web=str(PACKAGE / "web"), queries=queries, **options)
            ).encode(),
        )
    )


def test_publication_binds_sanitized_report_and_assets(collected, tmp_path):
    assert collected["kev"]["publication"] is None
    baseline = dict(
        collected,
        research={key: value for key, value in collected["research"].items() if key != "kev_input"},
    )
    baseline.pop("kev")
    before = public_projection(baseline)
    generation = publish(collected, tmp_path / "public")
    snapshot = json.loads((generation / "snapshot.json").read_text())
    report = snapshot["kev"]
    validate_report(report)
    assert report["publication"] == snapshot["publication"]
    assert report["generated_at"] == report["evaluated_at"] == snapshot["generated_at"]
    assert report == json.loads((generation / "kev.json").read_text())
    assert report["listed_cve_ids"] == [CID, OUTSIDE]
    assert list(report["entries"]) == [CID]
    retained = collected["research"]["kev_input"]["retained"]
    assert report["catalogue"]["sha256"] == hashlib.sha256(RAW).hexdigest() == retained["sha256"]
    assert report["catalogue"]["revision_id"] == retained["revision_id"]
    assert "kev_input" not in snapshot["research"]
    assert "publisherExtra" not in json.dumps(snapshot)
    assert RAW.decode() not in json.dumps(snapshot)
    api = json.loads((generation / "openapi.json").read_text())["paths"]
    for route in ["/api/state", "/api/export.json", "/api/export.csv", "/api/v1/kev"]:
        assert "kev" in {parameter["name"] for parameter in api[route]["get"]["parameters"]}
        assert {"200", "400", "503"} <= api[route]["get"]["responses"].keys()
    assert "/kev.json" in api and "/schemas/kev-v1.json" in api
    for key in ["research_dossiers", "component_studies", "disclosure_review", "product_cohorts"]:
        assert snapshot[key] == before[key]
    manifest = json.loads((generation / "manifest.json").read_text())["sha256"]
    for name in ["kev.json", "kev.js", "schemas/kev-v1.json"]:
        assert manifest[name] == hashlib.sha256((generation / name).read_bytes()).hexdigest()
        assert request(Application(tmp_path / "public"), "/" + name)[0] == 200
    kev_asset = "assets/" + manifest["kev.js"] + ".js"
    html = (generation / "index.html").read_text()
    assert kev_asset in html
    assert (
        html.index(kev_asset)
        < html.index("assets/" + manifest["snapshot.js"] + ".js")
        < html.index("assets/" + manifest["app.js"] + ".js")
    )
    status, body = request(Application(tmp_path / "public"), "/api/v1/kev")
    evaluated = json.loads(body)
    assert status == 200
    assert evaluated["selection"] == report["selection"]
    assert evaluated["publication"] == report["publication"]
    assert json.loads(
        request(Application(tmp_path / "public"), "/api/v1/research-dossiers")[1]
    ) == json.loads((generation / "research-dossiers.json").read_text())


@pytest.mark.parametrize("state_name", ["available", "stale", "failed"])
def test_native_and_installed_static_query_export_parity(collected, tmp_path, state_name):
    if state_name == "stale":
        collected["research"]["kev_input"]["checked_at"] = (
            datetime.now(timezone.utc) - timedelta(days=3)
        ).isoformat()
    if state_name == "failed":
        collected["research"]["kev_input"]["latest_attempt"].update(
            outcome="error", error_code="HTTP_503"
        )
    generation = publish(collected, tmp_path / "public")
    app = Application(tmp_path / "public")
    queries = [
        "",
        "kev=listed",
        f"cves={CID},{OTHER}",
        f"cves={CID},{OTHER}&kev=listed",
        f"cves={CID}&kev=",
        f"cves={CID}&kev=other",
        f"cves={CID}&kev=listed&kev=listed",
        f"cves={CID}&kev=listed&vendor=hpe",
        f"cves={CID}&vendor=unknown",
        f"cves={CID}&vendor=hpe&vendor=hpe",
        f"cves={CID}&vendor=",
        f"cves={OUTSIDE}&kev=listed",
        f"cves={OTHER}&kev=listed",
        "cves=CVE-1999-999999&kev=listed",
    ]
    urls = [
        path + "?" + query
        for path in ["/api/state", "/api/export.json", "/api/export.csv"]
        for query in queries
    ]
    static = static_requests(generation, urls)
    for url, browser in zip(urls, static):
        path, query = url.split("?", 1)
        status, body = request(app, path, query)
        assert browser["status"] == status, (url, browser, body)
        if status != 200:
            assert json.loads(browser["body"]) == json.loads(body)
        elif path.endswith(".csv"):
            native_rows = list(csv.DictReader(io.StringIO(body.decode())))
            browser_rows = list(csv.DictReader(io.StringIO(browser["body"])))
            for row in native_rows:
                row.pop("kev_evaluated_at")
            for row in browser_rows:
                row.pop("kev_evaluated_at")
            assert browser_rows == native_rows
        else:
            native = json.loads(body)
            browser_data = json.loads(browser["body"])
            for key in [
                "comparison",
                "coverage",
                "casefiles",
                "scorecards",
                "timeline",
                "research_dossiers",
                "all_cves",
            ]:
                assert browser_data[key] == native[key], (url, key)
            assert browser_data["kev"]["selection"] == native["kev"]["selection"]
            assert browser_data["kev"]["publication"] == native["publication"]
            assert browser_data["kev"]["listed_cve_ids"] == [CID, OUTSIDE]
            if "kev=listed" in query and native["comparison"]["cohort"] == []:
                assert native["kev"]["selection"]["requested_cve_ids"]
                assert native["comparison_eligibility"]["cohort"] == []
                assert native["casefiles"]["cases"] == []
                assert native["research_dossiers"]["dossiers"] == []


def test_selected_csv_keeps_historical_provenance_and_escapes_fields(collected, tmp_path):
    source = collected["research"]["kev_input"]
    collected["records"][0]["assessments"][0]["versions"] = [{"expression": "Synthetic 1.x"}]
    entry = source["retained"]["catalogue"]["entries"][CID]
    entry.update(
        requiredAction="=synthetic()",
        knownRansomwareCampaignUse="Unknown",
        forensicTriage="+triage",
    )
    source["latest_attempt"].update(outcome="error", error_code="HTTP_503")
    generation = publish(collected, tmp_path)
    full = json.loads((generation / "snapshot.json").read_text())
    selected = select(full, [CID, OTHER], evaluated_at=full["generated_at"])
    assert csv_export(selected).splitlines()[0] == ",".join(FIELDS)
    rows = list(csv.DictReader(io.StringIO(csv_export(selected))))
    assert rows[0]["kev_status"] == "unknown"
    assert rows[0]["kev_required_action"] == "'=synthetic()"
    assert rows[0]["kev_forensic_triage"] == "'+triage"
    assert rows[0]["kev_ransomware_use"] == "Unknown"
    assert rows[1]["kev_ransomware_use"] == rows[1]["kev_date_added"] == ""
    assert rows[0]["kev_source_sha256"] == source["retained"]["sha256"]
    assert rows[0]["publication_id"] == full["publication"]["id"]
    assert rows[0]["publication_generated_at"] == full["generated_at"]
    browser = static_requests(generation, [f"/api/export.csv?cves={CID},{OTHER}"])[0]
    browser_rows = list(csv.DictReader(io.StringIO(browser["body"])))
    for a, b in zip(rows, browser_rows):
        a.pop("kev_evaluated_at")
        b.pop("kev_evaluated_at")
        assert a == b


def test_legacy_selection_binds_enclosing_identity(collected):
    collected.pop("kev", None)
    collected["publication"] = {"id": "legacy", "advisory_schema_version": 2}
    result = select(collected, [CID], evaluated_at=collected["generated_at"])
    assert result["kev"]["publication"] == collected["publication"]
    assert result["kev"]["generated_at"] == collected["generated_at"]
    assert result["kev"]["source"]["availability"] == "missing"
    validate_report(result["kev"])
    for field, value in [("availability", "available"), ("membership", {CID: "listed"})]:
        invalid = copy.deepcopy(result["kev"])
        invalid["source" if field == "availability" else "selection"][field] = value
        with pytest.raises(ValueError):
            validate_report(invalid)


def test_write_boundary_validates_kev_before_writing_files(collected, tmp_path):
    generation = publish(collected, tmp_path / "public")
    invalid = json.loads((generation / "snapshot.json").read_text())
    invalid["kev"]["selection"]["membership"][CID] = "not_listed"
    destination = tmp_path / "invalid"
    with pytest.raises(ValueError, match="KEV"):
        write_bundle(destination, invalid)
    assert not destination.exists()


def test_legacy_native_and_static_missing_report_use_enclosing_identity(collected, tmp_path):
    from infrastructure_impact.application.static_delivery import write_static_delivery

    data = public_projection(collected)
    data.pop("kev")
    data["publication"] = {"id": "b" * 32, "advisory_schema_version": 2}
    data["current_evidence"]["publication"] = data["publication"]
    generation = tmp_path / "generations" / "legacy"
    generation.mkdir(parents=True)
    (generation / "snapshot.json").write_text(json.dumps(data))
    write_static_delivery(generation, data)
    (tmp_path / "current").symlink_to(generation)
    urls = [f"/api/state?cves={CID}", f"/api/state?cves={CID}&kev=listed"]
    for url, browser in zip(urls, static_requests(generation, urls)):
        path, query = url.split("?", 1)
        code, body = request(Application(tmp_path), path, query)
        assert code == browser["status"]
        native = json.loads(body)
        if code == 200:
            for report in [native["kev"], json.loads(browser["body"])["kev"]]:
                validate_report(report)
                assert report["publication"] == data["publication"]
                assert report["generated_at"] == data["generated_at"]
                assert report["source"]["availability"] == "missing"
        else:
            assert code == 503
            assert native == json.loads(browser["body"]) == {"error": "kev_unavailable"}


def test_non_state_fetch_does_not_cancel_committed_download(collected, tmp_path):
    generation = publish(collected, tmp_path)
    downloaded = static_requests(
        generation, [f"/api/state?cves={CID}&kev=listed", f"/api/v1/kev?cves={OTHER}"], race=True
    )
    assert downloaded is not None
    assert downloaded["comparison"]["cohort"] == [CID]
    assert downloaded["kev"]["selection"]["requested_cve_ids"] == [CID]
    assert downloaded["kev"]["selection"]["kev_only"] is True


@pytest.mark.parametrize("collected", [[CID, OTHER, OUTSIDE]], indirect=True)
@pytest.mark.parametrize("kev_only", [False, True])
def test_absent_cve_requests_hydrate_all_imported_scope(collected, tmp_path, kev_only):
    # Both nonbenchmark imported CVEs must be loaded: OUTSIDE listed, OTHER not listed.
    assert OTHER not in collected["benchmark_cohort"]
    assert OUTSIDE not in collected["benchmark_cohort"]
    generation = publish(collected, tmp_path)
    query = "kev=listed" if kev_only else ""
    paths = ["/api/state", "/api/export.json", "/api/export.csv"]
    urls = [path + ("?" + query if query else "") for path in paths]
    browser_responses = static_requests(generation, urls)
    requested = sorted([CID, OTHER, OUTSIDE])
    effective = sorted([CID, OUTSIDE]) if kev_only else requested
    app = Application(tmp_path)
    for path, browser in zip(paths, browser_responses):
        status, body = request(app, path, query)
        assert status == browser["status"] == 200
        if path.endswith(".csv"):
            native_rows = list(csv.DictReader(io.StringIO(body.decode())))
            browser_rows = list(csv.DictReader(io.StringIO(browser["body"])))
            assert sorted(row["cve_id"] for row in browser_rows) == effective
            for row in [*native_rows, *browser_rows]:
                row.pop("kev_evaluated_at")
            assert browser_rows == native_rows
        else:
            native = json.loads(body)
            selected = json.loads(browser["body"])
            assert selected["kev"]["selection"] == native["kev"]["selection"]
            assert selected["kev"]["selection"]["requested_cve_ids"] == requested
            assert selected["kev"]["selection"]["effective_cve_ids"] == effective
            for key in [
                "records",
                "comparison",
                "comparison_eligibility",
                "coverage",
                "scorecards",
                "timeline",
                "casefiles",
                "research_dossiers",
                "all_cves",
                "publication",
            ]:
                assert selected[key] == native[key], (path, key)
            assert selected["comparison"]["cohort"] == effective
            assert selected["kev"]["selection"]["membership"][OUTSIDE] == "listed"
            assert selected["kev"]["selection"]["membership"][OTHER] == "not_listed"
            assessment_ids = sorted(
                a["cve_id"] for record in selected["records"] for a in record["assessments"]
            )
            assert assessment_ids == (effective if path.endswith(".json") else requested)
