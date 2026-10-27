"""Cohort delivery parity and failure isolation using original synthetic records."""

import gzip
import hashlib
import json
import re
import subprocess

import pytest

from infrastructure_impact.adapters.common import assessment, base
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.exports import assessment_export, select
from infrastructure_impact.http import Application
from infrastructure_impact.settings import PACKAGE
from infrastructure_impact.storage.repository import connect, ingest

CID = "CVE-2025-12345"
OTHER = "CVE-2025-54321"


def dataset():
    with connect(":memory:") as db:
        for i, (vendor, cids, status) in enumerate(
            [
                ("juniper", [CID, OTHER], "published"),
                ("hpe", [OTHER], "published"),
                ("hpe", [OTHER], "draft"),
            ]
        ):
            r = base(
                vendor,
                "https://"
                + ("www.juniper.net" if vendor == "juniper" else "support.hpe.com")
                + "/synthetic/"
                + str(i),
                "SYNTHETIC-" + str(i),
                "Synthetic",
                "2025-01-01T00:00:00Z",
            )
            r.update(cves=cids, document_status=status)
            r["assessments"] = [
                assessment(
                    c,
                    "Junos OS Evolved"
                    if vendor == "juniper"
                    else "HPE ProLiant Compute DL325 Gen12",
                    "affected",
                    "Synthetic",
                    [
                        {
                            "expression": "publisher condition "
                            + ("x" * 20000 if c == OTHER else "1.x")
                        }
                    ],
                )
                for c in cids
            ]
            ingest(db, b"synthetic" + str(i).encode(), r["source_url"], lambda *_, r=r: r, vendor)
        d = state(db, [CID])
        d["benchmark_cohort"] = {CID: "Synthetic"}
        return d


SCRIPT = r"""
const fs=require('fs'),vm=require('vm'),{webcrypto}=require('crypto');
const x=JSON.parse(fs.readFileSync(0,'utf8'));
const requests=[];let active=0,peak=0;
const c={window:{},Set,Map,URL,Response,Blob,TextEncoder,TextDecoder,Uint8Array,crypto:webcrypto};
vm.createContext(c);
for(const f of ['delivery.js','snapshot.js'])vm.runInContext(fs.readFileSync(x.web+'/'+f,'utf8'),c);
const fetch=async(path)=>{
 requests.push(path);active++;peak=Math.max(peak,active);
 try {
  let raw=fs.readFileSync(x.root+'/'+path.replace('/site/',''));
  if(x.fault==='digest' && path.includes('/data/') && !path.endsWith('index.json'))raw=Buffer.from(raw.toString().replace('Synthetic','Tampered!'));
  if(x.fault==='missing' && !path.endsWith('index.json'))return new Response('',{status:404});
  return new Response(raw);
 } finally {active--;}
};
(async()=>{
 try {
  const load=await c.createStaticDelivery(fetch,'/site/');
  let source=await load(x.ids,x.changes);
  const selected=c.selectSnapshot(source,x.ids||Object.keys(source.benchmark_cohort),x.options||{});
  if(x.again)await load(x.ids,x.changes);
  process.stdout.write(JSON.stringify({selected,exported:c.exportSnapshot(selected),requests,peak}));
 }catch(error){process.stdout.write(JSON.stringify({error:error.message,requests}));}
})();
"""


def run(root, **options):
    return json.loads(
        subprocess.check_output(
            ["node", "-e", SCRIPT],
            input=json.dumps(dict(root=str(root), web=str(PACKAGE / "web"), **options)).encode(),
        )
    )


@pytest.mark.parametrize(
    "ids,options",
    [
        ([CID], {}),
        ([CID], {"group": "routing_switching"}),
        ([CID], {"products": {"hpe": ["HPE ProLiant Compute DL325 Gen12"]}}),
        (["CVE-1999-999999"], {}),
    ],
)
def test_narrow_delivery_preserves_global_product_scope_and_python_policy(tmp_path, ids, options):
    generation = publish(dataset(), tmp_path)
    full = json.loads((generation / "snapshot.json").read_text())
    result = run(generation, ids=ids, options=options, again=True)
    assert "error" not in result, result
    expected = select(full, ids, **options)
    for key in [
        "comparison",
        "comparison_eligibility",
        "coverage",
        "scorecards",
        "timeline",
        "casefiles",
    ]:
        assert result["selected"][key] == expected[key], key
    assert result["exported"]["records"] == assessment_export(expected)["records"]
    assert not any(p.endswith("snapshot.json") for p in result["requests"])
    assert len(result["requests"]) == len(set(result["requests"]))
    assert result["peak"] <= 6
    assert result["selected"]["counts"] == full["counts"]


def test_default_cohort_and_explicit_all_archive(tmp_path):
    generation = publish(dataset(), tmp_path)
    default = run(generation, ids=None)
    assert default["selected"]["comparison"]["cohort"] == [CID]
    assert not any(p.endswith("snapshot.json") for p in default["requests"])
    full = run(generation, ids=[CID, OTHER])
    assert any(p.endswith("snapshot.json") for p in full["requests"])
    assert len(full["selected"]["records"]) == 3


def test_compressed_archive_is_exact_public_projection_and_reproducible(tmp_path):
    d = dataset()
    d["records"][0]["notes"] = [{"text": "PRIVATE-NOTE-MUST-NOT-PUBLISH"}]
    generation = publish(d, tmp_path)
    raw = (generation / "snapshot.json").read_bytes()
    compressed = (generation / "snapshot.json.gz").read_bytes()
    assert gzip.decompress(compressed) == raw
    assert b"PRIVATE-NOTE-MUST-NOT-PUBLISH" not in raw
    assert len(compressed) < len(raw)
    manifest = json.loads((generation / "manifest.json").read_text())
    assert manifest["sha256"]["snapshot.json.gz"] == hashlib.sha256(compressed).hexdigest()
    from infrastructure_impact.application.publication import write_bundle

    write_bundle(tmp_path / "repeat", json.loads(raw))
    assert (tmp_path / "repeat/snapshot.json.gz").read_bytes() == compressed
    code, content_type, body = Application(tmp_path).route(
        dict(REQUEST_METHOD="GET", PATH_INFO="/snapshot.json.gz")
    )
    assert (code, content_type, body) == (200, "application/gzip", compressed)
    html = (generation / "index.html").read_text()
    assert not re.search(r'id="archive-export"\s+hidden\b', html)
    assert 'href="/snapshot.json.gz"' in html


@pytest.mark.parametrize("fault", ["digest", "missing", "generation"])
def test_partial_or_changed_parts_never_produce_a_successful_empty_cohort(tmp_path, fault):
    generation = publish(dataset(), tmp_path)
    if fault == "generation":
        index = json.loads((generation / "data/index.json").read_text())
        index["publication"]["id"] = "0" * 32
        (generation / "data/index.json").write_text(json.dumps(index))
    result = run(generation, ids=[CID], fault=fault)
    assert "error" in result and "selected" not in result


def test_static_route_allowlist_and_content_addressing(tmp_path):
    generation = publish(dataset(), tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    app = Application(tmp_path)
    for path in ["/data/index.json", "/" + index["bootstrap"]["path"], "/delivery.js"]:
        code, _, _ = app.route(dict(REQUEST_METHOD="GET", PATH_INFO=path))
        assert code == 200
    for path in [
        "/data/../../snapshot.json",
        "/data/private.json",
        "/data/" + ("a" * 64) + ".json",
    ]:
        code, _, _ = app.route(dict(REQUEST_METHOD="GET", PATH_INFO=path))
        assert code == 404
    import hashlib

    for path, digest in json.loads((generation / "manifest.json").read_text())["sha256"].items():
        assert hashlib.sha256((generation / path).read_bytes()).hexdigest() == digest


def test_source_changes_are_loaded_only_on_request(tmp_path):
    d = dataset()
    d["changes"] = [dict(id=1, details={"Synthetic": "change"})]
    generation = publish(d, tmp_path)
    normal = run(generation, ids=[CID])
    changed = run(generation, ids=[CID], changes=True)
    assert normal["selected"]["changes"] == [] and changed["selected"]["changes"] == d["changes"]
    assert len(changed["requests"]) > len(normal["requests"])


def test_missing_known_cve_index_fails_instead_of_claiming_no_evidence(tmp_path):
    generation = publish(dataset(), tmp_path)
    p = generation / "data/index.json"
    index = json.loads(p.read_text())
    index["cohorts"].pop(CID)
    p.write_text(json.dumps(index))
    assert "incomplete" in run(generation, ids=[CID])["error"]


def test_oversized_part_does_not_replace_active_generation(tmp_path):
    previous = publish(dataset(), tmp_path)
    d = dataset()
    d["records"][0]["title"] = "x" * 8_000_000
    with pytest.raises(ValueError, match="exceeds 8 MB"):
        publish(d, tmp_path)
    assert (tmp_path / "current").resolve() == previous
    assert not list((tmp_path / "generations").glob(".staging-*"))


def test_monitor_checks_cohort_parts_without_full_archive_download(tmp_path, monkeypatch):
    import io

    import checks.public_health as health
    from checks.public_health import check

    generation = publish(dataset(), tmp_path)
    seen = []

    class Response(io.BytesIO):
        status = 200

    def get(url, timeout=None):
        path = url.removeprefix("https://example.test/") or "index.html"
        seen.append(path)
        assert path != "snapshot.json", "Monitor must not fetch the entire archive"
        return Response((generation / path).read_bytes())

    monkeypatch.setattr(health, "urlopen", get)
    result = check("https://example.test")
    assert result["status"] == "fresh" and result["advisories"] == 3
    assert result["delivery"] == "cohort_parts_v1" and not result["full_archive_download_verified"]
    assert result["checked_default_bytes"] < 8_000_000
    assert result["compressed_archive_verified"]
    assert (
        result["checked_compressed_archive_bytes"]
        == (generation / "snapshot.json.gz").stat().st_size
    )


@pytest.mark.parametrize("fault", ["digest", "contents", "truncated"])
def test_monitor_rejects_invalid_compressed_archive(tmp_path, monkeypatch, fault):
    import io

    import checks.public_health as health

    generation = publish(dataset(), tmp_path)
    path = generation / "snapshot.json.gz"
    path.write_bytes(
        gzip.compress(b"wrong snapshot") if fault == "contents" else path.read_bytes()[:-5]
    )
    if fault != "digest":
        manifest = json.loads((generation / "manifest.json").read_text())
        manifest["sha256"]["snapshot.json.gz"] = hashlib.sha256(path.read_bytes()).hexdigest()
        (generation / "manifest.json").write_text(json.dumps(manifest))

    class Response(io.BytesIO):
        status = 200

    monkeypatch.setattr(
        health,
        "urlopen",
        lambda url, timeout=None: Response(
            (generation / (url.removeprefix("https://example.test/") or "index.html")).read_bytes()
        ),
    )
    with pytest.raises((AssertionError, EOFError)):
        health.check("https://example.test")


@pytest.mark.parametrize("fault", [False, True])
def test_json_download_hydrates_history_and_reports_fetch_failure(tmp_path, fault):
    d = dataset()
    d["changes"] = [dict(id=1, details={"Synthetic": "history"})]
    generation = publish(d, tmp_path)
    script = r"""
const fs=require('fs'),vm=require('vm'),{webcrypto}=require('crypto');
const x=JSON.parse(fs.readFileSync(0,'utf8')), handlers={},blobs=[],feedback={textContent:''};
const changes=new Set(JSON.parse(fs.readFileSync(x.root+'/data/index.json','utf8')).changes.map(p=>p.path));
URL.createObjectURL=b=>{blobs.push(b);return 'blob:synthetic'};URL.revokeObjectURL=()=>{};
const fetch=async(path)=>{const file=path.replace('/site/','');if(x.fault&&changes.has(file))return new Response('',{status:404});return new Response(fs.readFileSync(x.root+'/'+file));};
const c={window:{fetch},document:{baseURI:'https://example.test/site/',addEventListener:(n,fn)=>handlers[n]=fn,querySelector:()=>feedback,createElement:()=>({click(){}})},location:{origin:'https://example.test'},Set,Map,URL,Response,Blob,TextEncoder,TextDecoder,Uint8Array,crypto:webcrypto,setTimeout:fn=>fn()};
vm.createContext(c);for(const f of ['delivery.js','snapshot.js'])vm.runInContext(fs.readFileSync(x.web+'/'+f,'utf8'),c);
(async()=>{await c.window.fetch('/api/state?cves=CVE-2025-12345');await handlers.click({target:{closest:()=>({id:'json-export'})},preventDefault(){}});process.stdout.write(JSON.stringify({exported:blobs.length?JSON.parse(await blobs[0].text()):null,error:feedback.textContent}));})();
"""
    result = json.loads(
        subprocess.check_output(
            ["node", "-e", script],
            input=json.dumps(
                dict(root=str(generation), web=str(PACKAGE / "web"), fault=fault)
            ).encode(),
        )
    )
    if fault:
        assert result["exported"] is None and result["error"].startswith("Export failed:")
    else:
        assert result["exported"]["changes"] == d["changes"] and not result["error"]
