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
for(const f of ['research-dossiers.js','delivery.js','snapshot.js'])vm.runInContext(fs.readFileSync(x.web+'/'+f,'utf8'),c);
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
  process.stdout.write(JSON.stringify({selected,exported:c.exportSnapshot(selected),transportReport:source.research_dossiers,requests,peak}));
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
    assert result["static_marker_verified"] and ".nojekyll" in seen
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
vm.createContext(c);for(const f of ['research-dossiers.js','delivery.js','snapshot.js'])vm.runInContext(fs.readFileSync(x.web+'/'+f,'utf8'),c);
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


@pytest.mark.parametrize(
    "control,status",
    [
        ("vendor=hpe", 200),
        ("vendor=unknown", 400),
        ("vendor=constructor", 400),
        ("vendor=", 400),
        ("vendor=hpe&vendor=hpe", 400),
        ("vendor=hpe&vendor=aruba", 400),
    ],
)
def test_intercepted_state_fetch_validates_vendor_and_preserves_download_scope(
    tmp_path, control, status
):
    generation = publish(dataset(), tmp_path)
    query = "cves=CVE-2024-6387&" + control
    replies = []
    native_body = b"".join(
        Application(tmp_path)(
            dict(REQUEST_METHOD="GET", PATH_INFO="/api/state", QUERY_STRING=query),
            lambda status, headers: replies.append(status),
        )
    )
    assert int(replies[0].split()[0]) == status
    script = r"""
const fs=require('fs'),vm=require('vm'),{webcrypto}=require('crypto');
const x=JSON.parse(fs.readFileSync(0,'utf8')), handlers={},blobs=[];
URL.createObjectURL=b=>{blobs.push(b);return 'blob:synthetic'};URL.revokeObjectURL=()=>{};
const fetch=async(path)=>new Response(fs.readFileSync(x.root+'/'+path.replace('/site/','')));
const c={window:{fetch},document:{baseURI:'https://example.test/site/',addEventListener:(n,fn)=>handlers[n]=fn,querySelector:()=>({textContent:''}),createElement:()=>({click(){}})},location:{origin:'https://example.test'},Set,Map,URL,Response,Blob,TextEncoder,TextDecoder,Uint8Array,crypto:webcrypto,setTimeout:fn=>fn()};
vm.createContext(c);for(const f of ['research-dossiers.js','delivery.js','snapshot.js'])vm.runInContext(fs.readFileSync(x.web+'/'+f,'utf8'),c);
(async()=>{
 const response=await c.window.fetch('/api/state?'+x.query),body=await response.json();
 if(response.ok)await handlers.click({target:{closest:()=>({id:'json-export'})},preventDefault(){}});
 process.stdout.write(JSON.stringify({status:response.status,body,download:blobs.length?JSON.parse(await blobs[0].text()):null}));
})().catch(e=>{console.error(e);process.exitCode=1});
"""
    result = json.loads(
        subprocess.check_output(
            ["node", "-e", script],
            input=json.dumps(
                dict(root=str(generation), web=str(PACKAGE / "web"), query=query)
            ).encode(),
        )
    )
    assert result["status"] == status
    native = json.loads(native_body)
    if status == 400:
        assert result["body"] == native == {"error": "Invalid request"}
        assert result["download"] is None
    else:
        report = result["body"]["research_dossiers"]
        assert report == native["research_dossiers"]
        dossier = report["dossiers"][0]
        assert dossier["scope"]["selected_vendor"] == "hpe"
        assert dossier["comparison_targets"] == []
        assert [c["vendor"] for c in dossier["disclosure_context"]] == ["hpe"]
        assert result["download"]["research_dossiers"] == report
        assert result["download"]["publication"] == result["body"]["publication"]


def test_product_label_context_keeps_shared_scope_and_global_cohort_parity(tmp_path):
    from infrastructure_impact.application.static_delivery import product_label_context

    data = dataset()
    for record in data["records"]:
        for claim in record["assessments"]:
            claim["product"] = "16.x"
            if record["vendor"] == "juniper":
                claim["product_family"] = (
                    "Synthetic <family A>" if claim["cve_id"] == CID else "Synthetic family B"
                )
            elif record["document_status"] == "draft":
                claim["product_family"] = "DRAFT MUST NOT APPEAR"
            else:
                claim.pop("product_family", None)
    # The same literal label also has a statement without publisher family context.
    juniper = next(r for r in data["records"] if r["vendor"] == "juniper")
    juniper["assessments"].append(dict(juniper["assessments"][0]))
    juniper["assessments"][-1]["product_id"] = "synthetic-unscoped-branch"
    juniper["assessments"][-1].pop("product_family", None)
    expected = product_label_context(data["records"], "juniper")
    assert expected == {
        "16.x": {"families": ["Synthetic <family A>", "Synthetic family B"], "unscoped": True}
    }
    generation = publish(data, tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    bootstrap = json.loads((generation / index["bootstrap"]["path"]).read_text())["data"]
    assert bootstrap["product_label_index"]["juniper"]["context"] == expected
    assert bootstrap["product_label_index"]["juniper"]["all"] == ["16.x"]
    assert bootstrap["product_label_index"]["hpe"]["context"] == {
        "16.x": {"families": [], "unscoped": True}
    }
    assert "DRAFT MUST NOT APPEAR" not in json.dumps(bootstrap["product_label_index"])
    script = r"""
const fs=require('fs'),vm=require('vm');const c={window:{},Set,URL};vm.createContext(c);
const x=JSON.parse(fs.readFileSync(0,'utf8'));
vm.runInContext(fs.readFileSync(x.web+'/snapshot.js','utf8'),c);
const a=c.productLabelContext(x.full,'juniper'), b=c.productLabelContext(x.partial,'juniper');
process.stdout.write(JSON.stringify({a,b,display:c.productLabelDisplay('16.x',b),labels:c.productLabels(x.partial,'juniper'),unknown:c.productLabelDisplay('__proto__',{})}));
"""
    result = json.loads(
        subprocess.check_output(
            ["node", "-e", script],
            input=json.dumps(
                dict(
                    web=str(PACKAGE / "web"),
                    full=data,
                    partial=dict(records=[], product_label_index=bootstrap["product_label_index"]),
                )
            ).encode(),
        )
    )
    assert result["a"] == result["b"] == expected
    assert result["labels"] == ["16.x"] and result["unknown"] == "__proto__"
    assert (
        result["display"]
        == "16.x — Synthetic <family A> / Synthetic family B (shared publisher label) (some statements lack family context)"
    )


@pytest.mark.parametrize("fault", ["missing", "changed"])
def test_monitor_rejects_missing_or_changed_declared_static_marker(tmp_path, monkeypatch, fault):
    import io
    from urllib.error import HTTPError

    import checks.public_health as health

    generation = publish(dataset(), tmp_path)

    class Response(io.BytesIO):
        status = 200

    def get(url, timeout=None):
        path = url.removeprefix("https://example.test/") or "index.html"
        if path == ".nojekyll":
            if fault == "missing":
                raise HTTPError(url, 404, "Missing", {}, None)
            return Response(b"unexpected marker contents")
        return Response((generation / path).read_bytes())

    monkeypatch.setattr(health, "urlopen", get)
    with pytest.raises((HTTPError, AssertionError)):
        health.check("https://example.test")


def test_monitor_runs_without_site_packages_or_application_imports(tmp_path):
    import os
    import sys
    from pathlib import Path

    generation = publish(dataset(), tmp_path / "publications")
    script = Path(__file__).resolve().parent.parent / "checks/public_health.py"
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    probe = """
import io, json, runpy, sys, urllib.request
from pathlib import Path
folder = Path(sys.argv[2])
class Response(io.BytesIO):
    status = 200
def get(url, timeout=None):
    relative = url.removeprefix('https://example.test/') or 'index.html'
    return Response((folder / relative).read_bytes())
urllib.request.urlopen = get
module = runpy.run_path(sys.argv[1])
result = module['check']('https://example.test')
assert result['status'] == 'fresh'
assert not any(n == 'infrastructure_impact' or n.startswith('infrastructure_impact.') for n in sys.modules)
print(json.dumps(result))
"""
    result = subprocess.run(
        [sys.executable, "-S", "-c", probe, str(script), str(generation)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout)["static_marker_verified"]


@pytest.mark.parametrize(
    ("elapsed_seconds", "error"),
    [(0, None), (-240, None), (-360, "clock tolerance"), (35 * 3600, None), (36 * 3600, "stale")],
)
def test_monitor_bounds_publication_age_in_both_directions(
    tmp_path, monkeypatch, elapsed_seconds, error
):
    import io
    from datetime import datetime, timedelta

    import checks.public_health as health

    data = dataset()
    published = datetime.fromisoformat(data["generated_at"])
    generation = publish(data, tmp_path)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return (published + timedelta(seconds=elapsed_seconds)).astimezone(tz)

    class Response(io.BytesIO):
        status = 200

    monkeypatch.setattr(health, "datetime", Clock)
    monkeypatch.setattr(
        health,
        "urlopen",
        lambda url, timeout=None: Response(
            (generation / (url.removeprefix("https://example.test/") or "index.html")).read_bytes()
        ),
    )
    if error:
        with pytest.raises(AssertionError, match=error):
            health.check("https://example.test")
    else:
        assert health.check("https://example.test")["status"] == "fresh"


def test_monitor_reads_manifest_with_a_fixed_byte_budget(monkeypatch):
    import io

    import checks.public_health as health

    reads = []

    class Response(io.BytesIO):
        status = 200

        def read(self, size=-1):
            reads.append(size)
            return super().read(size)

    monkeypatch.setattr(
        health,
        "urlopen",
        lambda url, timeout=None: Response(b" " * 2_000_001),
    )
    with pytest.raises(AssertionError, match="manifest exceeds monitor budget"):
        health.check("https://example.test")
    assert reads == [2_000_001]


@pytest.mark.parametrize("ids", [None, [CID], ["CVE-2024-6387"], []])
def test_content_addressed_common_metadata_preserves_generation_dossiers(tmp_path, ids):
    generation = publish(dataset(), tmp_path)
    snapshot = json.loads((generation / "snapshot.json").read_text())
    index = json.loads((generation / "data/index.json").read_text())
    common = json.loads((generation / index["bootstrap"]["path"]).read_text())
    assert "research_dossiers" in snapshot
    assert common["data"]["research_dossiers"] == snapshot["research_dossiers"]
    assert common["publication"] == snapshot["publication"]
    # Transport retains the complete report; the browser applies current selection.
    result = run(generation, ids=ids)
    assert result["transportReport"] == snapshot["research_dossiers"]
    assert result["selected"]["publication"] == snapshot["publication"]
    assert (
        result["selected"]["research_dossiers"]
        == select(snapshot, ids if ids is not None else list(snapshot["benchmark_cohort"]))[
            "research_dossiers"
        ]
    )


def test_old_static_metadata_never_falls_back_to_another_dossier_generation(tmp_path):
    from infrastructure_impact.application.publication import public_projection
    from infrastructure_impact.application.static_delivery import write_static_delivery

    # Isolated old-generation transport fixture: no published generation is modified.
    data = public_projection(dataset())
    data.pop("research_dossiers", None)
    data["publication"] = {"id": "b" * 32, "advisory_schema_version": 2}
    (tmp_path / "snapshot.json").write_text(json.dumps(data))
    write_static_delivery(tmp_path, data)
    # A loose later report must never be requested by the generation-bound loader.
    (tmp_path / "research-dossiers.json").write_text(json.dumps({"PRIVATE_SENTINEL": "later"}))
    result = run(tmp_path, ids=[CID])
    assert "research_dossiers" not in result["selected"]
    assert not any("research-dossiers.json" in path for path in result["requests"])
    assert result["selected"]["publication"] == data["publication"]


def test_dossier_reader_assets_are_fingerprinted_ordered_and_served(tmp_path):
    generation = publish(dataset(), tmp_path)
    html = (generation / "index.html").read_text()
    scripts = re.findall(r'<script defer src="([^"]+)"', html)
    expected = ["research-dossiers.js", "delivery.js", "snapshot.js", "app.js"]
    paths = []
    manifest = json.loads((generation / "manifest.json").read_text())
    app = Application(tmp_path)
    for name in expected:
        raw = (PACKAGE / "web" / name).read_bytes()
        path = "assets/" + hashlib.sha256(raw).hexdigest() + ".js"
        paths.append("/" + path)
        assert (generation / path).read_bytes() == raw
        assert manifest["sha256"][path] == hashlib.sha256(raw).hexdigest()
        code, _, body = app.route(dict(REQUEST_METHOD="GET", PATH_INFO="/" + name))
        assert (code, body) == (200, raw)
    assert scripts == paths
    native = (PACKAGE / "web/index.html").read_text()
    assert re.findall(r'<script defer src="([^"]+)"', native) == [
        "/research-dossiers.js",
        "/app.js",
    ]


@pytest.mark.parametrize(
    "fault",
    [
        "generation",
        "concealment",
        "digest",
        "old_generation",
        "marker_object",
        "marker_array",
        "marker_false",
        "marker_null",
        "report_object",
        "report_array",
        "report_false",
        "report_null",
    ],
)
def test_monitor_checks_additive_dossier_report(tmp_path, monkeypatch, fault):
    import io

    import checks.public_health as health

    generation = publish(dataset(), tmp_path)
    report_path = generation / "research-dossiers.json"
    original = json.loads(report_path.read_text())
    selected_generation = json.loads((generation / "snapshot.json").read_text())["publication"]
    report = json.loads(report_path.read_text())
    if fault == "generation":
        report["publication"]["id"] = "different-generation"
        assert report["publication"]["id"] != selected_generation["id"]
    elif fault == "concealment":
        report["limits"]["concealment_established"] = True
    malformed = {"object": {}, "array": [], "false": False, "null": None}
    if fault.startswith("report_"):
        report = malformed[fault.removeprefix("report_")]
    report_raw = json.dumps(report).encode()
    manifest = json.loads((generation / "manifest.json").read_text())
    manifest["sha256"]["research-dossiers.json"] = hashlib.sha256(report_raw).hexdigest()
    seen = []

    class Response(io.BytesIO):
        status = 200

    def get(url, timeout=None):
        path = url.removeprefix("https://example.test/") or "index.html"
        seen.append(path)
        if path == "manifest.json":
            return Response(json.dumps(manifest).encode())
        if path == "research-dossiers.json":
            assert fault != "old_generation", "Absent additive report must not be fetched"
            return Response(report_raw + (b" " if fault == "digest" else b""))
        return Response((generation / path).read_bytes())

    if fault == "old_generation" or fault.startswith("marker_"):
        # Build valid content-addressed parts so the malformed marker reaches dispatch.
        from infrastructure_impact.application.static_delivery import write_static_delivery

        data = json.loads((generation / "snapshot.json").read_text())
        if fault == "old_generation":
            data.pop("research_dossiers")
        else:
            data["research_dossiers"] = malformed[fault.removeprefix("marker_")]
        write_static_delivery(generation, data)
        manifest["sha256"] = {
            path.relative_to(generation).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in generation.rglob("*")
            if path.is_file() and path.name != "manifest.json"
        }
        manifest["sha256"]["research-dossiers.json"] = hashlib.sha256(report_raw).hexdigest()
        assert original["publication"] == selected_generation
    monkeypatch.setattr(health, "urlopen", get)
    if fault == "old_generation":
        assert health.check("https://example.test")["status"] == "fresh"
        assert "research-dossiers.json" not in seen
    else:
        with pytest.raises(AssertionError):
            health.check("https://example.test")
