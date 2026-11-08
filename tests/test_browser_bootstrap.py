"""Actual app startup must select the benchmark before hydrating public state."""

import json
import subprocess

import pytest
from test_static_delivery import CID, dataset

from infrastructure_impact.application.publication import publish
from infrastructure_impact.http import Application

SCRIPT = r"""
const fs=require('fs'),assert=require('assert');
const {browser}=require('./tests/helpers/ui-browser.js');
const x=JSON.parse(fs.readFileSync(0,'utf8'));
const requests=[];
let failed=false,releaseBootstrap;
const gate=new Promise(resolve=>releaseBootstrap=resolve);
const b=browser(true, {static:x.static,fetch:async(path)=>{
 requests.push(path);
 if(x.race && path==='/api/v1/bootstrap') await gate;
 if(x.fail && !failed && path===(x.static?'/data/index.json':'/api/v1/bootstrap')) {
   failed=true; return new Response('{}',{status:503});
 }
 if(path.startsWith('/api/')) {
   const url=new URL(path,'https://example.test');
   if(url.pathname==='/api/state') assert.strictEqual(url.searchParams.get('cves'),x.cid,
     'startup must never request the whole imported catalogue');
   return new Response(JSON.stringify(x.responses[url.pathname]||{}));
 }
 assert(path!=='/'+x.forbidden,'startup must never materialize full snapshot');
 return new Response(fs.readFileSync(x.root+path));
}});
(async()=>{
 const settle=async()=>{for(let i=0;i<100;i++)await new Promise(r=>setImmediate(r));};
 if(x.race){
   b.nodes.get('#cohort').value='custom';
   b.nodes.get('#custom-cves').value=x.cid;
   b.nodes.get('#apply').fire('click');
   await settle();
   const count=requests.length;
   assert(b.evaluate('data'),'newer selected request must be accepted');
   releaseBootstrap();
   await settle();
   assert.strictEqual(requests.length,count,'obsolete metadata must not start another state request');
   assert.strictEqual(b.evaluate('cohortMode'),'custom');
 }
 await settle();
 if(x.fail){
   assert.strictEqual(b.evaluate('data'),undefined);
   assert(/503/.test(b.nodes.get('#feedback').textContent));
   assert(!requests.some(p=>p.startsWith('/api/state')));
   b.nodes.get('#apply').fire('click');
   await settle();
 }
 for(let i=0;i<5000 && !b.evaluate('data') && b.nodes.get('#feedback').textContent==='Loading evidence…';i++)
   await new Promise(r=>setTimeout(r,1));
 assert(b.evaluate('data'),'startup must accept selected evidence: '+b.nodes.get('#feedback').textContent);
 assert.deepStrictEqual(JSON.parse(b.evaluate('JSON.stringify(data.comparison.cohort)')),[x.cid]);
 assert(b.nodes.get('#matrix-results').innerHTML.includes(x.cid));
 assert.strictEqual(b.evaluate('selectedCves[0]'),x.cid);
 process.stdout.write(JSON.stringify({requests}));
})().catch(e=>{console.error(e);process.exitCode=1});
"""


@pytest.mark.parametrize("publication_format", ["v1", "v2"])
@pytest.mark.parametrize(
    "static,fail,race",
    [
        (True, False, False),
        (True, True, False),
        (False, False, False),
        (False, True, False),
        (False, False, True),
    ],
)
def test_actual_browser_bootstraps_selected_evidence(
    tmp_path, publication_format, static, fail, race
):
    root = tmp_path / "site"
    out = publish(dataset(), root, publication_format=publication_format)
    app = Application(root)
    responses = {}
    for path, query in [("/api/v1/bootstrap", ""), ("/api/state", "cves=" + CID)]:
        status, _, body = app.route(dict(REQUEST_METHOD="GET", PATH_INFO=path, QUERY_STRING=query))
        assert status == 200
        responses[path] = json.loads(body if isinstance(body, bytes) else b"".join(body))
    forbidden = (
        json.loads((out / "publication-v2.json").read_bytes())["roots"]["snapshot.json"]["path"]
        if publication_format == "v2"
        else "snapshot.json"
    )
    result = subprocess.run(
        ["node", "-e", SCRIPT],
        input=json.dumps(
            dict(
                root=str(out),
                cid=CID,
                responses=responses,
                static=static,
                fail=fail,
                race=race,
                forbidden=forbidden,
            )
        ),
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    requests = json.loads(result.stdout)["requests"]
    if static:
        assert "/data/index.json" in requests
        assert "/snapshot.json" not in requests
    else:
        assert requests[0] == "/api/v1/bootstrap"
        assert requests[-1].startswith("/api/state?view=matrix&cves=" + CID)


@pytest.mark.parametrize("publication_format", ["v1", "v2"])
def test_bootstrap_metadata_does_not_hydrate_state_and_unspecified_api_scope_stays_full(
    tmp_path, publication_format, monkeypatch
):
    from infrastructure_impact.application.publication_reader import PublicationReader

    publish(dataset(), tmp_path, publication_format=publication_format)
    app = Application(tmp_path)
    if publication_format == "v2":

        def reject(*args, **kwargs):
            raise AssertionError("bootstrap must not hydrate runtime state")

        monkeypatch.setattr(PublicationReader, "runtime_snapshot", reject)
    status, _, raw = app.route(dict(REQUEST_METHOD="GET", PATH_INFO="/api/v1/bootstrap"))
    assert status == 200
    metadata = json.loads(raw)
    assert set(metadata) == {"publication", "generated_at", "benchmark_cohort"}
    assert metadata["benchmark_cohort"] == {CID: "Synthetic"}
    monkeypatch.undo()
    status, _, raw = app.route(dict(REQUEST_METHOD="GET", PATH_INFO="/api/state"))
    assert status == 200
    state = json.loads(raw if isinstance(raw, bytes) else b"".join(raw))
    assert state["comparison"]["cohort"] == state["all_cves"]


@pytest.mark.parametrize("publication_format", ["v1", "v2"])
def test_bootstrap_http_methods_headers_and_minimal_body(tmp_path, publication_format):
    """Static and native bootstrap clients share the read-only HTTP contract."""
    root = publish(dataset(), tmp_path, publication_format=publication_format)
    app = Application(tmp_path)
    for method in ("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"):
        captured = []
        body = b"".join(
            app(
                dict(REQUEST_METHOD=method, PATH_INFO="/api/v1/bootstrap"),
                lambda status, headers: captured.append((status, dict(headers))),
            )
        )
        status, headers = captured[0]
        assert status.startswith("200" if method in ("GET", "HEAD") else "405")
        assert headers["Content-Type"].startswith("application/json")
        if method == "HEAD":
            assert body == b""
        elif method == "GET":
            assert set(json.loads(body)) == {"publication", "generated_at", "benchmark_cohort"}
        else:
            assert headers["Allow"] == "GET, HEAD"

    script = r"""
const fs=require('fs'),assert=require('assert');
const {browser}=require('./tests/helpers/ui-browser.js');
const root=process.argv[1];
const b=browser(true,{static:true,fetch:async path=>new Response(fs.readFileSync(root+path))});
(async()=>{
 for(const method of ['GET','HEAD','POST','PUT','DELETE','OPTIONS']) {
  const input={url:b.context.location.origin+'/api/v1/bootstrap',method};
  const response=await b.context.window.fetch(input);
  assert.strictEqual(response.status,['GET','HEAD'].includes(method)?200:405,method);
  assert(response.headers.get('Content-Type').startsWith('application/json'),method);
  const text=await response.text();
  if(method==='HEAD') assert.strictEqual(text,'');
  else if(method==='GET') assert.deepStrictEqual(Object.keys(JSON.parse(text)).sort(),
    ['benchmark_cohort','generated_at','publication']);
  else assert.strictEqual(response.headers.get('Allow'),'GET, HEAD');
 }
})().catch(e=>{console.error(e);process.exitCode=1});
"""
    result = subprocess.run(["node", "-e", script, str(root)], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_bootstrap_unavailable_head_has_json_headers_and_empty_body(tmp_path):
    app = Application(tmp_path)
    captured = []
    body = b"".join(
        app(
            dict(REQUEST_METHOD="HEAD", PATH_INFO="/api/v1/bootstrap"),
            lambda status, headers: captured.append((status, dict(headers))),
        )
    )
    assert captured[0][0].startswith("503")
    assert captured[0][1]["Content-Type"].startswith("application/json")
    assert body == b""
    script = r"""
const assert=require('assert'),{browser}=require('./tests/helpers/ui-browser.js');
const b=browser(true,{static:true,fetch:async()=>new Response('{}',{status:503})});
(async()=>{
 const response=await b.context.window.fetch('/api/v1/bootstrap',{method:'HEAD'});
 assert.strictEqual(response.status,503);
 assert(response.headers.get('Content-Type').startsWith('application/json'));
 assert.strictEqual(await response.text(),'');
 const rejected=await b.context.window.fetch('/api/v1/bootstrap',{method:'POST'});
 assert.strictEqual(rejected.status,405);
})().catch(e=>{console.error(e);process.exitCode=1});
"""
    result = subprocess.run(["node", "-e", script], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
