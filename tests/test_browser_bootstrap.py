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
