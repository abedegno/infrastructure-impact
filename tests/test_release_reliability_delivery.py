"""Generation-bound optional release catalogue delivery."""

import json

import pytest
from test_static_delivery import dataset

from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.publication_reader import PublicationReader
from infrastructure_impact.http import Application


@pytest.fixture(params=["v1", "v2"])
def generation(request, tmp_path):
    root = tmp_path / request.param
    path = publish(dataset(), root, publication_format=request.param)
    return root, path, request.param


def test_report_is_separate_generation_bound_root(generation):
    _, path, version = generation
    report = json.loads((path / "release-reliability.json").read_text())
    review = json.loads((path / "release-reliability-review.json").read_text())
    assert report["publication"] == review["publication"]
    assert report["generated_at"] == review["generated_at"]
    assert review["items"] == report["review_packet"]
    assert (path / "release-reliability.csv").read_text().strip()
    if version == "v2":
        reader = PublicationReader(path)
        assert reader.release_reliability() == report
        assert ("release_reliability",) not in reader.ranges("runtime-snapshot")
        assert ("release_reliability",) not in reader.ranges("snapshot.json")
    else:
        assert "release_reliability" not in json.loads((path / "snapshot.json").read_text())
        index = json.loads((path / "data/index.json").read_text())
        common = json.loads((path / index["bootstrap"]["path"]).read_text())["data"]
        assert "release_reliability" not in common


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_scientific_publication_retains_bounded_default_context_and_lazy_browser_reader(
    tmp_path, version
):
    from infrastructure_impact.application.release_reliability import validate_published_report

    root = tmp_path / version
    path = publish(dataset(), root, publication_format=version, include_switching_analysis=True)
    report = json.loads((path / "release-reliability.json").read_text())
    validate_published_report(report)
    assert report["published_staircase_version"] == 1
    assert report["upgrade_selection"]["kind"] == "configured_staircases"
    assert report["upgrade_selection"]["start"] == "2024-01-01"
    assert report["upgrade_selection"]["end"] == "2026-12-31"
    assert report["upgrade_selection"]["trains"] == [
        dict(vendor="cisco", train="17.12"),
        dict(vendor="aruba", train="10.13"),
        dict(vendor="arista", train="4.33"),
    ]
    if version == "v2":
        assert PublicationReader(path).release_reliability() == report
    status, _, raw = Application(root).route(
        {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/release-reliability"}
    )
    assert status == 200 and json.loads(raw) == report
    # Exercise the actual indexed reader, its retry path and owned return copies.
    test_browser_optional_reader_retries_failed_validation_and_returns_owned_copy(
        (root, path, version)
    )


def test_api_base_report_and_query_boundary(generation):
    root, path, _ = generation
    app = Application(root)
    status, _, body = app.route(
        {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/release-reliability"}
    )
    assert status == 200
    assert json.loads(body) == json.loads((path / "release-reliability.json").read_text())
    status, content, body = app.route(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/v1/release-reliability",
            "QUERY_STRING": "format=csv",
        }
    )
    assert (status, content) == (200, "text/csv")
    assert body == (path / "release-reliability.csv").read_bytes()
    result = []
    list(
        app(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/v1/release-reliability",
                "QUERY_STRING": "vendor=cisco",
            },
            lambda status, headers: result.append(status),
        )
    )
    assert result == ["400 Bad Request"]


def test_projection_ignores_supplied_report():
    from infrastructure_impact.application.publication import public_projection

    source = dataset()
    source["release_reliability"] = {"private": "PRIVATE_REPORT_SENTINEL"}
    projected = public_projection(source)
    assert "private" not in projected["release_reliability"]
    assert source["release_reliability"] == {"private": "PRIVATE_REPORT_SENTINEL"}


def test_missing_legacy_root_is_unavailable(generation):
    root, path, version = generation
    if version == "v2":
        reader = PublicationReader(path)
        reader.catalog["roots"].pop("release-reliability.json")
        assert reader.release_reliability() is None
        report = Application(root)._release_reliability({"QUERY_STRING": ""}, path, reader)
    else:
        (path / "release-reliability.json").unlink()
        manifest_path = path / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["sha256"].pop("release-reliability.json")
        manifest_path.write_text(json.dumps(manifest))
        report = Application(root).route(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/release-reliability"}
        )
    assert report[0] == 200
    assert json.loads(report[2])["catalogue"] is None


def test_selected_annotations_do_not_change_metrics(generation):
    root, _, _ = generation
    app = Application(root)
    request = {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/release-reliability"}
    base = json.loads(app.route(request)[2])
    selected = json.loads(
        app.route(dict(request, QUERY_STRING="include_upgrades=1&vendor=cisco"))[2]
    )
    assert selected["annual"] == base["annual"]
    assert selected["respins"] == base["respins"]
    assert selected["publication"] == base["publication"]
    assert selected["upgrade_selection"] is not None


def test_browser_optional_reader_retries_failed_validation_and_returns_owned_copy(generation):
    import subprocess

    from infrastructure_impact.settings import PACKAGE

    _, path, _ = generation
    script = r"""
const fs=require('fs'),vm=require('vm'),{webcrypto}=require('crypto');
const x=JSON.parse(fs.readFileSync(0,'utf8'));
const c={window:{},Set,Map,URL,Response,Blob,TextEncoder,TextDecoder,Uint8Array,AbortController,AbortSignal,DOMException,setTimeout,clearTimeout,crypto:webcrypto};
vm.createContext(c);
for(const f of ['lossless-json.js','switching-contracts.js','current-evidence.js','kev.js','publication-v2.js','release-reliability.js','delivery.js'])vm.runInContext(fs.readFileSync(x.web+'/'+f,'utf8'),c);
const requests=[];
const fetch=async p=>{requests.push(p);const file=x.root+'/'+p.replace('/site/','');return fs.existsSync(file)?new Response(fs.readFileSync(file)):new Response('',{status:404});};
(async()=>{
 const load=await c.createStaticDelivery(fetch,'/site/');
 const api=c.window.InfrastructureReleaseReliability, original=api.validate;
 let failed=false; api.validate=(...args)=>{if(!failed){failed=true;throw Error('injected validation failure');}return original(...args);};
 try{await load.releaseReliability();throw Error('Expected failure');}catch(e){if(e.message!=='injected validation failure')throw e;}
 const report=await load.releaseReliability();
 if(!report||!failed)throw Error('Missing report');
 report.annual.length=0;report.limitations.push('PRIVATE_MUTATION');
 const next=await load.releaseReliability();
 if(next.limitations.includes('PRIVATE_MUTATION'))throw Error('Shared mutable report');
 if(requests.some(p=>p.endsWith('switching-analysis.json')||p.endsWith('snapshot.json')))throw Error('Hydrated study');
 process.stdout.write(JSON.stringify(next));
})().catch(e=>{console.error(e);process.exitCode=1});
"""
    result = subprocess.run(
        ["node", "-e", script],
        input=json.dumps({"root": str(path), "web": str(PACKAGE / "web")}),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == json.loads((path / "release-reliability.json").read_text())


def test_v2_foreign_report_rejected_before_loading_tables(generation, tmp_path):
    import shutil

    _, path, version = generation
    if version != "v2":
        pytest.skip("v2 identity-first reader")
    foreign = publish(dataset(), tmp_path / "foreign", publication_format="v2")
    reader = PublicationReader(path)
    other = PublicationReader(foreign)
    descriptor = other.catalog["roots"]["release-reliability.json"]
    reader.catalog["roots"]["release-reliability.json"] = descriptor
    shutil.copyfile(foreign / descriptor["path"], path / descriptor["path"])
    with pytest.raises(ValueError, match="mixed publication generation"):
        reader.release_reliability()
    assert reader._strings is None
    assert reader._shapes is None


def test_writer_rejects_selected_analysis_as_persisted_base(generation, tmp_path):
    from infrastructure_impact.application.publication import write_reliability_assets

    root, _, _ = generation
    status, _, raw = Application(root).route(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/v1/release-reliability",
            "QUERY_STRING": "include_upgrades=1&vendor=cisco",
        }
    )
    assert status == 200
    selected = json.loads(raw)
    with pytest.raises(ValueError, match="selected analysis"):
        write_reliability_assets(
            tmp_path,
            {
                "publication": selected["publication"],
                "generated_at": selected["generated_at"],
                "release_reliability": selected,
            },
        )


def test_v1_legacy_without_manifest_returns_unavailable(tmp_path):
    path = publish(dataset(), tmp_path, publication_format="v1")
    (path / "release-reliability.json").unlink()
    (path / "manifest.json").unlink()
    status, _, raw = Application(tmp_path).route(
        {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/release-reliability"}
    )
    assert status == 200
    report = json.loads(raw)
    assert report["availability"] == "unavailable"
    assert report["catalogue"] is None
