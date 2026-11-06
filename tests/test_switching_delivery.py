"""Synthetic native/static study delivery; no vendor captures."""

import copy
import json
import subprocess

import pytest
from test_kev_delivery import ADAPTER, request
from test_kev_delivery import collected as collected

from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.application.publication import publish, write_bundle
from infrastructure_impact.http import Application
from infrastructure_impact.settings import PACKAGE

FIXTURE = json.loads((PACKAGE.parent / "tests/fixtures/switching-cases.json").read_text())


def static_requests(root, queries):
    script = ADAPTER.replace(
        "'kev.js','research", "'kev.js','switching.js','research"
    )
    return json.loads(
        subprocess.check_output(
            ["node", "-e", script],
            input=json.dumps(
                dict(root=str(root), web=str(PACKAGE / "web"), queries=queries)
            ).encode(),
        )
    )


@pytest.fixture
def study(collected):
    collected["research"]["switching_input"] = copy.deepcopy(
        FIXTURE["comparison_base_report"]["inputs"]["evidence"]
    )
    return collected


def test_current_malformed_is_not_legacy():
    report = copy.deepcopy(FIXTURE["comparison_base_report"])
    report["inputs"] = None
    with pytest.raises((ValueError, TypeError)):
        comparison.select_report(report)


def test_selected_source_closure_is_validated():
    report = copy.deepcopy(FIXTURE["comparison_base_report"])
    report["sources"] = []
    with pytest.raises(ValueError, match="source|provenance"):
        evidence.validate_comparison(report)


def test_native_static_study_contract(study, tmp_path):
    root = tmp_path / "public"
    generation = publish(study, root)
    data = json.loads((generation / "snapshot.json").read_text())
    full = json.loads((generation / "switching-comparison.json").read_text())
    evidence.validate_comparison(
        full, publication=data["publication"], generated_at=data["generated_at"]
    )
    assert full["inputs"]["evidence"] == json.loads(
        (generation / "switching-evidence.json").read_text()
    )
    index = json.loads((generation / "data/index.json").read_text())
    bootstrap = json.loads((generation / index["bootstrap"]["path"]).read_text())["data"]
    assert "switching_comparison" not in bootstrap and "switching_evidence" not in bootstrap
    assert data["switching_comparison"]["representation"] == "summary"
    assert "inputs" not in data["switching_comparison"]
    queries = [
        "",
        "vendor=arista",
        "scope=model_qualified&window=post",
        "cves=CVE-1999-99999",
        "format=csv",
        "vendor=",
        "vendor=arista&vendor=arista",
        "kev=listed",
        "scope=no",
        "window=2020",
        "cves=cve-2025-12345",
        "cves=",
        "format=other",
        "unknown=x",
    ]
    urls = ["/api/v1/switching-comparison?" + q for q in queries]
    browser = static_requests(generation, urls)
    app = Application(root)
    for q, response in zip(queries, browser):
        code, raw = request(app, "/api/v1/switching-comparison", q)
        assert response["status"] == code, (q, response, raw)
        if q == "format=csv":
            assert response["body"] == raw.decode()
        else:
            a, b = json.loads(raw), json.loads(response["body"])
            a.pop("evaluated_at", None)
            b.pop("evaluated_at", None)
            assert a == b, q
    assert browser[0]["status"] == 200
    assert json.loads(browser[3]["body"])["selection"]["effective_cve_ids"] == []
    assert all(r["status"] == 400 for r in browser[5:])
    for name in [
        "switching.js",
        "switching-view.js",
        "switching-study.json",
        "schemas/switching-summary-v1.json",
        "switching-evidence.json",
        "switching-comparison.json",
    ]:
        assert request(app, "/" + name)[0] == 200
    manifest = json.loads((generation / "manifest.json").read_text())["sha256"]
    html = (generation / "index.html").read_text()
    ordered = [
        "switching-contracts.js",
        "switching.js",
        "switching-view.js",
        "snapshot.js",
        "app.js",
    ]
    positions = [html.index("assets/" + manifest[name] + ".js") for name in ordered]
    assert positions == sorted(positions)
    damaged = copy.deepcopy(data)
    damaged["switching_comparison"] = copy.deepcopy(full)
    damaged["switching_evidence"] = copy.deepcopy(full["inputs"]["evidence"])
    damaged["switching_evidence"]["publication"]["id"] = "e" * 32
    with pytest.raises(ValueError):
        write_bundle(tmp_path / "invalid", damaged)
    assert not (tmp_path / "invalid").exists()


def test_manifest_and_score_metadata_allowlist(study):
    from infrastructure_impact.application.publication import public_projection
    from infrastructure_impact.application.query import merge_switching_manifest

    source = (
        "https://www.arista.com/en/support/advisories-notices/security-advisory/synthetic-index"
    )
    entry = dict(
        vendor="arista",
        source_url=source,
        definition_sha256=evidence.definition_sha256(evidence.definition()),
        source_kind="listing",
        window={"start_date": "2021-01-01", "end_date": "2026-11-04"},
        coverage_state="blocked",
        portfolio_completeness="not_established",
        gaps=["pre_2022_history_not_enumerated"],
        expected_total=None,
        unknown_dates=2,
        unknown_models=3,
        retrieval_failed=1,
        errors=["network_error"],
        private_path="/private/sentinel",
    )
    merge_switching_manifest(study["research"]["switching_input"], {"entries": [entry]})
    study["records"][0].update(
        vendor="arista",
        advisory_id="SOURCE-ONLY",
        source_url=source,
        cves=["CVE-2025-12345"],
        assessments=[],
    )
    study.pop("current_evidence")  # Synthetic source ownership was deliberately changed.
    study["research"]["score_input"] = {
        "advisories": [
            dict(
                vendor="arista",
                advisory_id="SOURCE-ONLY",
                source_url=source,
                claims=[],
                issues=[{"code": "score_format_unsupported", "details": "PRIVATE_SENTINEL"}],
            )
        ],
        "fallback": {
            "claims": [],
            "attempts": [
                dict(
                    source="nvd",
                    cve_id="CVE-2025-12345",
                    state="network_error",
                    checked_at=None,
                    retry_at=None,
                    headers="PRIVATE_SENTINEL",
                )
            ],
        },
    }
    result = public_projection(study)["switching_evidence"]
    row = next(c for c in result["coverage"] if c["source_url"] == source)
    assert row["observed_start"] is None and row["total"] is None
    assert row["enumeration"]["expected_total"] is None
    assert row["enumeration"]["retrieved"] is None
    assert row["enumeration"]["retrieval_failed"] == 1
    assert row["enumeration"]["gaps"] == ["network_error", "pre_2022_history_not_enumerated"]
    metadata = result["score_availability"][0]
    assert metadata["context"] == "source_only_unclassified"
    assert metadata["source"] is None and metadata["state"] == "unavailable"
    assert metadata["attempts"][0]["state"] == "network_error"
    assert "PRIVATE_SENTINEL" not in json.dumps(result) and "/private/sentinel" not in json.dumps(
        result
    )


DELIVERY = r"""
const fs=require('fs'),vm=require('vm'),{webcrypto}=require('crypto');
const x=JSON.parse(fs.readFileSync(0,'utf8')),requests=[];
const c={window:{},Set,Map,URL,Response,TextEncoder,TextDecoder,Uint8Array,crypto:webcrypto};vm.createContext(c);
for(const f of ['lossless-json.js','switching-contracts.js','current-evidence.js','kev.js','switching.js','delivery.js'])vm.runInContext(fs.readFileSync(x.web+'/'+f,'utf8'),c);
(async()=>{try{const load=await c.createStaticDelivery(async path=>{requests.push(path);let raw=fs.readFileSync(x.root+path);if(x.fault==='hash' && path===x.part)raw=Buffer.concat([raw.subarray(0,raw.length-1),Buffer.from(' ')]);return new Response(raw);},'/');let cacheReuse=null;if(x.mode==='reuse'){const first=await load.switchingReport(),count=requests.length;const second=await load.switchingReport();const selected=c.window.InfrastructureSwitching.selectReport(first,{scope_level:'model_qualified'});const ids=first.rows.flatMap(r=>r.claim_ids).slice(0,25);await load.switchingClaims(ids);cacheReuse={same:first===second,frozen:Object.isFrozen(first.inputs.evidence.claims[0]),shared:selected.inputs===first.inputs,extraFetches:requests.length-count};}let value=x.mode==='claims'?await load.switchingClaims(x.ids):x.mode==='summary'?await load.switchingSummary():await load.switchingReport();process.stdout.write(JSON.stringify({value,requests,cacheReuse}));}catch(e){process.stdout.write(JSON.stringify({error:e.message,requests}));}})();
"""


def delivery(root, **options):
    return json.loads(
        subprocess.check_output(
            ["node", "-e", DELIVERY],
            input=json.dumps(dict(root=str(root), web=str(PACKAGE / "web"), **options)).encode(),
        )
    )


def test_shards_hydrate_exactly_and_drilldown_is_lazy(study, tmp_path, monkeypatch):
    import hashlib

    from infrastructure_impact.application import static_delivery

    monkeypatch.setattr(static_delivery, "TARGET_BYTES", 2500)
    generation = publish(study, tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    parts = index["switching"]["claims"]
    assert len(parts) > 1
    report = json.loads((generation / "switching-comparison.json").read_text())
    hydrated = delivery(generation)
    assert hydrated["value"] == report
    assert "/snapshot.json" not in hydrated["requests"]
    selected = delivery(generation, mode="claims", ids=parts[0]["claim_ids"])
    expected = [
        "/data/index.json",
        "/" + index["bootstrap"]["path"],
        "/" + parts[0]["part"]["path"],
    ]
    assert selected["requests"] == expected
    assert {c["claim_id"] for c in selected["value"]} == set(parts[0]["claim_ids"])
    assert (
        "fingerprint"
        in delivery(generation, fault="hash", part="/" + parts[0]["part"]["path"])["error"]
    )
    # Rehashing a foreign generation does not evade identity checks.
    descriptor = parts[0]["part"]
    payload = json.loads((generation / descriptor["path"]).read_text())
    payload["publication"]["id"] = "d" * 32
    raw = static_delivery.encode(payload)
    digest = hashlib.sha256(raw).hexdigest()
    descriptor.update(path="data/" + digest + ".json", sha256=digest, bytes=len(raw))
    (generation / descriptor["path"]).write_bytes(raw)
    (generation / "data/index.json").write_bytes(static_delivery.encode(index))
    assert "generation" in delivery(generation)["error"].lower()


def test_legacy_missing_study_is_503(study, tmp_path):
    study["research"].pop("switching_input")
    generation = publish(study, tmp_path)
    assert "switching" not in json.loads((generation / "data/index.json").read_text())
    urls = ["/api/v1/switching-comparison", "/api/v1/switching-comparison?kev=listed"]
    for url, browser in zip(urls, static_requests(generation, urls)):
        path, _, query = url.partition("?")
        code, body = request(Application(tmp_path), path, query)
        assert browser["status"] == code
        assert json.loads(browser["body"]) == json.loads(body)
    assert request(Application(tmp_path), urls[0])[0] == 503


def test_failed_write_keeps_pointer_and_oversized_row_fails(study, tmp_path, monkeypatch):
    from infrastructure_impact.application import static_delivery

    generation = publish(study, tmp_path)
    before = (tmp_path / "current").resolve()
    # A single bounded evidence row still must fit the hard delivery maximum.
    monkeypatch.setattr(static_delivery, "MAX_PART_BYTES", 100)
    with pytest.raises(ValueError, match="8 MB"):
        publish(study, tmp_path)
    assert (tmp_path / "current").resolve() == before == generation
    assert not list((tmp_path / "generations").glob(".staging-*"))


def test_public_assets_are_sanitized_and_monitor_compact(study, tmp_path):
    from infrastructure_impact.exports import switching_csv

    study["research"]["switching_input"]["private"] = "PRIVATE_SENTINEL /private/operator"
    generation = publish(study, tmp_path)
    for file in generation.rglob("*"):
        if file.is_file() and file.suffix in (".json", ".js", ".html", ".csv"):
            content = file.read_text()
            assert "PRIVATE_SENTINEL" not in content and "/private/operator" not in content
            assert '"switching_input"' not in content and '"score_input"' not in content
    code, raw = request(Application(tmp_path), "/api/state", "cves=CVE-2025-12345")
    monitor = json.loads(raw)
    assert code == 200 and len(raw) < 20_000_000
    assert "switching_evidence" not in monitor
    assert "inputs" not in monitor["switching_comparison"]
    report = json.loads((generation / "switching-comparison.json").read_text())
    # Formula controls are escaped even after leading whitespace.
    report["rows"][0]["severity"] = [
        dict(
            version="3.1",
            provider=" \t=synthetic()",
            origin="@source",
            preferred=True,
            band="High",
            count=1,
        )
    ]
    browser = subprocess.check_output(
        [
            "node",
            "-e",
            "const fs=require('fs'),vm=require('vm');const c={window:{}};vm.createContext(c);vm.runInContext(fs.readFileSync('infrastructure_impact/web/switching.js','utf8'),c);process.stdout.write(c.window.InfrastructureSwitching.csvExport(JSON.parse(fs.readFileSync(0,'utf8'))));",
        ],
        input=json.dumps(report).encode(),
    ).decode()
    assert browser == switching_csv(report)
    assert "' \t=synthetic()" in browser and "'@source" in browser
    full_before = json.loads(
        static_requests(generation, ["/api/v1/switching-comparison"])[0]["body"]
    )
    selected = static_requests(
        generation,
        [
            "/api/state?cves=" + ",".join(study["benchmark_cohort"]) + "&kev=listed",
            "/api/v1/switching-comparison",
        ],
    )[-1]
    full_after = json.loads(selected["body"])
    full_before.pop("evaluated_at")
    full_after.pop("evaluated_at")
    assert full_after == full_before


def test_real_oversized_study_claim_aborts_atomically(study, tmp_path):
    generation = publish(study, tmp_path)
    claim = study["research"]["switching_input"]["claims"][0]
    claim["conditions"] = [str(i) + "x" * 3890 for i in range(2100)]
    with pytest.raises(ValueError, match="8 MB"):
        publish(study, tmp_path)
    assert (tmp_path / "current").resolve() == generation


def test_native_rejects_valid_foreign_study_generation(study, tmp_path):
    first = publish(study, tmp_path)
    second = publish(study, tmp_path)
    (second / "switching-comparison.json").write_bytes(
        (first / "switching-comparison.json").read_bytes()
    )
    code, body = request(Application(tmp_path), "/api/v1/switching-comparison")
    assert code == 503
    assert json.loads(body) == {"error": "Publication temporarily unavailable"}


def test_query_projection_joins_manifest_read_only(tmp_path, monkeypatch):
    from infrastructure_impact.application.publication import public_projection
    from infrastructure_impact.application.query import state
    from infrastructure_impact.storage.repository import connect

    path = tmp_path / "synthetic.sqlite"
    with connect(path):
        pass
    entry = dict(
        vendor="arista",
        source_url="https://www.arista.com/en/support/advisories-notices",
        definition_sha256=evidence.definition_sha256(evidence.definition()),
        source_kind="listing",
        window={"start_date": "2021-01-01", "end_date": "2026-11-04"},
        coverage_state="partial",
        portfolio_completeness="not_established",
        gaps=[],
        page_evidence=[{"retrieved_at": "2026-11-03T23:30:00-02:00"}],
    )
    monkeypatch.setattr(
        "infrastructure_impact.collection.switching_backfill.manifest",
        lambda *args, **kwargs: {"entries": [entry]},
    )
    with connect(path, read_only=True) as db:
        before = db.total_changes
        result = public_projection(state(db))
        assert db.total_changes == before
    coverage = result["switching_evidence"]["coverage"][0]
    assert coverage["observed_start"] == coverage["observed_end"] == "2026-11-04"
    assert coverage["enumeration"]["window"]["start_date"] == "2021-01-01"
    assert coverage["enumeration"]["expected_total"] is None


def test_selector_unicode_identity_and_legacy_parity():
    from test_switching_comparison import claim, report

    reports = [report([claim(identity="\U00010000"), claim(identity="\ue000")]), None]
    script = "const fs=require('fs'),vm=require('vm');const c={window:{}};vm.createContext(c);for(const f of ['kev','switching-contracts','switching'])vm.runInContext(fs.readFileSync('infrastructure_impact/web/'+f+'.js','utf8'),c);process.stdout.write(JSON.stringify(JSON.parse(fs.readFileSync(0,'utf8')).map(r=>c.window.InfrastructureSwitching.selectReport(r,{evaluated_at:'2026-11-04T10:00:00Z'}))));"
    browser = json.loads(
        subprocess.check_output(["node", "-e", script], input=json.dumps(reports).encode())
    )
    assert browser == [
        comparison.select_report(r, evaluated_at="2026-11-04T10:00:00Z") for r in reports
    ]


def test_pre_study_generation_remains_readable_and_utc_end(study, tmp_path):
    study["generated_at"] = "2000-01-01T00:00:00Z"
    study["current_evidence"]["generated_at"] = study["generated_at"]
    generation = publish(study, tmp_path)
    assert not (generation / "switching-comparison.json").exists()
    assert request(Application(tmp_path), "/api/v1/switching-comparison")[0] == 503
    study["generated_at"] = "2026-12-31T23:30:00-02:00"
    study["current_evidence"]["generated_at"] = study["generated_at"]
    generation = publish(study, tmp_path)
    report = json.loads((generation / "switching-comparison.json").read_text())
    assert report["observation_end"] == "2027-01-01"
    assert request(Application(tmp_path), "/api/v1/switching-comparison", "window=2027")[0] == 200
    assert (
        static_requests(generation, ["/api/v1/switching-comparison?window=2027"])[0]["status"]
        == 200
    )


def test_shared_selections_through_installed_adapters(study, tmp_path):
    from urllib.parse import urlencode

    generation = publish(study, tmp_path)
    queries = []
    for case in FIXTURE["comparison_cases"]:
        values = {
            {"scope_level": "scope", "cve_ids": "cves"}.get(k, k): (
                ",".join(v) if v else "CVE-1999-99999"
            )
            if k == "cve_ids"
            else v
            for k, v in case["options"].items()
            if k != "evaluated_at"
        }
        queries.append(urlencode(values))
    responses = static_requests(generation, ["/api/v1/switching-comparison?" + q for q in queries])
    for query, response in zip(queries, responses):
        code, raw = request(Application(tmp_path), "/api/v1/switching-comparison", query)
        assert code == response["status"] == 200
        native, browser = json.loads(raw), json.loads(response["body"])
        native.pop("evaluated_at")
        browser.pop("evaluated_at")
        assert native == browser


@pytest.mark.parametrize(
    "fault", ["definition", "evidence_version", "evidence_extra", "kev_version", "claim_extra"]
)
def test_browser_rejects_current_contract_tampering(fault):
    from jsonschema import ValidationError

    report = copy.deepcopy(FIXTURE["comparison_base_report"])
    if fault == "definition":
        report["definition"]["references"][0]["reviewed_at"] = "2026-11-03"
    elif fault == "evidence_version":
        report["inputs"]["evidence"]["schema_version"] = 999
    elif fault == "evidence_extra":
        report["inputs"]["evidence"]["unrecognized_field"] = True
    elif fault == "kev_version":
        report["inputs"]["kev"]["schema_version"] = 999
    else:
        report["inputs"]["evidence"]["claims"][0]["unrecognized_field"] = True
    with pytest.raises((ValueError, ValidationError)):
        comparison.select_report(report)
    script = "const fs=require('fs'),vm=require('vm');const c={window:{}};vm.createContext(c);for(const f of ['kev','switching-contracts','switching'])vm.runInContext(fs.readFileSync('infrastructure_impact/web/'+f+'.js','utf8'),c);try{c.window.InfrastructureSwitching.selectReport(JSON.parse(fs.readFileSync(0,'utf8')));process.stdout.write('accepted');}catch{process.stdout.write('rejected');}"
    assert (
        subprocess.check_output(["node", "-e", script], input=json.dumps(report).encode()).decode()
        == "rejected"
    )


def rehash_part(generation, descriptor, mutate):
    from hashlib import sha256

    from infrastructure_impact.application.static_delivery import encode

    value = json.loads((generation / descriptor["path"]).read_text())
    mutate(value["data"])
    raw = encode(value)
    digest = sha256(raw).hexdigest()
    descriptor.update(path="data/" + digest + ".json", sha256=digest, bytes=len(raw))
    (generation / descriptor["path"]).write_bytes(raw)


@pytest.mark.parametrize(
    "fault",
    [
        "summary_generation",
        "summary_extra",
        "summary_definition",
        "header_version",
        "header_extra",
        "header_definition",
        "metadata_extra",
        "index_null",
        "index_false",
    ],
)
def test_loaders_reject_rehashed_inner_contract_tampering(study, tmp_path, fault):
    generation = publish(study, tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    if fault.startswith("summary"):

        def mutate(value):
            if fault == "summary_generation":
                value["publication"]["id"] = "d" * 32
            elif fault == "summary_extra":
                value["unexpected"] = True
            else:
                value["definition"]["references"][0]["reviewed_at"] = "2026-11-03"

        rehash_part(generation, index["switching"]["summary"], mutate)
        mode = "summary"
    elif fault.startswith("header"):

        def mutate(value):
            if fault == "header_version":
                value["evidence"]["schema_version"] = 999
            elif fault == "header_extra":
                value["evidence"]["coverage"] = []
            else:
                value["evidence"]["definition_sha256"] = "d" * 64

        rehash_part(generation, index["switching"]["inputs"], mutate)
        mode = "report"
    elif fault in ("index_null", "index_false"):
        index["switching"] = None if fault == "index_null" else False
        mode = "summary"
    else:
        # Strict optional metadata is checked before reconstruction returns.
        index["switching"]["has_score_availability"] = "yes"
        mode = "report"
    (generation / "data/index.json").write_text(json.dumps(index))
    assert "error" in delivery(generation, mode=mode)


@pytest.mark.parametrize("mode", ["report", "claims"])
@pytest.mark.parametrize("fault", ["duplicate_actual", "duplicate_declared", "wrong_membership"])
def test_claim_parts_require_exact_unique_membership(study, tmp_path, mode, fault):
    generation = publish(study, tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    part = index["switching"]["claims"][0]
    assert len(part["claim_ids"]) > 1
    requested = part["claim_ids"][:1]
    if fault == "duplicate_declared":
        part["claim_ids"][1] = part["claim_ids"][0]
    else:

        def mutate(value):
            if fault == "duplicate_actual":
                value[1] = copy.deepcopy(value[0])
            else:
                value[1]["claim_id"] = "d" * 64

        rehash_part(generation, part["part"], mutate)
    (generation / "data/index.json").write_text(json.dumps(index))
    assert "error" in delivery(generation, mode=mode, ids=requested)


def test_browser_contract_bundle_matches_packaged_schemas():
    import runpy

    source = (PACKAGE / "web/switching-contracts.js").read_text()
    raw = source.split("/* BEGIN GENERATED CONTRACTS */", 1)[1].split(
        "/* END GENERATED CONTRACTS */", 1
    )[0]
    generate = runpy.run_path(str(PACKAGE.parent / "checks/generate_switching_contracts.py"))
    assert json.loads(raw.strip().removesuffix(";")) == generate["payload"]()


@pytest.mark.parametrize("fault", ["definition", "evidence_version", "evidence_extra"])
def test_native_static_adapter_reject_same_current_contract(study, tmp_path, fault):
    generation = publish(study, tmp_path)
    report = json.loads((generation / "switching-comparison.json").read_text())
    index = json.loads((generation / "data/index.json").read_text())
    if fault == "definition":
        report["definition"]["references"][0]["reviewed_at"] = "2026-11-03"

        def mutate(value):
            value["definition"]["references"][0]["reviewed_at"] = "2026-11-03"

        descriptor = index["switching"]["summary"]
    else:

        def mutate(value):
            value["evidence"][
                "schema_version" if fault == "evidence_version" else "unrecognized_field"
            ] = 999

        report["inputs"]["evidence"][
            "schema_version" if fault == "evidence_version" else "unrecognized_field"
        ] = 999
        descriptor = index["switching"]["inputs"]
    rehash_part(generation, descriptor, mutate)
    (generation / "switching-comparison.json").write_text(json.dumps(report))
    (generation / "data/index.json").write_text(json.dumps(index))
    code, body = request(Application(tmp_path), "/api/v1/switching-comparison")
    browser = static_requests(generation, ["/api/v1/switching-comparison"])[0]
    assert code == browser["status"] == 503
    assert (
        json.loads(body)
        == json.loads(browser["body"])
        == {"error": "Publication temporarily unavailable"}
    )


@pytest.mark.parametrize("mode", ["report", "claims"])
def test_claim_index_rejects_cross_part_duplicates(study, tmp_path, monkeypatch, mode):
    from infrastructure_impact.application import static_delivery

    monkeypatch.setattr(static_delivery, "TARGET_BYTES", 2500)
    generation = publish(study, tmp_path)
    index = json.loads((generation / "data/index.json").read_text())
    first, second = index["switching"]["claims"][:2]
    second["claim_ids"][0] = first["claim_ids"][0]
    (generation / "data/index.json").write_text(json.dumps(index))
    assert "error" in delivery(generation, mode=mode, ids=first["claim_ids"])


def test_hydration_cache_reused_for_selection_and_detail(study, tmp_path):
    generation = publish(study, tmp_path)
    result = delivery(generation, mode="reuse")
    assert result["cacheReuse"] == dict(same=True, frozen=True, shared=True, extraFetches=0)
