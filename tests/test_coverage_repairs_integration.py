"""Public-only synthetic sources exercise collection through strict delivery."""

import hashlib
import json
import subprocess
from contextlib import closing

from jsonschema import Draft202012Validator
from test_arista_current_scope import URLS, source
from test_aruba_text_coverage import CVES, signed_text
from test_aruba_text_coverage import URL as ARUBA_URL
from test_coverage_notice_transitions import ROOT, URL, advisory, notice
from test_switching_delivery import request, static_requests

from infrastructure_impact.application import coverage_gaps, switching_comparison
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.collection import archive, service
from infrastructure_impact.http import Application
from infrastructure_impact.settings import PACKAGE
from infrastructure_impact.storage.repository import connect, evidence, latest, now

AT = "2026-11-05T20:00:00Z"


def test_sources_to_study_notice_transition_and_all_delivery_routes(tmp_path, monkeypatch):
    for name, path in {
        "IMPACT_HOME": tmp_path,
        "IMPACT_DATABASE": tmp_path / "vault.sqlite3",
        "IMPACT_SOURCES": tmp_path / "sources.json",
        "IMPACT_PUBLICATIONS": tmp_path / "publications",
        "IMPACT_SNAPSHOT": tmp_path / "snapshot",
    }.items():
        monkeypatch.setenv(name, str(path))
    raw = signed_text().replace(b"CVSSv3 Overall Score: 9.8", b"CVSSv3 Overall Score: 12", 1)
    captures = {ARUBA_URL: raw, URLS["0203"]: source(), URL: notice()}
    config = {
        "vendors": [],
        "pinned": [
            {"vendor": "aruba" if url == ARUBA_URL else "arista", "url": url} for url in captures
        ],
    }
    (tmp_path / "sources.json").write_text(json.dumps(config))

    def fetch(db, url, *_):
        evidence(db, captures[url], url)
        return captures[url]

    monkeypatch.setattr(service, "fetch", fetch)
    database = tmp_path / "vault.sqlite3"
    assert service.run(config, db_path=database) == (2, 0)
    with closing(connect(database)) as db:
        documents = latest(db)
        assert len(documents) == 2
        aruba = next(d for d in documents if d["vendor"] == "aruba")
        assert aruba["cves"] == CVES and len(aruba["assessments"]) == 4
        arista = next(d for d in documents if d["vendor"] == "arista")
        assert [a["status"] for a in arista["assessments"]] == [
            "affected",
            "unaffected",
            "unaffected",
            "investigating",
        ]
        assert arista["metrics"] == []
        private = state(db)
        private["generated_at"] = AT
        generation = publish(private, tmp_path / "publications")
        old_files = {
            p.relative_to(generation): p.read_bytes() for p in generation.rglob("*") if p.is_file()
        }
        snapshot = json.loads((generation / "snapshot.json").read_text())
        assert len(next(d for d in snapshot["records"] if d["vendor"] == "aruba")["metrics"]) == 3
        claims = json.loads((generation / "switching-evidence.json").read_text())["claims"]
        cx = [c for c in claims if c["vendor"] == "aruba"]
        assert len(cx) == 4
        assert [len(c["scores"]) for c in cx] == [0, 1, 1, 1]
        assert "score_invalid" in cx[0]["issues"]

        assert {c["source"]["source_sha256"] for c in cx} == {hashlib.sha256(raw).hexdigest()}
        assert {c["publisher"]["sequence"] for c in cx} == {"3"}
        assert all(not c["platform_bindings"] and c["product_id"] is None for c in cx)
        eos = next(c for c in claims if c["family"] == "arista-eos")
        assert "score_unavailable" in eos["issues"]
        assert all(b["model"] is None for b in eos["platform_bindings"])
        assert "720XP/722XPM" in eos["named_platforms"]
        assert not any(c["source"]["source_url"] == URL for c in claims)
        before = list(db.iterdump())
        gaps = coverage_gaps.report(db, config)
        assert list(db.iterdump()) == before
        Draft202012Validator(
            json.loads((PACKAGE / "schemas/coverage-gaps-v1.json").read_text())
        ).validate(gaps)
        assert (
            next(s for s in gaps["sources"] if s["source_url"] == URL)["triage"][
                "recognized_notice"
            ]
            == 1
        )
        full = json.loads((generation / "switching-comparison.json").read_text())
        selected = switching_comparison.select_report(full, evaluated_at=AT)
        script = (
            "const fs=require('fs'),vm=require('vm');const c={window:{}};vm.createContext(c);for(const f of ['kev','switching-contracts','switching'])vm.runInContext(fs.readFileSync('infrastructure_impact/web/'+f+'.js','utf8'),c);process.stdout.write(JSON.stringify(c.window.InfrastructureSwitching.selectReport(JSON.parse(fs.readFileSync(0,'utf8')),{evaluated_at:'"
            + AT
            + "'})));"
        )
        assert (
            json.loads(
                subprocess.check_output(["node", "-e", script], input=json.dumps(full).encode())
            )
            == selected
        )
        queries = ["", "vendor=aruba", "vendor=arista&scope=model_qualified", "format=csv"]
        browser = static_requests(
            generation, ["/api/v1/switching-comparison?" + q for q in queries]
        )
        for query, response in zip(queries, browser):
            code, body = request(
                Application(tmp_path / "publications"), "/api/v1/switching-comparison", query
            )
            assert code == response["status"] == 200
            if query == "format=csv":
                assert body.decode() == response["body"]
            else:
                native, static = json.loads(body), json.loads(response["body"])
                native.pop("evaluated_at")
                static.pop("evaluated_at")
                assert native == static
        # The ordinary collector revisits the retained notice at the same URL.
    captures[URL] = advisory()
    assert service.run(config, db_path=database) == (1, 0)
    with closing(connect(database)) as db:
        assert len(latest(db)) == 3
        private = state(db)
        private["generated_at"] = AT
        publish(private, tmp_path / "publications")
    assert all((generation / p).read_bytes() == content for p, content in old_files.items())


def test_gap_inventory_distinguishes_positive_notice_from_transport_failure(tmp_path):
    with closing(connect(tmp_path / "vault.sqlite3")) as db:
        db.execute(
            "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
            ("arista", ROOT, "listing", now()),
        )
        source_row = dict(db.execute("SELECT * FROM archive_sources").fetchone())
        archive.enqueue(db, source_row["id"], "document", URL)
        item = dict(db.execute("SELECT * FROM archive_items").fetchone())
        archive.document(db, source_row, item, fetcher=lambda *_: notice())
        denied = ROOT + "/synthetic-denied"
        archive.enqueue(db, source_row["id"], "document", denied)
        db.execute(
            "UPDATE archive_items SET state='error',error_code='access_denied' WHERE url=?",
            (denied,),
        )
        db.commit()
        before = list(db.iterdump())
        result = coverage_gaps.report(db, {"vendors": []})
        assert list(db.iterdump()) == before
        row = result["sources"][0]
        assert row["queue"]["not_applicable"] == row["triage"]["recognized_notice"] == 1
        assert row["queue"]["retrieval_failures"] == 1
        assert row["current"]["parsed_advisories"] == 0


def test_recognized_cisco_notice_keeps_own_html_before_advertised_csaf(tmp_path, monkeypatch):
    from test_coverage_notice_transitions import CISCO_URL, cisco_notice

    from infrastructure_impact.collection.retained import retained_fetch

    raw = cisco_notice(
        lambda s: s.replace("</footer>", '</footer><a href="/synthetic/csaf/notice.json">CSAF</a>')
    )

    def fetch(db, url, *_):
        assert url == CISCO_URL, "A recognized notice must not fetch another representation"
        evidence(db, raw, url)
        return raw

    monkeypatch.setattr(service, "fetch", fetch)
    config = {"vendors": [], "pinned": [{"vendor": "cisco", "url": CISCO_URL}]}
    database = tmp_path / "notices.sqlite3"
    assert service.run(config, db_path=database) == (0, 0)
    with closing(connect(database)) as db:
        assert latest(db) == []
        assert retained_fetch(db, CISCO_URL, "cisco") == raw
        before = list(db.iterdump())
        result = coverage_gaps.report(db, config)
        assert list(db.iterdump()) == before
        row = result["sources"][0]
        assert row["triage"]["recognized_notice"] == 1
        assert row["current"]["parsed_advisories"] == 0
        assert row["health"]["outcome"] == "not_applicable"


def test_unrecognized_cisco_article_still_resolves_advertised_structured_source(tmp_path):
    from test_coverage_notice_transitions import CISCO_URL, cisco_notice

    raw = cisco_notice(
        lambda s: s.replace("Informational", "High").replace(
            "</footer>", '</footer><a href="/synthetic/csaf/advisory.json">CSAF</a>'
        )
    )
    structured = advisory()
    target = "https://sec.cloudapps.cisco.com/synthetic/csaf/advisory.json"
    with closing(connect(tmp_path / "sources.sqlite3")) as db:
        resolved = service.resolve_document(
            db,
            CISCO_URL,
            "cisco",
            fetcher=lambda _db, url, _vendor: {CISCO_URL: raw, target: structured}[url],
        )
    assert resolved == (target, structured)
