"""Authored synthetic collection baselines: provenance, consistency and privacy."""

import hashlib
import json
from contextlib import closing
from pathlib import Path

import pytest

from infrastructure_impact.reconciliation import baseline
from infrastructure_impact.storage.repository import connect, evidence

CVE = "CVE-2026-12345"
REGISTRY = "https://cveawg.mitre.org/api/cve/" + CVE
PUBLISHER = (
    "https://sec.cloudapps.cisco.com/security/center/content/"
    "CiscoSecurityAdvisory/cisco-sa-synthetic-abc123"
)
ARISTA = "https://www.arista.com/en/support/advisories-notices/security-advisory/12345-security-advisory-9999"
INDEX = "https://csaf.arubanetworking.hpe.com/index.txt"
AT = "2026-11-06T12:00:00+00:00"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def inputs(tmp_path):
    database = tmp_path / "collection.sqlite3"
    config = tmp_path / "sources.json"
    config.write_text(json.dumps({"vendors": [], "pinned": [{"vendor": "cisco", "url": REGISTRY}]}))
    with closing(connect(database)) as db:
        add_revision(db)
        db.commit()
    return database, config


def add_revision(
    db,
    *,
    vendor="cisco",
    url=REGISTRY,
    product="Cisco IOS XE Software",
    cve=CVE,
    advisory="synthetic",
    status="affected",
):
    retained = evidence(db, b"synthetic public source bytes", url)
    normalized = dict(
        schema_version=2,
        vendor=vendor,
        advisory_id=advisory,
        source_url=url,
        advisory_url=PUBLISHER,
        cves=[cve],
        document_status="published",
        published_at="2026-01-01",
        adapter_version="synthetic-1",
        title="PRIVATE_TEXT_SENTINEL",
        notes=[{"text": "PRIVATE_TEXT_SENTINEL"}],
        assessments=[
            dict(
                cve_id=cve,
                product_id="synthetic-product",
                product=product,
                status=status,
                scope="cve_specific",
                versions=[{"version": "1.0"}],
                evidence_locator="/containers/cna/affected/0",
            )
        ],
    )
    db.execute(
        "INSERT INTO revisions(evidence_id,vendor,advisory_id,source_url,observed_at,normalized) "
        "VALUES(?,?,?,?,?,?)",
        (retained["id"], vendor, advisory, url, AT, json.dumps(normalized)),
    )
    return retained["id"]


def export(inputs, tmp_path, name="baseline.json"):
    return baseline.export_baseline(
        database=inputs[0], config_path=inputs[1], output=tmp_path / name
    )


def test_baseline_is_consistent_read_only_and_deterministic(inputs, tmp_path, monkeypatch):
    database, config = inputs
    before = digest(database), digest(config)
    with closing(connect(database, read_only=True)) as db:
        rows = list(db.iterdump())
    first = export(inputs, tmp_path)
    second = export(inputs, tmp_path, "second.json")
    assert first["observed_at"] != second["observed_at"]
    assert first["fingerprint"] == second["fingerprint"]
    assert first["generation"] is None
    assert baseline.load_baseline(tmp_path / "baseline.json") == first
    assert (digest(database), digest(config)) == before
    with closing(connect(database, read_only=True)) as db:
        assert list(db.iterdump()) == rows
    # A second WAL connection commits after the export has pinned its snapshot.
    # Removing BEGIN would make these tables reflect different moments.
    original_connect = baseline.connect
    traces = []
    with closing(connect(database)) as writer:

        def traced_connect(path, *, read_only):
            assert read_only is True
            db = original_connect(path, read_only=read_only)
            committed = False

            def trace(sql):
                nonlocal committed
                traces.append(sql)
                if "FROM evidence" in sql and not committed:
                    assert db.in_transaction
                    committed = True
                    add_revision(
                        writer, url=ARISTA, vendor="arista", product="EOS", advisory="later"
                    )
                    writer.commit()

            db.set_trace_callback(trace)
            return db

        monkeypatch.setattr(baseline, "connect", traced_connect)
        concurrent = export(inputs, tmp_path, "concurrent.json")
    assert len(concurrent["revisions"]) == len(first["revisions"]) == 1
    assert concurrent["fingerprint"] == first["fingerprint"]
    assert "BEGIN" in traces and not any("INSERT" in sql or "CREATE" in sql for sql in traces)
    monkeypatch.setattr(baseline, "connect", original_connect)
    changed = export(inputs, tmp_path, "changed.json")
    assert changed["fingerprint"] != first["fingerprint"]
    assert len(changed["revisions"]) == 2


def test_cve_other_vendor_is_not_target_presence(inputs, tmp_path):
    with closing(connect(inputs[0])) as db:
        add_revision(
            db, vendor="arista", url=ARISTA, product="EOS lookalike", advisory="other-family"
        )
        add_revision(
            db,
            vendor="hpe",
            url="https://support.hpe.com/hpesc/public/docDisplay?docId=a12345en_us",
            product="Cisco IOS XE Software",
            advisory="other-vendor",
        )
        add_revision(db, product="Cisco IOS XEphony", advisory="lookalike")
        add_revision(db, product="NX-OS", advisory="wrong-branch", cve="CVE-2026-54321")
        db.commit()
    data = export(inputs, tmp_path)
    by_id = {r["advisory_id"]: r for r in data["revisions"]}
    assert by_id["other-vendor"]["vendor"] == "hpe"
    assert by_id["other-vendor"]["cves"] == [CVE]
    assert by_id["other-vendor"]["assessments"][0]["families"] == []
    assert by_id["other-family"]["assessments"][0]["families"] == ["arista-eos"]
    assert by_id["lookalike"]["assessments"][0]["families"] == []
    assert by_id["wrong-branch"]["assessments"][0]["families"] == []
    assert by_id["synthetic"]["assessments"][0]["families"] == ["cisco-iosxe"]
    assert by_id["wrong-branch"]["cves"] == ["CVE-2026-54321"]


def test_retained_unparsed_error_pending_and_not_observed_are_distinct(inputs, tmp_path):
    retained_url = INDEX.replace("index.txt", "synthetic.json")
    pending_url = INDEX.replace("index.txt", "pending.json")
    absent_url = INDEX.replace("index.txt", "absent.json")
    inputs[1].write_text(
        json.dumps(
            {
                "vendors": [],
                "pinned": [
                    {"vendor": "aruba", "url": url}
                    for url in [retained_url, pending_url, absent_url]
                ],
            }
        )
    )
    with closing(connect(inputs[0])) as db:
        db.execute(
            "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
            ("aruba", INDEX, "index", AT),
        )
        ev = evidence(db, b"not parsed retained bytes", retained_url)
        for url, state, ev_id in [
            (retained_url, "error", ev["id"]),
            (pending_url, "pending", None),
        ]:
            db.execute(
                "INSERT INTO archive_items(source_id,kind,url,state,evidence_id,discovered_at,error_code) "
                "VALUES(1,?,?,?,?,?,?)",
                (
                    "document",
                    url,
                    state,
                    ev_id,
                    AT,
                    "unsupported_or_invalid_document" if ev_id else None,
                ),
            )
        db.execute(
            "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details,error_code) "
            "VALUES(?,?,?,?,?,?)",
            (
                "aruba",
                retained_url,
                AT,
                "error",
                "PRIVATE_ERROR_SENTINEL",
                "unsupported_or_invalid_document",
            ),
        )
        db.commit()
    data = export(inputs, tmp_path)
    assert any(e["source_url"] == retained_url for e in data["evidence"])
    assert not any(r["source_url"] == retained_url for r in data["revisions"])
    assert [(q["requested_url"], q["state"]) for q in data["queue"]] == [
        (retained_url, "error"),
        (pending_url, "pending"),
    ]
    assert data["source_checks"][0]["error_code"] == "unsupported_or_invalid_document"
    assert absent_url in [s["source_url"] for s in data["configured_sources"]]
    assert absent_url not in [e["source_url"] for e in data["evidence"]]


def test_source_binding_queries_and_aliases_are_exact(inputs, tmp_path):
    root = "https://www.arista.com/en/support/advisories-notices/securityadvisory"
    one, two = root + "?start=10", root + "?start=20"
    with closing(connect(inputs[0])) as db:
        selected = evidence(db, b"synthetic representation", ARISTA)
        requested = evidence(db, b"synthetic wrapper", one)
        db.execute(
            "INSERT INTO source_selections(vendor,requested_url,observed_at,reason,selected_evidence_id) "
            "VALUES(?,?,?,?,?)",
            ("arista", one, AT, "PRIVATE_SELECTION_REASON", selected["id"]),
        )
        for ev in (selected, requested):
            db.execute(
                "INSERT INTO source_selection_views(selection_id,evidence_id,source_format,adapter_version,assessments) "
                "VALUES(1,?,?,?,?)",
                (ev["id"], "html", "1", 1),
            )
        evidence(db, b"different page", two)
        evidence(db, b"credentials", root + "?start=10&token=PRIVATE_TOKEN_SENTINEL")
        db.commit()
    data = export(inputs, tmp_path)
    urls = {e["source_url"] for e in data["evidence"]}
    assert {one, two} <= urls
    selection = data["source_selections"][0]
    assert selection["requested_url"] == one
    assert selection["selected_evidence_id"] != selection["views"][1]["evidence_id"]
    assert {v["evidence_id"] for v in selection["views"]} == {selected["id"], requested["id"]}
    revision = data["revisions"][0]
    assert revision["source_url"] == REGISTRY
    assert revision["advisory_url"] == PUBLISHER
    assert (
        next(e for e in data["evidence"] if e["evidence_id"] == revision["evidence_id"])[
            "source_url"
        ]
        == REGISTRY
    )
    assert PUBLISHER not in urls
    assert data["diagnostics"]["omitted_urls"] >= 1
    assert "PRIVATE_" not in json.dumps(data)


@pytest.mark.parametrize(
    "kind", ["database", "config", "wal", "shm", "journal", "hardlink", "symlink"]
)
def test_inputs_sidecars_hardlinks_and_symlinks_cannot_be_outputs(inputs, tmp_path, kind):
    database, config = inputs
    targets = {
        "database": database,
        "config": config,
        **{key: Path(str(database) + "-" + key) for key in ("wal", "shm", "journal")},
    }
    output = targets.get(kind, tmp_path / "alias.json")
    if kind == "hardlink":
        output.hardlink_to(database)
    elif kind == "symlink":
        output.symlink_to(config)
    before = digest(database), digest(config)
    with pytest.raises(baseline.BaselineError) as caught:
        baseline.export_baseline(database=database, config_path=config, output=output)
    assert caught.value.code == "unsafe_output_path"
    assert (digest(database), digest(config)) == before


def test_private_config_errors_and_paths_never_export(inputs, tmp_path):
    with closing(connect(inputs[0])) as db:
        evidence(
            db,
            b"PRIVATE_BODY_SENTINEL",
            "https://user:PRIVATE_PASSWORD@www.arista.com/arbitrary/private",
        )
        db.execute(
            "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details,error_code) VALUES(?,?,?,?,?,?)",
            (
                "aruba",
                INDEX,
                AT,
                "error",
                "/private/PRIVATE_ERROR_SENTINEL",
                "PRIVATE_ERROR_SENTINEL",
            ),
        )
        db.commit()
    data = export(inputs, tmp_path)
    text = json.dumps(data)
    assert "PRIVATE_" not in text and str(tmp_path) not in text
    assert data["source_checks"][0]["error_code"] == "collection_error"
    assert data["diagnostics"]["omitted_error_details"] == 1
    assert data["config_sha256"] == digest(inputs[1])
    inputs[1].write_text('{"vendors": [], "PRIVATE_CONFIG_SENTINEL": "password"}')
    with pytest.raises(baseline.BaselineError, match="invalid_config") as caught:
        export(inputs, tmp_path, "invalid.json")
    assert "PRIVATE_" not in str(caught.value)
    assert not (tmp_path / "invalid.json").exists()


def test_rejects_unsupported_schema_missing_inputs_and_tampered_baseline(inputs, tmp_path):
    data = export(inputs, tmp_path)
    data["revisions"][0]["cves"] = ["CVE-2026-99999"]
    (tmp_path / "tampered.json").write_text(json.dumps(data))
    with pytest.raises(baseline.BaselineError, match="invalid_baseline"):
        baseline.load_baseline(tmp_path / "tampered.json")
    with closing(connect(inputs[0])) as db:
        db.execute("CREATE TABLE future_revision_data(id INTEGER)")
        db.commit()
    with pytest.raises(baseline.BaselineError, match="unsupported_schema"):
        export(inputs, tmp_path, "unsupported.json")
    with pytest.raises(baseline.BaselineError, match="invalid_input"):
        baseline.export_baseline(
            database=tmp_path / "missing.sqlite",
            config_path=inputs[1],
            output=tmp_path / "missing.json",
        )
    assert not (tmp_path / "missing.sqlite").exists()


@pytest.mark.parametrize(
    ("vendor", "url", "want"),
    [
        (
            "cisco",
            "https://sec.cloudapps.cisco.com/.well-known/csaf/2026/cisco-sa-synthetic.json",
            "https://sec.cloudapps.cisco.com/.well-known/csaf/2026/cisco-sa-synthetic.json",
        ),
        (
            "hpe",
            "https://support.hpe.com/hpesc/public/docDisplay?docId=a12345en_us",
            "https://support.hpe.com/hpesc/public/docDisplay?docId=a12345en_us",
        ),
        (
            "hpe",
            "https://support.hpe.com/hpesc/public/docDisplay?docId=a54321en_us",
            "https://support.hpe.com/hpesc/public/docDisplay?docId=a54321en_us",
        ),
        (
            "hpe",
            "https://support.hpe.com/hpesc/public/docDisplay?docId=a12345en_us&token=secret",
            None,
        ),
        ("cisco", REGISTRY + "?query=secret", None),
        ("cisco", REGISTRY + "#secret", None),
        ("cisco", "https://cisco.com/private/customer/secret", None),
        (
            "arista",
            "https://www.arista.com/en/support/advisories-notices/securityadvisory?start=10&start=20",
            None,
        ),
    ],
)
def test_only_reviewed_semantic_url_routes_are_exported(inputs, tmp_path, vendor, url, want):
    with closing(connect(inputs[0])) as db:
        db.execute(
            "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details) VALUES(?,?,?,?,?)",
            (vendor, url, AT, "ok", ""),
        )
        db.commit()
    data = export(inputs, tmp_path)
    assert data["source_checks"][0]["source_url"] == want
    assert data["diagnostics"]["omitted_urls"] == (0 if want else 1)


def test_exact_reviewed_reference_routes_are_preserved(inputs, tmp_path):
    from infrastructure_impact.references.registry import SOURCES

    entries = [{"source_id": key, "url": value.url} for key, value in SOURCES.items()]
    inputs[1].write_text(json.dumps({"vendors": [], "reference_sources": entries}))
    data = export(inputs, tmp_path)
    assert {e["source_url"] for e in data["configured_sources"]} == {e["url"] for e in entries}
    assert data["diagnostics"]["omitted_urls"] == 0


def write_rehashed(path, data):
    payload = {k: v for k, v in data.items() if k not in {"observed_at", "fingerprint"}}
    data["fingerprint"] = hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()
    path.write_text(json.dumps(data))


@pytest.mark.parametrize(
    "mutation",
    [
        "nested_url",
        "queue_evidence",
        "observation_evidence",
        "cache_evidence",
        "selection_vendor",
        "duplicate_cve",
        "family_vendor",
    ],
)
def test_reader_rejects_invalid_structure_even_with_recomputed_identity(inputs, tmp_path, mutation):
    data = export(inputs, tmp_path)
    if mutation == "nested_url":
        data["source_selections"] = [
            dict(
                selection_id=1,
                vendor="cisco",
                requested_url=REGISTRY,
                observed_at=AT,
                latest=True,
                selected_evidence_id=1,
                views=[dict(evidence_id=1, selected=True)],
                unavailable=[
                    dict(
                        source_url="https://user:secret@cisco.com/arbitrary",
                        error_code="http_error",
                    )
                ],
            )
        ]
    elif mutation == "queue_evidence":
        data["queue"] = [
            dict(
                item_id=1,
                source_id=1,
                vendor="cisco",
                kind="document",
                requested_url=REGISTRY,
                resolved_url=None,
                state="done",
                evidence_id=999,
                attempts=1,
                discovered_at=AT,
                checked_at=AT,
                error_code=None,
                page_evidence_ids=[],
            )
        ]
    elif mutation == "observation_evidence":
        data["source_observations"] = [
            dict(
                observation_id=1,
                vendor="cisco",
                source_url=REGISTRY,
                checked_at=AT,
                evidence_id=999,
                http_status=200,
            )
        ]
    elif mutation == "cache_evidence":
        data["cache"] = [dict(source_url=REGISTRY, evidence_id=999)]
    elif mutation == "selection_vendor":
        data["source_selections"] = [
            dict(
                selection_id=1,
                vendor="arista",
                requested_url=ARISTA,
                observed_at=AT,
                latest=True,
                selected_evidence_id=1,
                views=[dict(evidence_id=1, selected=True)],
                unavailable=[],
            )
        ]
    elif mutation == "duplicate_cve":
        data["revisions"][0]["cves"].append(CVE)
    elif mutation == "family_vendor":
        data["revisions"][0]["assessments"][0]["families"] = ["aruba-aoscx"]
    path = tmp_path / "invalid-baseline.json"
    write_rehashed(path, data)
    with pytest.raises(baseline.BaselineError, match="invalid_baseline"):
        baseline.load_baseline(path)


@pytest.mark.parametrize("error_code", ["invalid_json", "response_too_large", "url_rejected"])
def test_latest_source_check_preserves_reviewed_error_codes(inputs, tmp_path, error_code):
    with closing(connect(inputs[0])) as db:
        for outcome, code in [("ok", None), ("error", error_code)]:
            db.execute(
                "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,details,error_code) VALUES(?,?,?,?,?,?)",
                ("cisco", REGISTRY, AT, outcome, "PRIVATE_ERROR_DETAILS", code),
            )
        db.commit()
    data = export(inputs, tmp_path)
    assert len(data["source_checks"]) == 1
    assert data["source_checks"][0]["outcome"] == "error"
    assert data["source_checks"][0]["error_code"] == error_code
