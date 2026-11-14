"""The installed finite Arista batch; authored stores, no ambient storage or HTTP."""

import json
from contextlib import closing
from hashlib import sha256
from importlib.resources import files

import pytest

from infrastructure_impact.application import maintenance
from infrastructure_impact.collection.maintenance_profiles import profile
from infrastructure_impact.storage.repository import connect, evidence

PROFILE = "arista-reviewed-sa0137-chronology-0165-0198-v1"
PINS_DIGEST = "6053fad4d6006294dc53df6cd9b8bb67650b04f8dce2d8d5cc63793dbae7351b"


def no_http(*args, **kwargs):
    pytest.fail("HTTP must not be reached")


def test_installed_batch_perimeter_and_path_free_pins():
    selected = profile(PROFILE)
    batch = selected.metadata()["batch"]
    pins = batch["captures"]
    assert len(selected.primary_urls) == 34
    assert len(selected.allowed_urls) == len(pins) == 69
    assert sum(p["kind"] != "rss" for p in pins) == 68
    assert sum(p["bytes"] for p in pins) == 4_061_372
    assert {p["number"] for p in pins if p["kind"] == "csaf"} == set(range(165, 199)) - {184}
    assert (
        sha256(json.dumps(pins, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        == PINS_DIGEST
    )
    raw = files("infrastructure_impact").joinpath("resources/arista-hosted-batch.json").read_text()
    local_home_prefix = "/" + "Users" + "/"
    assert local_home_prefix not in raw and "local_public_path" not in raw and "raw_b64" not in raw
    assert batch["analysis_profile"] == "campus-switching-openvuln-2026-11-14-v1"


def test_empty_preview_no_http_and_capture_sensitive_stale_apply(tmp_path, monkeypatch):
    from infrastructure_impact.collection import transport

    monkeypatch.setattr(transport, "fetch", no_http)
    path = tmp_path / "authored.sqlite"
    with closing(connect(path)) as db:
        db.commit()
    original = path.read_bytes()
    before = maintenance.preview(path, PROFILE)
    assert path.read_bytes() == original
    assert len(before["targets"]) == 34
    assert any(i["code"] == "missing_optional_rss" for i in before["issues"])
    assert any(i["code"] == "missing_required_owner" for i in before["issues"])
    pin = profile(PROFILE).metadata()["batch"]["captures"][0]
    with closing(connect(path)) as db:
        with db:
            evidence(db, b"authored unrelated capture at exact URL", pin["url"])
        with pytest.raises(maintenance.MaintenanceBaselineChanged):
            maintenance.apply_profile(db, profile(PROFILE), before["fingerprint"], fetcher=no_http)
    after = maintenance.preview(path, PROFILE)
    assert before["fingerprint"] != after["fingerprint"]
    maintenance.preview_bytes(after)


def test_missing_required_owners_fail_before_fetch_or_normalization(tmp_path, monkeypatch):
    from infrastructure_impact.plugins.registry import default_registry

    path = tmp_path / "authored.sqlite"
    with closing(connect(path)) as db:
        db.commit()
    accepted = maintenance.preview(path, PROFILE)
    monkeypatch.setattr(type(default_registry()), "normalize", no_http)
    with closing(connect(path)) as db:
        result = maintenance.apply_profile(
            db, profile(PROFILE), accepted["fingerprint"], fetcher=no_http
        )
        assert result["outcome"] == "failed_primary_validation"
        assert result["imported"] == result["unchanged"] == 0
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 0
        maintenance.receipt_bytes(result)


@pytest.fixture
def authored_batch(monkeypatch):
    """Exercise the installed 34-record shape with small authored source bytes."""
    from copy import deepcopy
    from pathlib import Path

    from test_arista_sa0137 import synthetic_alternate

    from infrastructure_impact.adapters import arista_sa0137 as sa137
    from infrastructure_impact.application import arista_hosted_batch as implementation
    from infrastructure_impact.collection import maintenance_profiles
    from infrastructure_impact.plugins.registry import default_registry
    from infrastructure_impact.plugins.shared import structured
    from infrastructure_impact.storage.repository import ingest

    fixture = Path(__file__).parent / "fixtures"
    batch = deepcopy(profile(PROFILE).metadata()["batch"])
    pins = batch["captures"]
    template = json.loads((fixture / "arista-chronology-165-authored.json").read_text())
    html_template = (fixture / "arista-chronology-165-authored.html").read_text()
    bodies = {}
    for pin in pins:
        n = pin["number"]
        if pin["kind"] == "csaf":
            data = deepcopy(template)
            data["document"]["title"] = f"Security Advisory {n}"
            data["document"]["tracking"]["id"] = f"Arista Networks Security Advisory {n}"
            data["document"]["references"][0]["url"] = next(
                p["url"] for p in pins if p["number"] == n and p["kind"] == "html"
            )
            data["vulnerabilities"] = [{"cve": c} for c in pin["cve_ids"]]
            raw = json.dumps(data).encode()
        elif pin["kind"] == "csaf_draft":
            raw = synthetic_alternate()
            monkeypatch.setattr(sa137, "REVIEWED_SHA256", sha256(raw).hexdigest())
        elif pin["kind"] == "rss":
            raw = b"<rss><channel></channel></rss>"
        elif n == 137:
            raw = (fixture / "arista-sa0137-authored.html").read_bytes()
        else:
            raw = (
                html_template.replace("Advisory 0165", f"Advisory {n:04d}")
                .replace("advisory_165_CSAF", f"advisory_{n}_CSAF")
                .replace("CVE-2026-73454", " ".join(pin["cve_ids"]))
            ).encode()
        bodies[pin["url"]] = raw
        pin["sha256"] = sha256(raw).hexdigest()
        pin["bytes"] = len(raw)
    for target in batch["expected_primaries"]:
        target["sha256"] = sha256(bodies[target["url"]]).hexdigest()
    monkeypatch.setattr(implementation, "batch_metadata", lambda: deepcopy(batch))
    monkeypatch.setattr(maintenance_profiles, "batch_metadata", lambda: deepcopy(batch))
    registry = default_registry()
    with closing(connect(":memory:")) as db:
        for pin in pins:
            with db:
                db.execute(
                    "INSERT INTO evidence(source_url,sha256,observed_at,raw,media_type) VALUES(?,?,?,?,?)",
                    (
                        pin["url"],
                        pin["sha256"],
                        "2026-11-13T20:00:00Z",
                        bodies[pin["url"]],
                        "application/json",
                    ),
                )
            if pin["kind"] in {"csaf", "csaf_draft"}:
                adapter = (
                    (
                        lambda raw, url, vendor: registry.finalize(
                            structured(raw, url, vendor), url, vendor
                        )
                    )
                    if pin["kind"] == "csaf_draft"
                    else registry.normalize
                )
                ingest(db, bodies[pin["url"]], pin["url"], adapter, "arista")
        yield db, profile(PROFILE), batch, bodies


def execute(authored_batch, fetcher=no_http):
    db, selected, _, _ = authored_batch
    return maintenance.apply_profile(
        db, selected, maintenance._preview(db, selected)["fingerprint"], fetcher=fetcher
    )


def test_all_33_authored_chronologies_and_sa137_selection_are_idempotent(authored_batch):
    from infrastructure_impact.adapters import arista_sa0137 as sa137
    from infrastructure_impact.storage.repository import latest

    db, _, _, _ = authored_batch
    first = execute(authored_batch)
    assert first["outcome"] == "completed"
    assert first["imported"] == 34
    assert len(first["primary_outcomes"]) == 34 and len(first["alternate_outcomes"]) == 35
    assert any(p["source_url"] == sa137.CSAF for d in first["decisions"] for p in d["proofs"])
    records = latest(db)
    repaired = [r for r in records if r.get("publisher_chronology")]
    assert len(repaired) == 33
    assert {r["published_at"] for r in repaired} == {"2026-09-09"}
    primary137 = next(r for r in records if r["advisory_id"] == sa137.ID)
    assert all(
        rem["category"] != "vendor_fix"
        for a in primary137["assessments"]
        for rem in a["remediations"]
    )
    assert db.execute("SELECT count(*) FROM source_selections").fetchone()[0] == 1
    count = db.execute("SELECT count(*) FROM revisions").fetchone()[0]
    repeated = execute(authored_batch)
    assert (repeated["outcome"], repeated["imported"], repeated["unchanged"]) == (
        "completed",
        0,
        34,
    )
    assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == count


@pytest.mark.parametrize("kind", ["csaf", "csaf_draft", "html"])
def test_changed_required_capture_no_normalized_writes(authored_batch, kind):
    db, _, batch, _ = authored_batch
    pin = next(p for p in batch["captures"] if p["kind"] == kind)
    with db:
        db.execute(
            "UPDATE evidence SET raw=? WHERE source_url=? AND sha256=?",
            (b"changed authored bytes", pin["url"], pin["sha256"]),
        )
    before = [tuple(r) for r in db.execute("SELECT * FROM revisions")]
    result = execute(authored_batch)
    assert result["outcome"] == "failed_primary_validation"
    assert result["imported"] == 0
    assert [tuple(r) for r in db.execute("SELECT * FROM revisions")] == before


def test_optional_rss_absence_is_retained_only_and_diagnostic(authored_batch):
    from infrastructure_impact.storage.repository import latest

    db, selected, batch, _ = authored_batch
    rss = next(p for p in batch["captures"] if p["kind"] == "rss")
    with db:
        db.execute("DELETE FROM evidence WHERE source_url=?", (rss["url"],))
    preview = maintenance._preview(db, selected)
    assert {"code": "missing_optional_rss", "source_url": rss["url"]} in preview["issues"]
    result = execute(authored_batch)
    assert result["outcome"] == "completed"
    assert (
        next(r for r in result["alternate_outcomes"] if r["source_url"] == rss["url"])["outcome"]
        == "not_attempted"
    )
    assert all(
        "rss_not_supplied" in r["publisher_chronology"]["issues"]
        for r in latest(db)
        if r.get("publisher_chronology")
    )


def test_missing_html_fetches_exact_bytes_once_without_backdating(authored_batch):
    from infrastructure_impact.application.arista_hosted_batch import exact_capture

    db, selected, batch, bodies = authored_batch
    pin = next(p for p in batch["captures"] if p["kind"] == "html" and p["number"] == 198)
    with db:
        db.execute("DELETE FROM evidence WHERE source_url=?", (pin["url"],))
    called = []

    def fetch(connection, url, vendor, **kwargs):
        assert connection is db and vendor == "arista" and url == pin["url"]
        assert kwargs == dict(max_bytes=2_000_000, allowed_urls=selected.allowed_urls)
        called.append(url)
        return bodies[url]

    result = execute(authored_batch, fetch)
    assert result["outcome"] == "completed" and called == [pin["url"]]
    assert exact_capture(db, pin)[1]["retrieved_at"] != "2026-11-13T20:00:00Z"
    assert exact_capture(db, pin)[1]["retrieved_at"] != pin["retrieved_at"]


def test_exact_retained_capture_wins_over_changed_latest_url(authored_batch):
    db, _, batch, _ = authored_batch
    pin = next(p for p in batch["captures"] if p["kind"] == "html")
    with db:
        evidence(db, b"newer unrelated authored bytes", pin["url"])
    assert execute(authored_batch)["outcome"] == "completed"


@pytest.mark.parametrize("kind", ["csaf", "csaf_draft"])
@pytest.mark.parametrize("mutation", ["hash", "url", "cves"])
def test_changed_current_owner_refuses_before_supporting_fetch(
    authored_batch, monkeypatch, kind, mutation
):
    from infrastructure_impact.plugins.registry import default_registry
    from infrastructure_impact.storage.repository import latest

    db, selected, batch, _ = authored_batch
    pin = next(p for p in batch["captures"] if p["kind"] == kind)
    advisory_id = f"Arista Networks Security Advisory {pin['number']}"
    row = db.execute(
        "SELECT id,normalized FROM revisions WHERE vendor='arista' AND advisory_id=?",
        (advisory_id,),
    ).fetchone()
    normalized = json.loads(row["normalized"])
    changed_url = "https://www.arista.com/unreviewed-owner"
    changed_cves = ["CVE-2026-999999"]
    with db:
        if mutation == "hash":
            ev = evidence(db, b"changed current owner", pin["url"])
            db.execute("UPDATE revisions SET evidence_id=? WHERE id=?", (ev["id"], row["id"]))
        elif mutation == "url":
            normalized["source_url"] = changed_url
            db.execute(
                "UPDATE revisions SET source_url=?,normalized=? WHERE id=?",
                (changed_url, json.dumps(normalized), row["id"]),
            )
        else:
            normalized["cves"] = changed_cves
            db.execute(
                "UPDATE revisions SET normalized=? WHERE id=?",
                (json.dumps(normalized), row["id"]),
            )
    owner = next(r for r in latest(db) if r["advisory_id"] == advisory_id)
    assert owner["sha256"] == (
        sha256(b"changed current owner").hexdigest() if mutation == "hash" else pin["sha256"]
    )
    assert owner["source_url"] == (changed_url if mutation == "url" else pin["url"])
    assert owner["cves"] == (changed_cves if mutation == "cves" else pin["cve_ids"])
    preview = maintenance._preview(db, selected)
    assert {"code": "changed_required_owner", "source_url": pin["url"]} in preview["issues"]
    before = [tuple(r) for r in db.execute("SELECT * FROM revisions ORDER BY id")]

    def no_normalization(*args, **kwargs):
        pytest.fail("Changed current owner must fail before normalization")

    monkeypatch.setattr(type(default_registry()), "normalize", no_normalization)
    result = execute(authored_batch)
    assert result["outcome"] == "failed_primary_validation"
    assert result["imported"] == result["unchanged"] == 0
    assert result["primary_outcomes"] == []
    assert [tuple(r) for r in db.execute("SELECT * FROM revisions ORDER BY id")] == before


def test_late_preflight_reconcile_failure_means_no_normalized_writes(authored_batch, monkeypatch):
    from infrastructure_impact.adapters import arista_chronology

    db, _, _, _ = authored_batch
    original = arista_chronology.reconcile

    def fail_last(record, **kwargs):
        if record["advisory_id"].endswith("198"):
            return {"status": "unchanged", "chronology": None}
        return original(record, **kwargs)

    monkeypatch.setattr(arista_chronology, "reconcile", fail_last)
    before = [tuple(r) for r in db.execute("SELECT * FROM revisions")]
    assert execute(authored_batch)["outcome"] == "failed_primary_validation"
    assert [tuple(r) for r in db.execute("SELECT * FROM revisions")] == before


def test_finalized_projection_failure_keeps_failed_cleanup_receipt(authored_batch, monkeypatch):
    from infrastructure_impact.application import switching_evidence

    def broken(*args, **kwargs):
        raise RuntimeError("authored finalization failure")

    monkeypatch.setattr(switching_evidence, "project", broken)
    result = execute(authored_batch)
    assert result["outcome"] == "failed_cleanup_proof"
    assert result["imported"] == 34


def test_source_pinned_finalized_case_failure_refuses_completion(authored_batch, monkeypatch):
    from infrastructure_impact.application import arista_chronology_repair

    monkeypatch.setattr(
        arista_chronology_repair,
        "validate_cases",
        lambda rows: [dict(number=165, automated_validation="failed", human_review="pending")],
    )
    assert execute(authored_batch)["outcome"] == "failed_cleanup_proof"


@pytest.mark.parametrize("mutation", ["timestamp", "bytes", "absence", "newer_capture"])
def test_capture_fact_change_invalidates_accepted_preview_before_http(authored_batch, mutation):
    db, selected, batch, _ = authored_batch
    accepted = maintenance._preview(db, selected)
    pin = next(p for p in batch["captures"] if p["kind"] == "html")
    with db:
        if mutation == "timestamp":
            db.execute(
                "UPDATE evidence SET observed_at=? WHERE source_url=?",
                ("2026-11-14T20:00:00Z", pin["url"]),
            )
        elif mutation == "bytes":
            db.execute(
                "UPDATE evidence SET raw=? WHERE source_url=?",
                (b"tampered authored bytes", pin["url"]),
            )
        elif mutation == "absence":
            db.execute("DELETE FROM evidence WHERE source_url=?", (pin["url"],))
        else:
            evidence(db, b"newer authored capture", pin["url"])
    assert maintenance._preview(db, selected)["fingerprint"] != accepted["fingerprint"]
    with pytest.raises(maintenance.MaintenanceBaselineChanged):
        maintenance.apply_profile(db, selected, accepted["fingerprint"], fetcher=no_http)


def test_missing_last_html_changed_download_fails_before_normalizer(authored_batch, monkeypatch):
    from infrastructure_impact.plugins.registry import default_registry

    db, _, batch, _ = authored_batch
    pin = next(p for p in batch["captures"] if p["kind"] == "html" and p["number"] == 198)
    with db:
        db.execute("DELETE FROM evidence WHERE source_url=?", (pin["url"],))
    monkeypatch.setattr(type(default_registry()), "normalize", no_http)
    called = []

    def fetch(connection, url, vendor, **kwargs):
        called.append(url)
        return b"changed downloaded authored HTML"

    result = execute(authored_batch, fetch)
    assert result["outcome"] == "failed_primary_validation"
    assert result["imported"] == 0 and called == [pin["url"]]
    assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 34


def test_completed_batch_receipt_requires_every_supporting_capture_and_exact_draft(authored_batch):
    from copy import deepcopy

    result = execute(authored_batch)
    assert result["outcome"] == "completed"
    for mutation in ["missing_support", "duplicate_support", "no_draft_decision", "private_field"]:
        forged = deepcopy(result)
        if mutation == "missing_support":
            forged["alternate_outcomes"][0]["outcome"] = "not_attempted"
        elif mutation == "duplicate_support":
            forged["alternate_outcomes"][0] = forged["alternate_outcomes"][1]
        elif mutation == "no_draft_decision":
            forged["decisions"] = []
            forged["proof_fingerprints"] = []
        else:
            forged["raw_b64"] = "authored private field"
        with pytest.raises(ValueError, match="invalid_maintenance_receipt"):
            maintenance.receipt_bytes(forged)
