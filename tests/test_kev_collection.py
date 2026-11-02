"""Synthetic KEV inputs exercise the real collector, transport and retention path."""

import io
import json
import sqlite3
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from infrastructure_impact.application.query import state
from infrastructure_impact.collection.config import validate_config
from infrastructure_impact.collection.service import run
from infrastructure_impact.collection.transport import fetch
from infrastructure_impact.references.kev import parse
from infrastructure_impact.references.registry import KEV_URL, source
from infrastructure_impact.references.storage import enrichment_input, ingest, latest
from infrastructure_impact.storage.repository import connect, evidence

RAW = (Path(__file__).parent / "fixtures/kev-valid.json").read_bytes()
CONFIG = {"vendors": [], "reference_sources": [{"source_id": "cisa-kev", "url": KEV_URL}]}


def encoded(data):
    return json.dumps(data, separators=(",", ":")).encode()


def invalid_cases():
    for field, value in [
        ("count", True),
        ("count", 1),
        ("count", 0),
        ("count", "2"),
        ("count", 2.0),
        ("vulnerabilities", []),
        ("vulnerabilities", {}),
        ("catalogVersion", ""),
        ("catalogVersion", 1),
        ("dateReleased", "2026-11-02T12:00:00"),
        ("dateReleased", "2026-02-30T00:00:00Z"),
        ("dateReleased", None),
        ("dateReleased", "2026-11-02T12:00:00+00:99"),
    ]:
        data = json.loads(RAW)
        data[field] = value
        yield f"catalogue-{field}-{value}", encoded(data)
    for field, value in [
        ("cveID", "cve-2024-6387"),
        ("cveID", "CVE-２０２４-6387"),
        ("cveID", "CVE-2024-" + "1" * 20),
        ("cveID", None),
        ("dateAdded", "2026-02-30"),
        ("dueDate", "2026-11-23T00:00:00Z"),
        ("vendorProject", ""),
        ("product", None),
        ("vulnerabilityName", 1),
        ("shortDescription", []),
        ("requiredAction", False),
        ("knownRansomwareCampaignUse", True),
        ("forensicTriage", {}),
        ("notes", []),
        ("cwes", "CWE-362"),
        ("cwes", [None]),
    ]:
        data = json.loads(RAW)
        data["vulnerabilities"][0][field] = value
        yield f"entry-{field}-{value}", encoded(data)
    for field in [
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
    ]:
        data = json.loads(RAW)
        del data["vulnerabilities"][0][field]
        yield "missing-" + field, encoded(data)
    data = json.loads(RAW)
    data["vulnerabilities"][1] = deepcopy(data["vulnerabilities"][0])
    yield "duplicate-id", encoded(data)
    yield "duplicate-key", RAW.replace(b'"count": 2', b'"count": 2, "count": 2')
    yield "nonfinite", RAW.replace(b'"count": 2', b'"count": NaN')
    yield "overflow", RAW.replace(b'"count": 2', b'"count": 1e999')
    yield "truncated", RAW[:-4]
    yield "malformed", b'{"count":}'
    yield "wrong-root", b"[]"
    yield "bytes", b" " * 8_000_001
    data = json.loads(RAW)
    row = {
        "vendorProject": "V",
        "product": "P",
        "vulnerabilityName": "N",
        "dateAdded": "2026-11-02",
        "shortDescription": "S",
        "requiredAction": "A",
        "dueDate": "2026-11-23",
    }
    data["vulnerabilities"] = [dict(row, cveID=f"CVE-2099-{n:05d}") for n in range(20_001)]
    data["count"] = 20_001
    assert len(encoded(data)) < 8_000_000  # Exercise the entry bound independently.
    yield "entries", encoded(data)


INVALID = list(invalid_cases())


class Response(io.BytesIO):
    headers = {"Content-Type": "application/json", "ETag": '"synthetic"'}
    status = 200


class Opener:
    def __init__(self, raw):
        self.raw = raw

    def open(self, request, timeout):
        if self.raw is None:
            raise HTTPError(request.full_url, 304, "Not modified", {}, None)
        return Response(self.raw)


def collect(path, raw, config=CONFIG):
    # Only the external HTTP boundary is replaced; collection/cache/parser/DB are real.
    with patch("infrastructure_impact.collection.transport.build_opener", return_value=Opener(raw)):
        return run(config, db_path=path)


def read_input(path, config=CONFIG):
    with connect(path) as db:
        return enrichment_input(db, config, "cisa-kev")


def test_normalized_catalogue_keeps_publisher_values_without_extra_fields():
    result = parse(RAW)
    assert result["parser_version"] == 1
    assert result["catalogue_version"] == "2026.11.02-synthetic"
    assert result["released_at"] == "2026-11-02T12:00:00Z"
    assert result["count"] == 2
    assert sorted(result["entries"]) == ["CVE-2024-6387", "CVE-2099-99999"]
    first = result["entries"]["CVE-2024-6387"]
    assert first["cveID"] == "CVE-2024-6387"
    assert first["knownRansomwareCampaignUse"] == "Future publisher value"
    assert first["cwes"] == ["CWE-362"] and first["forensicTriage"] is None
    assert "publisherExtra" not in first
    second = result["entries"]["CVE-2099-99999"]
    assert second["notes"] is None and second["cwes"] == []


@pytest.mark.parametrize("label,raw", INVALID, ids=[case[0] for case in INVALID])
def test_invalid_collection_never_replaces_last_good(tmp_path, label, raw):
    path = tmp_path / "vault.sqlite"
    assert collect(path, RAW) == (0, 0)
    before = read_input(path)
    with pytest.raises(ValueError):
        parse(raw)
    assert collect(path, raw) == (0, 1)
    after = read_input(path)
    assert after["retained"] == before["retained"]
    assert after["checked_at"] == before["checked_at"]
    assert after["latest_attempt"]["outcome"] == "error"
    assert after["latest_attempt"]["error_code"] == "unsupported_or_invalid_document"
    with connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM reference_documents").fetchone()[0] == 1


def test_verified_checks_and_reversions(tmp_path):
    path = tmp_path / "vault.sqlite"
    assert collect(path, RAW) == (0, 0)
    first = read_input(path)
    assert first["configured"] and first["enabled"]
    assert isinstance(first["retained"]["revision_id"], str)
    assert collect(path, None) == (0, 0)
    unchanged = read_input(path)
    assert unchanged["checked_at"] > first["checked_at"]
    assert unchanged["retained"]["revision_id"] == first["retained"]["revision_id"]
    assert collect(path, b"invalid") == (0, 1)
    failed = read_input(path)
    assert failed["latest_attempt"]["outcome"] == "error"
    assert failed["checked_at"] == unchanged["checked_at"]
    correction = json.loads(RAW)
    correction["vulnerabilities"][0]["requiredAction"] = "Corrected synthetic action"
    assert collect(path, encoded(correction)) == (0, 0)
    assert (
        read_input(path)["retained"]["catalogue"]["entries"]["CVE-2024-6387"]["requiredAction"]
        == "Corrected synthetic action"
    )
    correction["vulnerabilities"].pop()
    correction["count"] = 1
    assert collect(path, encoded(correction)) == (0, 0)
    assert "CVE-2099-99999" not in read_input(path)["retained"]["catalogue"]["entries"]
    assert collect(path, RAW) == (0, 0)
    reverted = read_input(path)
    assert reverted["retained"]["revision_id"] != first["retained"]["revision_id"]
    assert reverted["retained"]["sha256"] == first["retained"]["sha256"]
    with connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM reference_documents").fetchone()[0] == 4
        assert not db.execute("SELECT 1 FROM revisions").fetchone()


@pytest.mark.parametrize(
    "raw", [b"invalid cached JSON", b" " * 8_000_001], ids=["invalid", "oversized"]
)
def test_304_cached_bytes_are_bounded_and_freshly_parsed(tmp_path, raw):
    path = tmp_path / "vault.sqlite"
    assert collect(path, RAW) == (0, 0)
    before = read_input(path)
    with connect(path) as db:
        ev = evidence(db, raw, KEV_URL)
        db.execute("UPDATE http_cache SET evidence_id=? WHERE url=?", (ev["id"], KEV_URL))
    assert collect(path, None) == (0, 1)
    after = read_input(path)
    assert after["retained"] == before["retained"]
    assert after["checked_at"] == before["checked_at"]
    assert after["latest_attempt"]["outcome"] == "error"


def test_failure_before_any_retained_document_has_attempt_state(tmp_path):
    path = tmp_path / "vault.sqlite"
    assert collect(path, b"invalid") == (0, 1)
    result = read_input(path)
    assert result["retained"] is None and result["checked_at"] is None
    assert result["latest_attempt"]["outcome"] == "error"


def test_disabled_and_unconfigured_preserve_context_without_fetching(tmp_path):
    path = tmp_path / "vault.sqlite"
    assert collect(path, RAW) == (0, 0)
    disabled = deepcopy(CONFIG)
    disabled["reference_sources"][0]["enabled"] = False
    absent = {"vendors": []}
    for config in [disabled, absent]:
        with patch(
            "infrastructure_impact.collection.transport.build_opener",
            side_effect=AssertionError("disabled source fetched"),
        ):
            assert run(config, db_path=path) == (0, 0)
        result = read_input(path, config)
        assert result["configured"] is (config is disabled)
        assert result["enabled"] is False
        assert result["retained"] is not None
    config_path = tmp_path / "sources.json"
    config_path.write_text(json.dumps(absent))
    with patch.dict("os.environ", {"IMPACT_SOURCES": str(config_path)}), connect(path) as db:
        result = state(db)["research"]["kev_input"]
        assert result["configured"] is False and result["enabled"] is False


@pytest.mark.parametrize("value", [None, "false", 0, 1, []])
def test_reference_enabled_requires_a_boolean(value):
    config = deepcopy(CONFIG)
    config["reference_sources"][0]["enabled"] = value
    with pytest.raises(ValueError):
        validate_config(config)


def test_transport_default_budget_and_exact_kev_boundary(tmp_path):
    with connect(tmp_path / "vault.sqlite") as db:
        for size, budget in [
            (8_000_000, 8_000_000),
            (8_000_001, 8_000_000),
            (15_000_000, None),
            (15_000_001, None),
        ]:
            with patch(
                "infrastructure_impact.collection.transport.build_opener",
                return_value=Opener(b" " * size),
            ):
                kwargs = {} if budget is None else {"max_bytes": budget}
                if size > (budget or 15_000_000):
                    with pytest.raises(ValueError):
                        fetch(db, KEV_URL, "upstream", **kwargs)
                else:
                    assert len(fetch(db, KEV_URL, "upstream", **kwargs)) == size


def test_kev_does_not_change_nvd_study_inputs_fingerprints_or_enrollment(tmp_path):
    from test_references import response

    path = tmp_path / "vault.sqlite"
    with connect(path) as db:
        ingest(db, encoded(response()), "nvd-openssh-products")
        before = state(db)
    assert collect(path, RAW) == (0, 0)
    with connect(path) as db:
        after = state(db)
        assert len(latest(db)) == 2
        assert latest(db, purpose="component_study") == before["research"]["study_inputs"]
    assert after["research"]["study_inputs"] == before["research"]["study_inputs"]
    assert after["component_studies"] == before["component_studies"]
    assert after["research"]["kev_input"]["retained"]["catalogue"]["count"] == 2
    assert source("cisa-kev").purpose == "cve_enrichment"


def test_valid_catalogue_limits_and_calendar_timezone_variants():
    data = json.loads(dict(INVALID)["entries"])
    data["vulnerabilities"].pop()
    data["count"] = 20_000
    assert parse(encoded(data))["count"] == 20_000
    data = json.loads(RAW)
    data["dateReleased"] = "2024-02-29T12:34:56.123+05:30"
    data["vulnerabilities"][0]["dateAdded"] = "2024-02-29"
    data["vulnerabilities"][0]["cveID"] = "CVE-2024-1234567890123456789"
    raw = encoded(data)
    assert parse(raw + b" " * (8_000_000 - len(raw)))["count"] == 2


def test_missing_verification_and_legacy_vault_remain_explicit(tmp_path):
    with sqlite3.connect(":memory:") as db:
        assert enrichment_input(db, CONFIG, "cisa-kev") == {
            "configured": True,
            "enabled": True,
            "retained": None,
            "latest_attempt": None,
            "checked_at": None,
        }
        assert not db.execute("SELECT name FROM sqlite_master").fetchone()
    with connect(tmp_path / "vault.sqlite") as db:
        ingest(db, RAW, "cisa-kev")
        result = enrichment_input(db, CONFIG, "cisa-kev")
        assert result["retained"] is not None
        assert result["latest_attempt"] is None and result["checked_at"] is None
