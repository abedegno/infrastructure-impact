"""Authored synthetic KEV data only; no licensed feed records or real credentials."""

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError

import pytest

from infrastructure_impact.collection import vulncheck_kev as vc

NOW = datetime(2026, 11, 19, 12, tzinfo=timezone.utc)
TOKEN = "synthetic-token-never-retained"


def row(ids=None):
    return dict(
        cve=ids or ["CVE-2026-10001"],
        vendorProject="Example Vendor",
        product="Example OS",
        date_added="2026-11-18T00:00:00Z",
        vulncheck_reported_exploitation=[
            dict(url="https://example.org/report", date_added="2026-11-17T00:00:00Z")
        ],
        reported_exploited_by_vulncheck_canaries=False,
        vulncheck_xdb=[dict(clone_ssh_url="git@example.org:unused.git")],
    )


def archive(rows=None):
    raw = json.dumps([row()] if rows is None else rows).encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("vulncheck-kev.json", raw)
    return stream.getvalue()


class Response(io.BytesIO):
    status = 200

    def __init__(self, raw, url):
        super().__init__(raw)
        self.url = url

    def geturl(self):
        return self.url


class Session:
    def __init__(self, body=None):
        self.body = body or archive()
        self.calls = []
        self.error = None
        self.url = "https://serve.vulncheck.com/latest/synthetic.zip?Signature=private"

    def open(self, request, timeout):
        self.calls.append(request)
        if self.error:
            raise self.error
        if request.full_url == vc.API_URL:
            raw = json.dumps(
                dict(
                    data=[
                        dict(
                            url=self.url,
                            sha256=hashlib.sha256(self.body).hexdigest(),
                            date_added="2026-11-18T12:00:00Z",
                        )
                    ]
                )
            ).encode()
        else:
            raw = self.body
        return Response(raw, request.full_url)


def collect(path, session, at=NOW, force=False):
    return vc.collect(path, token=TOKEN, session=session, at=at, force=force)


def test_collect_caches_once_and_preserves_revision_provenance(tmp_path):
    session = Session()
    path = tmp_path / "private.sqlite"
    first = collect(path, session)
    assert first["outcome"] == "ok" and first["revision_id"] == 1
    assert session.calls[0].get_header("Authorization") == "Bearer " + TOKEN
    assert session.calls[1].get_header("Authorization") is None
    assert collect(path, session)["outcome"] == "cached"
    assert len(session.calls) == 2
    assert collect(path, session, force=True)["revision_id"] == 1
    assert len(session.calls) == 3  # verified hash reuses ZIP, without downloading it again
    session.body = archive([row(["CVE-2026-10002"])])
    assert collect(path, session, force=True)["revision_id"] == 2
    data = path.read_bytes()
    assert TOKEN.encode() not in data and b"Signature=private" not in data
    assert path.stat().st_mode & 0o777 == 0o600
    result = vc.report(path, ["CVE-2026-10002", "CVE-2026-10001"], at=NOW)
    assert result["source"]["url"] == vc.API_URL
    assert result["source"]["sha256"] == hashlib.sha256(session.body).hexdigest()
    assert result["source"]["revision_id"] == 2
    assert result["counts"]["vulncheck_listed"] == 1


def test_multicve_rows_and_exploitation_semantics():
    entries = vc.parse(archive([row(["CVE-2026-10001", "CVE-2026-10002"])]))
    assert sorted(entries) == ["CVE-2026-10001", "CVE-2026-10002"]
    assert (
        entries["CVE-2026-10001"]["reported_exploitation"][0]["url"] == "https://example.org/report"
    )
    assert "clone_ssh_url" not in json.dumps(entries)
    assert entries["CVE-2026-10001"]["listed_at"] == "2026-11-18T00:00:00Z"


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [row(), row()],
        [dict(row(), cve=["bad"])],
        [dict(row(), date_added="2026-02-30T00:00:00Z")],
        [dict(row(), reported_exploited_by_vulncheck_canaries="true")],
    ],
)
def test_rejects_incomplete_or_ambiguous_catalogues(rows):
    with pytest.raises(ValueError):
        vc.parse(archive(rows))


def test_zip_limits_and_member_validation(monkeypatch):
    monkeypatch.setattr(vc, "MAX_JSON_BYTES", 4)
    with pytest.raises(ValueError):
        vc.parse(archive())


@pytest.mark.parametrize(
    "url",
    [
        "http://serve.vulncheck.com/a",
        "https://evil.example/a",
        "https://serve.vulncheck.com.evil.example/a",
        "https://user@serve.vulncheck.com/a",
    ],
)
def test_download_url_allowlist(tmp_path, url):
    session = Session()
    session.url = url
    result = collect(tmp_path / "state.sqlite", session)
    assert result["outcome"] == "failed"
    assert len(session.calls) == 1


def test_rate_limit_is_resumable_and_failure_makes_membership_unknown(tmp_path):
    path, session = tmp_path / "state.sqlite", Session()
    collect(path, session)
    session.error = HTTPError(
        vc.API_URL, 429, TOKEN, {"Retry-After": "120"}, io.BytesIO(TOKEN.encode())
    )
    result = collect(path, session, force=True)
    assert result["error_code"] == "rate_limited"
    assert TOKEN not in json.dumps(result)
    assert (
        collect(path, session, at=NOW + timedelta(seconds=60), force=True)["outcome"] == "deferred"
    )
    report = vc.report(path, ["CVE-2026-10001"], at=NOW)
    assert report["source"]["availability"] == "failed"
    assert report["cves"][0]["vulncheck"]["membership"] == "unknown"
    assert report["cves"][0]["vulncheck"]["retained_listed"] is True


def test_missing_stale_and_cisa_remain_distinct(tmp_path):
    path, session = tmp_path / "state.sqlite", Session()
    assert vc.report(path, ["CVE-2026-10001"], at=NOW)["source"]["availability"] == "missing"
    assert not path.exists()  # read-only report does not initialize storage
    collect(path, session)
    report = vc.report(
        path, ["CVE-2026-10001", "CVE-2026-10002"], at=NOW, cisa_ids={"CVE-2026-10002"}
    )
    assert report["counts"] == dict(
        vulncheck_listed=1, cisa_listed=1, both=0, vulncheck_only=1, cisa_only=1
    )
    assert report["attribution"]["name"] == "VulnCheck Known Exploited Vulnerabilities"
    assert report["distribution"] == "private_research_only"
    assert (
        vc.report(path, ["CVE-2026-10001"], at=NOW + timedelta(days=2))["cves"][0]["vulncheck"][
            "membership"
        ]
        == "unknown"
    )


def test_missing_token_does_not_open_network(tmp_path):
    session = Session()
    result = vc.collect(tmp_path / "state.sqlite", token="", session=session, at=NOW)
    assert result["error_code"] == "credentials_missing"
    assert not session.calls


def test_cli_report_never_opens_default_vault(tmp_path, monkeypatch, capsys):
    from infrastructure_impact.cli import main
    from infrastructure_impact.storage import repository

    def forbidden(*args, **kwargs):
        pytest.fail("VulnCheck CLI opened default vault")

    monkeypatch.setattr(repository, "connect", forbidden)
    assert (
        main(
            [
                "vulncheck-kev",
                "report",
                "--state",
                str(tmp_path / "missing.sqlite"),
                "--cve",
                "CVE-2026-10001",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["counts"]["vulncheck_listed"] is None
    assert result["cisa_source"]["availability"] == "missing"


def test_cli_scope_file_and_failed_collection_exit(tmp_path, monkeypatch, capsys):
    from infrastructure_impact.cli import main

    scope = tmp_path / "scope.json"
    scope.write_text('["CVE-2026-10001", "CVE-2026-10002"]')
    state = tmp_path / "state.sqlite"
    assert main(["vulncheck-kev", "report", "--state", str(state), "--scope", str(scope)]) == 0
    assert len(json.loads(capsys.readouterr().out)["cves"]) == 2
    monkeypatch.setenv("VULNCHECK_API_TOKEN", "")
    assert main(["vulncheck-kev", "collect", "--state", str(state)]) == 1
    assert json.loads(capsys.readouterr().out)["error_code"] == "credentials_missing"


def test_module_cli_report_entrypoint(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "infrastructure_impact.cli",
            "vulncheck-kev",
            "report",
            "--state",
            str(tmp_path / "missing.sqlite"),
            "--cve",
            "CVE-2026-10001",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout)["source"]["availability"] == "missing"


@pytest.mark.parametrize("failure", ["hash", "redirect", "reflected_token", "corrupt_zip"])
def test_failed_download_does_not_create_revision(tmp_path, failure):
    session = Session()
    original = session.open

    def open_request(request, timeout):
        response = original(request, timeout)
        if request.full_url == vc.API_URL and failure == "hash":
            data = json.loads(response.getvalue())
            data["data"][0]["sha256"] = "0" * 64
            return Response(json.dumps(data).encode(), request.full_url)
        if request.full_url != vc.API_URL and failure == "redirect":
            response.url = "https://elsewhere.example/private"
        return response

    session.open = open_request
    if failure == "reflected_token":
        session.body = archive([dict(row(), unknown_private_field=TOKEN)])
    if failure == "corrupt_zip":
        session.body = b"invalid archive"
    path = tmp_path / "state.sqlite"
    assert collect(path, session)["outcome"] == "failed"
    assert TOKEN.encode() not in path.read_bytes()
    assert vc.report(path, ["CVE-2026-10001"], at=NOW)["source"]["revision_id"] is None


def test_cli_does_not_credit_stale_cisa_report(tmp_path, capsys):
    from pathlib import Path

    from infrastructure_impact.cli import main

    supplied = json.loads(
        (Path(__file__).parent / "fixtures/kev-selection-cases.json").read_text()
    )["base_report"]
    cisa = tmp_path / "cisa.json"
    cisa.write_text(json.dumps(supplied))
    main(
        [
            "vulncheck-kev",
            "report",
            "--state",
            str(tmp_path / "state.sqlite"),
            "--cve",
            "CVE-2024-6387",
            "--cisa-report",
            str(cisa),
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert result["cisa_source"]["availability"] == "stale"
    assert result["counts"]["cisa_listed"] is None


def test_does_not_modify_unrelated_database(tmp_path):
    import sqlite3

    path = tmp_path / "unrelated.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE unrelated(value)")
    before = path.read_bytes()
    with pytest.raises(ValueError):
        collect(path, Session())
    assert path.read_bytes() == before


def test_repeated_old_hash_selects_verified_revision(tmp_path):
    path, session = tmp_path / "state.sqlite", Session()
    original = session.body
    collect(path, session)
    session.body = archive([row(["CVE-2026-10002"])])
    collect(path, session, force=True)
    session.body = original
    assert collect(path, session, force=True)["revision_id"] == 1
    result = vc.report(path, ["CVE-2026-10001", "CVE-2026-10002"], at=NOW)
    assert result["source"]["revision_id"] == 1
    assert result["cves"][0]["vulncheck"]["membership"] == "listed"
    assert result["cves"][1]["vulncheck"]["membership"] == "not_listed"


@pytest.mark.parametrize("status", [429, 503])
def test_http_date_backoff_is_honored(tmp_path, status):
    session = Session()
    session.error = HTTPError(
        vc.API_URL,
        status,
        "synthetic",
        {"Retry-After": "Thu, 19 Nov 2026 13:00:00 GMT"},
        io.BytesIO(),
    )
    result = collect(tmp_path / "state.sqlite", session)
    assert result["retry_at"] == "2026-11-19T13:00:00+00:00"
