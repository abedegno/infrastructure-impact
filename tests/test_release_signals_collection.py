import hashlib
import io
import json
from urllib.error import HTTPError

import pytest

from infrastructure_impact import release_signals_cli as cli
from infrastructure_impact.collection.release_signals import (
    ARISTA_URL,
    parse_arista_releases,
    parse_aruba_history,
    parse_cisco_caveats,
)

TIMESTAMP = "2026-11-25T11:33:58+00:00"
RSS = b"""<?xml version="1.0" encoding="iso-8859-1"?>
<rss version="2.0"><channel>
<title>Arista Networks :: Software Release</title>
<link>https://www.arista.com/support/release-notes</link>
<item><title>EOS-4.33.21M is now available for download.</title>
<pubDate>2026-10-15 00:27:28 +0000</pubDate></item>
<item><title>EOS-4.33.21.2M is now available for download.</title>
<pubDate>2026-11-03 02:28:26 +0000</pubDate></item>
<item><title>EOS-4.36.10M is now available for download.</title>
<pubDate>2026-11-03 02:30:00 +0000</pubDate></item>
</channel></rss>"""

CISCO = b"""<!DOCTYPE html><html><body>
<h1>Release Notes for Cisco Catalyst 9300 Series Switches, Cisco IOS XE Dublin 17.12.x</h1>
<h2>Caveats</h2>
<h2>Resolved Caveats in Cisco IOS XE Dublin 17.12.7a</h2>
<table><tr><th>Identifier</th><th>Headline</th></tr>
<tr><td><a>CSCzz12345</a></td><td>Example switch headline</td></tr></table>
<h2>Resolved Caveats in Cisco IOS XE Dublin 17.12.4</h2>
<table><tr><th>Identifier</th><th>Applicable Models</th><th>Headline</th></tr>
<tr><td><a>CSCzz12346</a></td><td>C9300X</td><td>Example port headline</td></tr></table>
<h2>Open Caveats in Cisco IOS XE Dublin 17.12.4</h2>
<table><tr><th>Identifier</th><th>Headline</th></tr>
<tr><td>CSCzz12347</td><td>Excluded example</td></tr></table></body></html>"""

ARUBA = b"""<!DOCTYPE html><html><body>
<h1>AOS-CX 10.13.1040 Release Notes | for 6300 and 6400 Switches</h1>
<h2>Version history</h2>
<p>All released versions are fully supported by Aruba, unless noted in the table.</p>
<table><tr><th>Version number</th><th>Release date</th><th>Remarks</th></tr>
<tr><td>10.13.1020</td><td>07/06/2024</td>
<td>Released, fully supported, and posted on the Web.</td></tr></table></body></html>"""


def test_arista_announcements_use_reviewed_date_and_leave_model_scope_unknown():
    events = parse_arista_releases(RSS)
    assert [(event["release"], event["date"], event["kind"]) for event in events] == [
        ("4.33.21M", "2026-10-15", "release"),
        ("4.33.21.2M", "2026-11-03", "release"),
    ]
    assert events[0]["platforms"] == []
    assert "pubDate" in events[0]["source_locator"]


def test_cisco_caveats_respect_heading_and_explicit_model_column():
    events = parse_cisco_caveats(CISCO)
    assert [(event["release"], event["platforms"], event["bug_ids"]) for event in events] == [
        ("17.12.7a", [], ["CSCzz12345"]),
        ("17.12.4", ["C9300X"], ["CSCzz12346"]),
    ]
    assert all(event["date"] is None and event["kind"] == "bug_list" for event in events)


def test_aruba_history_uses_publisher_day_first_date_and_family_scope():
    [event] = parse_aruba_history(ARUBA)
    assert event["date"] == "2024-06-07"
    assert event["release"] == "10.13.1020"
    assert event["platforms"] == ["6300 Switch Series", "6400 Switch Series"]
    assert event["kind"] == "release"


@pytest.mark.parametrize(
    "parser", [parse_arista_releases, parse_aruba_history, parse_cisco_caveats]
)
@pytest.mark.parametrize(
    "raw",
    [
        b"<!DOCTYPE html><html><title>Client Challenge</title></html>",
        b"<!DOCTYPE html><html><h1>Access Denied</h1></html>",
        b"<html><meta http-equiv='refresh' content='0;url=/login'></html>",
        b"<html><h2>Unrelated document</h2></html>",
    ],
)
def test_access_and_unsupported_pages_cannot_become_events(parser, raw):
    with pytest.raises(ValueError):
        parser(raw)


def test_arista_rejects_unsupported_date_format():
    with pytest.raises(ValueError, match="pubDate"):
        parse_arista_releases(RSS.replace(b"2026-10-15", b"Thu, 15 Oct 2026"))


def test_arista_rejects_entity_declarations():
    with pytest.raises(ValueError):
        parse_arista_releases(RSS.replace(b"<rss", b"<!DOCTYPE rss [<!ENTITY x 'x'>]><rss"))


def test_cisco_rejects_different_model_document_even_if_tables_match():
    with pytest.raises(ValueError):
        parse_cisco_caveats(CISCO.replace(b"Catalyst 9300", b"Catalyst 9500"))


def test_aruba_does_not_infer_withdrawal_from_unreviewed_remarks():
    with pytest.raises(ValueError):
        parse_aruba_history(
            ARUBA.replace(b"Released, fully supported, and posted on the Web.", b"Withdrawn?")
        )


def _init(tmp_path):
    path = tmp_path / "dataset.json"
    assert cli.main(["init", "--dataset", str(path), "--generated-at", TIMESTAMP]) == 0
    return path


def _import(dataset, source_file, source_url=ARISTA_URL):
    return cli.main(
        [
            "import-document",
            "--dataset",
            str(dataset),
            "--parser",
            "arista-rss",
            "--source-url",
            source_url,
            "--input",
            str(source_file),
            "--retrieved-at",
            TIMESTAMP,
        ]
    )


def test_cli_import_and_report_work_offline(tmp_path, monkeypatch):
    def unexpected_network():
        pytest.fail("offline command tried to fetch the feed")

    monkeypatch.setattr(cli, "fetch_arista", unexpected_network)
    dataset = _init(tmp_path)
    source = tmp_path / "feed.xml"
    source.write_bytes(RSS)
    assert _import(dataset, source) == 0
    actual = json.loads(dataset.read_text())
    [document] = actual["documents"]
    assert document["source_sha256"] == hashlib.sha256(RSS).hexdigest()
    assert len(document["events"]) == 2
    assert {row["vendor"] for row in actual["coverage"]} == {"arista", "aruba", "cisco"}

    json_output = tmp_path / "report.json"
    csv_output = tmp_path / "report.csv"
    assert (
        cli.main(
            [
                "report",
                "--dataset",
                str(dataset),
                "--start",
                "2024-01-01",
                "--end",
                "2026-11-25",
                "--json-output",
                str(json_output),
                "--csv-output",
                str(csv_output),
            ]
        )
        == 0
    )
    assert len(json.loads(json_output.read_text())["events"]) == 2
    assert "observed_releases" in csv_output.read_text()


def test_invalid_import_never_mutates_dataset(tmp_path):
    dataset = _init(tmp_path)
    source = tmp_path / "feed.xml"
    source.write_bytes(RSS)
    before = dataset.read_bytes()
    assert _import(dataset, source, "https://www.arista.com/en/support/login") == 1
    assert dataset.read_bytes() == before


@pytest.mark.parametrize("invalid", [b'{"documents":[],"documents":[]}', b'{"documents":NaN}'])
def test_cli_rejects_ambiguous_and_nonfinite_json(tmp_path, invalid, capsys):
    dataset = tmp_path / "dataset.json"
    dataset.write_bytes(invalid)
    source_file = tmp_path / "feed.xml"
    source_file.write_bytes(RSS)
    assert _import(dataset, source_file) == 1
    assert "Invalid JSON" in capsys.readouterr().err
    assert dataset.read_bytes() == invalid


class _Response(io.BytesIO):
    def __init__(self, raw, *, status=200, url=ARISTA_URL):
        super().__init__(raw)
        self.status = status
        self.url = url

    def geturl(self):
        return self.url


class _Opener:
    def __init__(self, response):
        self.response = response

    def open(self, request, *, timeout):
        assert request.full_url == ARISTA_URL
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") is None
        assert timeout > 0
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _collect(dataset, cache):
    return cli.main(["collect-arista", "--dataset", str(dataset), "--cache-dir", str(cache)])


def test_collect_retains_raw_bytes_and_duplicate_revision(tmp_path, monkeypatch):
    dataset = _init(tmp_path)
    cache = tmp_path / "raw"
    monkeypatch.setattr(
        "infrastructure_impact.collection.release_signals.build_opener",
        lambda *handlers: _Opener(_Response(RSS)),
    )
    assert _collect(dataset, cache) == 0
    before = json.loads(dataset.read_text())["documents"]
    assert _collect(dataset, cache) == 0
    assert json.loads(dataset.read_text())["documents"] == before
    assert (cache / (hashlib.sha256(RSS).hexdigest() + ".xml")).read_bytes() == RSS


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (HTTPError(ARISTA_URL, 403, "Forbidden", {}, None), "access_denied"),
        (HTTPError(ARISTA_URL, 302, "Redirect", {}, None), "redirect_rejected"),
        (
            _Response(b"<html><title>Client Challenge</title></html>"),
            "access_verification_required",
        ),
        (_Response(RSS, url="https://www.arista.com/login"), "redirect_rejected"),
    ],
)
def test_collect_failure_records_gap_without_evidence(tmp_path, monkeypatch, response, reason):
    dataset = _init(tmp_path)
    cache = tmp_path / "raw"
    monkeypatch.setattr(
        "infrastructure_impact.collection.release_signals.build_opener",
        lambda *handlers: _Opener(response),
    )
    assert _collect(dataset, cache) == 1
    actual = json.loads(dataset.read_text())
    assert actual["documents"] == []
    assert any(row["status"] == "blocked" and reason in row["reason"] for row in actual["coverage"])
    assert not cache.exists()


def test_cisco_all_models_does_not_create_exact_model_scope():
    events = parse_cisco_caveats(CISCO.replace(b"<td>C9300X</td>", b"<td>All models</td>"))
    assert events[1]["platforms"] == []


def test_cisco_hidden_headline_cannot_substantiate_a_bug_row():
    raw = CISCO.replace(b"Example port headline", b"<em hidden>Fabricated headline</em>")
    with pytest.raises(ValueError, match="visibility"):
        parse_cisco_caveats(raw)


def test_cisco_hidden_heading_cannot_extend_previous_release_scope():
    raw = CISCO.replace(
        b"<h2>Resolved Caveats in Cisco IOS XE Dublin 17.12.4",
        b"<h2 hidden>Resolved Caveats in Cisco IOS XE Dublin 17.12.4",
    )
    assert [event["release"] for event in parse_cisco_caveats(raw)] == ["17.12.7a"]


def test_report_stage_failure_preserves_previous_output(tmp_path):
    dataset = _init(tmp_path)
    old_output = tmp_path / "report.json"
    old_output.write_bytes(b"previous")
    unavailable_output = tmp_path / "nonexistent" / "report.csv"
    assert (
        cli.main(
            [
                "report",
                "--dataset",
                str(dataset),
                "--start",
                "2024-01-01",
                "--end",
                "2026-11-25",
                "--json-output",
                str(old_output),
                "--csv-output",
                str(unavailable_output),
            ]
        )
        == 1
    )
    assert old_output.read_bytes() == b"previous"
    assert not unavailable_output.exists()


def test_aruba_does_not_claim_html_is_pdf_origin_bytes(tmp_path, capsys):
    dataset = _init(tmp_path)
    source = tmp_path / "history.html"
    source.write_bytes(ARUBA)
    command = [
        "import-document",
        "--dataset",
        str(dataset),
        "--parser",
        "aruba-history",
        "--source-url",
        cli.ARUBA_URL,
        "--input",
        str(source),
        "--retrieved-at",
        TIMESTAMP,
    ]
    assert cli.main(command) == 1
    assert "rendered HTML capture" in capsys.readouterr().err
    assert cli.main([*command, "--capture-method", "rendered_capture"]) == 0
    [document] = json.loads(dataset.read_text())["documents"]
    assert document["capture_method"] == "rendered_capture"
    assert document["source_sha256"] == hashlib.sha256(ARUBA).hexdigest()


def test_collect_records_truncated_http_body_as_network_failure(tmp_path, monkeypatch):
    from http.client import IncompleteRead

    class TruncatedResponse(_Response):
        def read(self, *args):
            raise IncompleteRead(b"<rss", 10)

        read1 = read

    dataset = _init(tmp_path)
    cache = tmp_path / "raw"
    monkeypatch.setattr(
        "infrastructure_impact.collection.release_signals.build_opener",
        lambda *handlers: _Opener(TruncatedResponse(b"")),
    )
    assert _collect(dataset, cache) == 1
    actual = json.loads(dataset.read_text())
    assert actual["documents"] == []
    assert any("network_error" in row["reason"] for row in actual["coverage"])


def test_arista_rejects_duplicate_channel_identity():
    raw = RSS.replace(
        b"<title>Arista Networks :: Software Release</title>",
        b"<title>Arista Networks :: Software Release</title><title>Unreviewed</title>",
    )
    with pytest.raises(ValueError, match="channel"):
        parse_arista_releases(raw)


def test_cisco_hidden_heading_ancestor_cannot_extend_previous_release_scope():
    heading = b"<h2>Resolved Caveats in Cisco IOS XE Dublin 17.12.4</h2>"
    raw = CISCO.replace(heading, b"<div hidden>" + heading + b"</div>")
    assert [event["release"] for event in parse_cisco_caveats(raw)] == ["17.12.7a"]


def test_collect_retains_distinct_failure_intervals(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    class Clock(datetime):
        day = 1

        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 11, cls.day, tzinfo=UTC)

    dataset = _init(tmp_path)
    cache = tmp_path / "raw"
    monkeypatch.setattr(cli, "datetime", Clock)
    monkeypatch.setattr(
        cli, "fetch_arista", lambda: (_ for _ in ()).throw(HTTPError(ARISTA_URL, 403, "", {}, None))
    )
    assert _collect(dataset, cache) == 1
    Clock.day = 25
    assert _collect(dataset, cache) == 1
    assert _collect(dataset, cache) == 1
    observed = json.loads(dataset.read_text())["coverage"]
    assert [(row["start"], row["end"]) for row in observed if row["status"] == "blocked"] == [
        ("2026-11-01", "2026-11-01"),
        ("2026-11-25", "2026-11-25"),
    ]
