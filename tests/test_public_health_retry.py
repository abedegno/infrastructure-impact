"""Whole-publication retries against synthetic HTTP generations only."""

import functools
import json
import threading
import time
from contextlib import contextmanager
from http.client import IncompleteRead
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest
from test_static_delivery import dataset

import checks.public_health as health
from infrastructure_impact.application.publication import publish


@pytest.fixture(scope="module")
def generations(tmp_path_factory):
    root = tmp_path_factory.mktemp("retry-publications")
    data = dataset()
    old = publish(data, root / "old", publication_format="v2")
    data["benchmark_cohort"]["CVE-2025-12345"] = "Changed synthetic generation"
    new = publish(data, root / "new", publication_format="v2")
    return old, new


@contextmanager
def serving(generations, fault, *, persistent=False):
    old, new = generations
    requests = []
    switched = False

    class Handler(SimpleHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            nonlocal switched
            path = self.path.lstrip("/") or "index.html"
            requests.append(path)
            directory = new if switched else old
            if path == "manifest.json" and fault == "network" and not switched:
                switched = True
                self.send_error(503)
                return
            raw = (directory / path).read_bytes()
            if path == "publication-v2.json" and (not switched or persistent):
                if fault == "size":
                    raw += b" "  # One byte beyond the descriptor, as in the incident.
                elif fault == "hash":
                    raw = b"x" + raw[1:]
                switched = True
            if path == "manifest.json" and fault == "generation" and not switched:
                value = json.loads(raw)
                value["generation"] = "wrong-generation"
                raw = json.dumps(value).encode()
            if path == "data/index.json" and fault == "generation":
                switched = True
            self.send_response(200)
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(old)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("size", "part_size"),
        ("hash", "fingerprint"),
        ("generation", "mixed_generation"),
        ("network", "http_transient"),
    ],
)
def test_retry_reloads_manifest_and_recovers(generations, monkeypatch, capsys, fault, reason):
    # Retrying only the failed fetch would keep the old manifest/index and fail again.
    monkeypatch.setattr(time, "sleep", lambda _: None)
    with serving(generations, fault) as (origin, requests):
        result = health.check_with_retries(origin)
        assert requests.count("manifest.json") == 2
        clean = health.check(origin)
    assert result == clean  # Byte accounting and all per-check state reset, too.
    assert (
        result["publication"]
        == json.loads((generations[1] / "manifest.json").read_bytes())["generation"]
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    retries = [
        json.loads(line)
        for line in captured.err.splitlines()
        if json.loads(line)["event"] == "monitor_retry"
    ]
    assert retries == [
        {
            "event": "monitor_retry",
            "attempt": 1,
            "next_attempt": 2,
            "reason": reason,
            "delay_seconds": 2,
        }
    ]


@pytest.mark.parametrize("fault", ["hash", "size"])
def test_persistent_corruption_stops_after_three_checks(generations, monkeypatch, capsys, fault):
    sleeps = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    with serving(generations, fault, persistent=True) as (origin, requests):
        with pytest.raises(
            AssertionError, match="Fingerprint mismatch|Publication part exceeds monitor budget"
        ):
            health.check_with_retries(origin)
    assert requests.count("manifest.json") == 3
    assert sleeps == [2, 5]
    assert capsys.readouterr().out == ""


def test_single_attempt_keeps_original_failure(generations, monkeypatch, capsys):
    monkeypatch.setattr(time, "sleep", lambda _: pytest.fail("unexpected retry"))
    with serving(generations, "size") as (origin, requests):
        with pytest.raises(AssertionError, match="Publication part exceeds monitor budget"):
            health.check_with_retries(origin, attempts=1)
    assert requests.count("manifest.json") == 1
    assert "monitor_retry" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "error",
    [
        AssertionError("Default publication exceeds monitor budget"),
        AssertionError("Private projection failed"),
        ValueError("unexpected programming error"),
        KeyError("unexpected schema field"),
        HTTPError("https://example.test/?secret=hidden", 403, "secret", None, None),
    ],
)
def test_unrelated_errors_and_aggregate_capacity_do_not_retry(monkeypatch, error):
    operation = Mock(side_effect=error)
    monkeypatch.setattr(health, "check", operation)
    with pytest.raises(type(error)) as raised:
        health.check_with_retries("https://example.test/?secret=hidden")
    assert raised.value is error
    assert operation.call_count == 1


def test_cli_outputs_one_success_json(generations, monkeypatch, capsys):
    monkeypatch.setattr(time, "sleep", lambda _: None)
    with serving(generations, "size") as (origin, _):
        monkeypatch.setattr("sys.argv", ["public_health.py", origin])
        health.main()
    output = capsys.readouterr()
    assert len(output.out.splitlines()) == 1
    assert json.loads(output.out)["status"] == "fresh"
    assert "monitor_retry" in output.err
    assert origin not in output.err


@pytest.mark.parametrize("attempts", [0, 4, True])
def test_retry_count_is_bounded(attempts):
    with pytest.raises(ValueError, match="attempts"):
        health.check_with_retries("https://example.test", attempts=attempts)


@pytest.mark.parametrize(
    "error",
    [
        URLError("https://example.test/?secret=hidden"),
        TimeoutError("secret timeout"),
        ConnectionResetError("secret reset"),
        IncompleteRead(b"secret body", 100),
    ],
)
def test_network_retry_diagnostic_never_includes_exception_details(monkeypatch, capsys, error):
    monkeypatch.setattr(time, "sleep", lambda _: None)
    operation = Mock(side_effect=[error, {"status": "fresh"}])
    monkeypatch.setattr(health, "check", operation)
    assert health.check_with_retries("https://example.test/?secret=hidden") == {"status": "fresh"}
    output = capsys.readouterr()
    diagnostic = json.loads(output.err)
    assert diagnostic["reason"] == "network"
    assert "secret" not in output.err
    assert output.out == ""
