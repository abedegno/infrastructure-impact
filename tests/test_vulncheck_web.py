"""Run the synthetic browser contract in both supported Python CI jobs."""

import subprocess
from pathlib import Path


def test_vulncheck_browser_contract():
    subprocess.run(
        ["node", "tests/test_vulncheck_web.js"], check=True, cwd=Path(__file__).resolve().parents[1]
    )


def test_vulncheck_is_an_immutable_reader_asset(tmp_path, monkeypatch):
    import hashlib

    from infrastructure_impact.application.publication import write_reader_assets
    from infrastructure_impact.settings import PACKAGE

    monkeypatch.setenv("IMPACT_HOME", str(tmp_path))
    monkeypatch.setenv("IMPACT_BASE_PATH", "/synthetic/")
    destination = tmp_path / "public"
    destination.mkdir()
    write_reader_assets(destination, {"generated_at": "2026-11-19T12:00:00Z"})
    raw = (PACKAGE / "web/vulncheck.js").read_bytes()
    assert (destination / "vulncheck.js").read_bytes() == raw
    asset = "assets/" + hashlib.sha256(raw).hexdigest() + ".js"
    assert (destination / asset).read_bytes() == raw
    assert 'src="/synthetic/' + asset + '"' in (destination / "index.html").read_text()
    assert not (destination / "vulncheck.json").exists()
    from infrastructure_impact.http import Application

    status, content_type, body = Application(tmp_path).route(
        {"REQUEST_METHOD": "GET", "PATH_INFO": "/vulncheck.js"},
        _opened=(destination, {}),
    )
    assert status == 200 and "javascript" in content_type
    assert body == raw
