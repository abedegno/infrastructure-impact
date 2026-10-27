"""Public access probes retain metadata only and enforce retrieval boundaries."""

from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from checks.source_access import MAX_BYTES, SOURCES, probe


class Response(BytesIO):
    status = 200


class Opener:
    def __init__(self, raw):
        self.raw = raw

    def open(self, request, timeout):
        assert timeout == 25 and not request.has_header("Authorization")
        return Response(self.raw)


def test_probe_rejects_unreviewed_urls_and_never_exposes_response_bodies():
    with pytest.raises(ValueError):
        probe("cisco", "ucs-rack-html", "https://www.cisco.com/other")
    with patch("checks.source_access.build_opener", return_value=Opener(b"PRIVATE_BODY_SENTINEL")):
        result = probe(*SOURCES[0])
    assert result["outcome"] == "retrieved_requires_content_review"
    assert result["bytes"] == 21 and "PRIVATE_BODY_SENTINEL" not in str(result)


def test_http_denials_and_oversized_sources_are_explicit_gaps():
    error = HTTPError(SOURCES[0][2], 403, "SECRET_ERROR_BODY", {}, BytesIO(b"SECRET_BODY"))
    with patch("checks.source_access.build_opener") as factory:
        factory.return_value.open.side_effect = error
        result = probe(*SOURCES[0])
    assert result["http_status"] == 403 and result["reason"] == "http_error"
    assert "SECRET" not in str(result)
    with patch("checks.source_access.build_opener", return_value=Opener(b"x" * (MAX_BYTES + 1))):
        assert probe(*SOURCES[0])["reason"] == "response_budget_exceeded"


def test_cross_vendor_redirect_and_known_browser_challenge_are_rejected():
    def opener(redirects):
        with pytest.raises(ValueError):
            redirects.redirect_request(None, None, 302, "", {}, "https://attacker.example/")
        return Opener(
            b"<html><title>Client Challenge</title>/_fs-ch- javascript is disabled</html>"
        )

    with patch("checks.source_access.build_opener", side_effect=opener):
        assert probe(*SOURCES[0])["reason"] == "access_or_redirect_policy_rejected"


def test_optional_f5_normalization_retains_only_fixed_counts_and_fingerprint():
    import json

    source = next(s for s in SOURCES if s[0] == "f5")
    document = dict(
        schema_version=2,
        adapter_version="synthetic-parser",
        cves=["CVE-2099-99999"],
        assessments=[dict(status="affected"), dict(status="unaffected")],
        title="PRIVATE_BODY_SENTINEL",
        notes=["PRIVATE_BODY_SENTINEL"],
    )
    with (
        patch("checks.source_access.build_opener", return_value=Opener(b"PRIVATE_BODY_SENTINEL")),
        patch(
            "infrastructure_impact.plugins.registry.PluginRegistry.normalize", return_value=document
        ),
    ):
        report = probe(*source, verify_f5=True)
    assert report["normalization"] == dict(
        status="passed",
        schema_version=2,
        adapter_version="synthetic-parser",
        cves=1,
        assessments=2,
        affected=1,
        unaffected=1,
    )
    assert "PRIVATE_BODY_SENTINEL" not in json.dumps(report)
    with (
        patch("checks.source_access.build_opener", return_value=Opener(b"PRIVATE_BODY_SENTINEL")),
        patch(
            "infrastructure_impact.plugins.registry.PluginRegistry.normalize",
            side_effect=ValueError("PRIVATE_BODY_SENTINEL"),
        ),
    ):
        report = probe(*source, verify_f5=True)
    assert report["normalization"]["status"] == "rejected_requires_review"
    assert "PRIVATE_BODY_SENTINEL" not in json.dumps(report)


def test_failed_f5_verification_writes_metadata_before_nonzero_exit(tmp_path, monkeypatch):
    import json

    import checks.source_access as access

    output = tmp_path / "access.json"
    source = next(s for s in SOURCES if s[0] == "f5")
    monkeypatch.setattr(access, "SOURCES", (source,))
    monkeypatch.setattr(
        access, "probe", lambda *args, **kwargs: dict(vendor="f5", outcome="unavailable")
    )
    monkeypatch.setattr("sys.argv", ["source_access", "--verify-f5", "--output", str(output)])
    with pytest.raises(SystemExit, match="normalization did not pass"):
        access.main()
    assert json.loads(output.read_text())["observations"][0]["outcome"] == "unavailable"
