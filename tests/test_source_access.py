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
