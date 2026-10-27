"""Stable operational failure categories; these never assert product affectedness."""

from urllib.error import HTTPError


class PublisherScopeUnavailable(ValueError):
    """A retrieved publisher envelope has no explicit CVE/product scope."""


class AccessVerificationRequired(ValueError):
    """The source returned an access challenge, not an advisory."""


def check_access_response(raw):
    prefix = raw[:15000].lower()
    html = prefix.lstrip().startswith((b"<!doctype html", b"<html"))
    if html and all(
        marker in prefix
        for marker in (
            b"function checksession(",
            b"function syncnothing(",
            b"https://auth.hpe.com/api/v1/sessions/me",
            b'<body onload="main();">',
        )
    ):
        raise AccessVerificationRequired(
            "Source returned a browser session-check shell, not document content. No login synchronization or product inference performed."
        )
    if (
        html
        and b"<title>client challenge</title>" in prefix
        and b"/_fs-ch-" in prefix
        and b"javascript is disabled" in prefix
    ):
        raise AccessVerificationRequired(
            "Source returned an interactive client challenge; no challenge execution or product inference performed."
        )
    if html and (
        b"token.awswaf.com" in prefix
        and b"javascript is disabled" in prefix
        and b"not a robot" in prefix
    ):
        raise AccessVerificationRequired(
            "Source requires interactive bot verification. No challenge execution or product inference performed."
        )


class SourceHTTPError(HTTPError):
    """Bounded response diagnostics without exporting headers, cookies or body."""

    def __init__(self, error, requested_url, body):
        super().__init__(error.url, error.code, error.reason, error.headers, None)
        self.requested_url = requested_url
        self.edge_denial = (error.headers or {}).get(
            "Server", ""
        ).lower() == "akamaighost" and b"access denied" in body.lower()


def failure_code(error):
    if isinstance(error, PublisherScopeUnavailable):
        return "publisher_scope_unavailable"
    if isinstance(error, SourceNotRetained):
        return "retained_source_missing"
    if isinstance(error, AccessVerificationRequired):
        return "access_verification_required"
    if isinstance(error, HTTPError):
        if error.code in (404, 410):
            return (
                "redirect_target_missing"
                if getattr(error, "requested_url", error.url) != error.url
                else "source_missing"
            )
        if error.code == 403 and getattr(error, "edge_denial", False):
            return "edge_access_denied"
        return (
            "rate_limited"
            if error.code == 429
            else "access_denied"
            if error.code in (401, 403)
            else "http_error"
        )
    if isinstance(error, (TimeoutError, OSError)):
        return "network_error"
    if isinstance(error, (ValueError, KeyError)):
        return "unsupported_or_invalid_document"
    return "collection_error"


class SourceNotRetained(ValueError):
    """An offline resolution dependency has no retained source bytes."""
