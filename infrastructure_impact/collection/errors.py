"""Stable operational failure categories; these never assert product affectedness."""

from urllib.error import HTTPError


class AccessVerificationRequired(ValueError):
    """The source returned an access challenge, not an advisory."""


def check_access_response(raw):
    prefix = raw[:15000].lower()
    if prefix.lstrip().startswith((b"<!doctype html", b"<html")) and (
        b"token.awswaf.com" in prefix
        and b"javascript is disabled" in prefix
        and b"not a robot" in prefix
    ):
        raise AccessVerificationRequired(
            "Source requires interactive bot verification. No challenge execution or product inference performed."
        )


def failure_code(error):
    if isinstance(error, AccessVerificationRequired):
        return "access_verification_required"
    if isinstance(error, HTTPError):
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
