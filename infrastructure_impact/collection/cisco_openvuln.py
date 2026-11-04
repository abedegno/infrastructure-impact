"""Credential-isolated Cisco openVuln transport; no shared public HTTP cache.

Reviewed 2026-11-04: developer.cisco.com/docs/psirt/authentication/ and /all/;
sec.cloudapps.cisco.com/security/center/resources/openvulnapi (5/s,30/min,5000/day).
`opener` is a build_opener-compatible factory, invoked for two separate sessions.
`clock` returns an aware datetime. Auth sessions never use evidence/cache helpers.
"""

import json
import math
import os
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..storage.repository import evidence
from ..storage.switching import SERVICE, defer_request, request_succeeded, reserve_request
from .errors import CiscoAccessError

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
API_HOST = "apix.cisco.com"
MAX_BYTES = 8_000_000
TOKEN_MAX_BYTES = 64_000
_PRIVATE_KEYS = frozenset(
    {
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "clientsecret",
        "clientid",
        "authorization",
        "password",
        "secret",
        "token",
        "apikey",
        "credentials",
    }
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        raise CiscoAccessError("redirect_rejected")


def _private_key(value):
    return re.sub(r"[^a-z0-9]", "", value.lower()) in _PRIVATE_KEYS


def _has_private_content(value, private_values):
    # Iteration also covers deeply nested valid JSON without Python recursion.
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if any(_private_key(key) for key in item):
                return True
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str) and any(secret in item for secret in private_values):
            return True
    return False


def _strict_json(raw):
    def reject_constant(_):
        raise ValueError("Nonfinite JSON")

    def unique_members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result

    # The decoder's exception holds raw input. Discard it before raising outward.
    invalid = False
    try:
        result = json.loads(raw, parse_constant=reject_constant, object_pairs_hook=unique_members)
    except (ValueError, UnicodeError, RecursionError):
        invalid = True
    if invalid:
        raise CiscoAccessError("invalid_json")
    return result


class CiscoOpenVuln:
    def __init__(self, db, *, environ=None, opener=None, clock=None):
        self._db = db
        environ = os.environ if environ is None else environ
        self._client_id = environ.get("CISCO_OPENVULN_CLIENT_ID", "")
        self._client_secret = environ.get("CISCO_OPENVULN_CLIENT_SECRET", "")
        self._token = None
        self._expires_at = None
        self._private_values = {value for value in (self._client_id, self._client_secret) if value}
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        factory = opener or build_opener
        self._token_session = factory(_NoRedirect())
        self._api_session = factory(_NoRedirect())

    def _time(self):
        return self._clock().astimezone(timezone.utc)

    def _url_allowed(self, url):
        invalid = False
        try:
            parts = urlsplit(url)
            invalid = (
                parts.scheme != "https"
                or parts.netloc != API_HOST
                or not parts.path.startswith("/security/advisories/v2/")
                or bool(parts.fragment)
                or any(ord(c) <= 32 for c in url)
                or any(_private_key(key) for key, _ in parse_qsl(parts.query))
            )
        except ValueError:
            invalid = True
        if invalid or any(value in url for value in self._private_values):
            raise CiscoAccessError("url_rejected")

    def _retry_after(self, value):
        invalid = False
        try:
            seconds = float(value)
            if not math.isfinite(seconds) or seconds < 0:
                invalid = True
            else:
                return (self._time() + timedelta(seconds=seconds)).isoformat()
        except (TypeError, ValueError, OverflowError):
            invalid = True
        if invalid:
            try:
                date = parsedate_to_datetime(value)
                if date.tzinfo is not None:
                    return max(self._time(), date.astimezone(timezone.utc)).isoformat()
            except (TypeError, ValueError, OverflowError):
                pass
        return None

    def _request(self, session, request, *, auth=False):
        at = self._time().isoformat()
        reservation = reserve_request(self._db, SERVICE, at)
        if not reservation["allowed"]:
            raise CiscoAccessError("rate_limited", retry_at=reservation["retry_at"])
        status, raw, retry_after, code = None, None, None, None
        try:
            with session.open(request, timeout=25) as response:
                status = response.status
                final_url = response.geturl()
                if final_url and final_url != request.full_url:
                    code = "redirect_rejected"
                elif 200 <= status < 300:
                    limit = TOKEN_MAX_BYTES if auth else MAX_BYTES
                    raw = response.read(limit + 1)
                    if len(raw) > limit:
                        code = "response_too_large"
                elif status == 429:
                    retry_after = self._retry_after(response.headers.get("Retry-After"))
        except HTTPError as error:
            # Do not read, retain, stringify or chain reflected error bodies/headers.
            status = error.code
            if status == 429:
                retry_after = self._retry_after((error.headers or {}).get("Retry-After"))
            error.close()
        except CiscoAccessError:
            code = "redirect_rejected"
        except Exception:
            code = "network_error"
        # Outside the except blocks: outward exceptions retain no sensitive context.
        if code == "network_error" or (status is not None and 500 <= status <= 599):
            until = defer_request(self._db, SERVICE, self._time().isoformat())
            raise CiscoAccessError(code or "service_unavailable", retry_at=until)
        if code:
            raise CiscoAccessError(code)
        if status == 429:
            until = defer_request(self._db, SERVICE, self._time().isoformat(), retry_at=retry_after)
            raise CiscoAccessError("rate_limited", retry_at=until)
        if status is not None and 300 <= status < 400:
            raise CiscoAccessError("redirect_rejected")
        if auth and status is not None and not 200 <= status < 300:
            raise CiscoAccessError("auth_rejected")
        if status == 403:
            raise CiscoAccessError("access_denied")
        if status == 401:
            return None
        if status is None or not 200 <= status < 300:
            raise CiscoAccessError("http_error")
        return raw

    def _authenticate(self):
        raw = self._request(
            self._token_session,
            Request(
                TOKEN_URL,
                data=urlencode(
                    {
                        "grant_type": "client_credentials",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    }
                ).encode(),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            ),
            auth=True,
        )
        body = _strict_json(raw)
        if not isinstance(body, dict):
            raise CiscoAccessError("auth_rejected")
        token, lifetime = body.get("access_token"), body.get("expires_in")
        if (
            not isinstance(token, str)
            or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token)
            or not isinstance(body.get("token_type"), str)
            or body["token_type"].lower() != "bearer"
            or type(lifetime) not in (int, float)
            or not 0 < lifetime <= 86400
        ):
            raise CiscoAccessError("auth_rejected")
        self._token = token
        self._private_values.add(token)
        # Lifetime is measured from request start in get_json, never from response completion.
        self._expires_at = self._auth_started + timedelta(seconds=lifetime)

    def get_json(self, url: str) -> bytes:
        self._url_allowed(url)
        if not self._client_id or not self._client_secret:
            raise CiscoAccessError("auth_not_configured")
        for attempt in range(2):
            if not self._token or self._time() >= self._expires_at:
                self._auth_started = self._time()
                self._authenticate()
            raw = self._request(
                self._api_session,
                Request(
                    url,
                    headers={
                        "Authorization": "Bearer " + self._token,
                        "Accept": "application/json",
                    },
                ),
            )
            if raw is None:
                self._token, self._expires_at = None, None
                if attempt:
                    raise CiscoAccessError("auth_rejected")
                continue
            body = _strict_json(raw)
            if not isinstance(body, dict) or not (
                isinstance(body.get("advisories"), list) or isinstance(body.get("advisoryId"), str)
            ):
                raise CiscoAccessError("unsupported_response")
            # Inspect decoded string values: quotes/unicode escapes cannot hide echoes.
            if _has_private_content(body, self._private_values) or any(
                value.encode() in raw for value in self._private_values
            ):
                raise CiscoAccessError("credential_response_rejected")
            with self._db:
                evidence(self._db, raw, url, "application/json")
            request_succeeded(self._db, SERVICE)
            return raw
        raise CiscoAccessError("auth_rejected")
