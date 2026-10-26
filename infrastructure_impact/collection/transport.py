"""Bounded HTTPS retrieval with per-plugin official-domain policy."""

import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..plugins.registry import default_registry
from ..storage.repository import evidence
from .errors import check_access_response


def allowed(url, vendor):
    if vendor != "upstream" and vendor not in default_registry().names():
        return False
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    return (
        u.scheme == "https"
        and not u.username
        and not u.password
        and u.port in (None, 443)
        and any(
            host == d or host.endswith("." + d)
            for d in (
                ("mitre.org", "cve.org")
                if vendor == "upstream"
                else default_registry().get(vendor).domains
            )
        )
    )


def fetch(db, url, vendor):
    if not allowed(url, vendor):
        raise ValueError("URL outside configured official vendor domains")
    cached = db.execute("SELECT * FROM http_cache WHERE url=?", (url,)).fetchone()
    headers = {
        "User-Agent": "VendorImpact/0.2 (public advisory research)",
        "Accept": "application/json,application/xml,text/html,*/*",
    }
    if cached:
        if cached["etag"]:
            headers["If-None-Match"] = cached["etag"]
        if cached["modified"]:
            headers["If-Modified-Since"] = cached["modified"]

    class Redirects(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            if not allowed(newurl, vendor):
                raise ValueError("Cross-domain redirect outside vendor allowlist")
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)

    opener = build_opener(Redirects())
    for attempt in range(2):
        try:
            with opener.open(Request(url, headers=headers), timeout=25) as response:
                raw = response.read(15_000_001)
                if len(raw) > 15_000_000:
                    raise ValueError("Document exceeds 15 MB limit")
                with db:
                    ev = evidence(db, raw, url, response.headers.get("Content-Type", ""))
                    db.execute(
                        "INSERT OR REPLACE INTO http_cache VALUES(?,?,?,?)",
                        (
                            url,
                            response.headers.get("ETag"),
                            response.headers.get("Last-Modified"),
                            ev["id"],
                        ),
                    )
                check_access_response(raw)
                return raw
        except HTTPError as e:
            if e.code == 304 and cached:
                raw = db.execute(
                    "SELECT raw FROM evidence WHERE id=?", (cached["evidence_id"],)
                ).fetchone()["raw"]
                check_access_response(raw)
                return raw
            if attempt or e.code not in (429, 500, 502, 503, 504):
                raise
        except (OSError, TimeoutError):
            if attempt:
                raise
        time.sleep(0.5)
