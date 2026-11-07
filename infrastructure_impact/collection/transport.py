"""Bounded HTTPS retrieval with per-plugin official-domain policy."""

import time
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..source_policy import allowed
from ..storage.repository import evidence
from .errors import SourceHTTPError, check_access_response


def fetch(db, url, vendor, *, max_bytes=15_000_000, allowed_urls: frozenset[str] | None = None):
    if allowed_urls is not None and url not in allowed_urls:
        raise ValueError("URL outside exact retrieval allowlist")
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
            if allowed_urls is not None and newurl not in allowed_urls:
                raise ValueError("redirect outside exact retrieval allowlist")
            if not allowed(newurl, vendor):
                raise ValueError("Cross-domain redirect outside vendor allowlist")
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)

    opener = build_opener(Redirects())
    for attempt in range(2):
        try:
            with opener.open(Request(url, headers=headers), timeout=25) as response:
                raw = response.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    raise ValueError(f"Document exceeds {max_bytes}-byte limit")
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
                from ..storage.observations import observe

                observe(db, vendor, url, ev["id"], response.status)
                return raw
        except HTTPError as e:
            if e.code == 304 and cached:
                raw = db.execute(
                    "SELECT raw FROM evidence WHERE id=?", (cached["evidence_id"],)
                ).fetchone()["raw"]
                if len(raw) > max_bytes:
                    raise ValueError(f"Cached document exceeds {max_bytes}-byte limit")
                check_access_response(raw)
                from ..storage.observations import observe

                observe(db, vendor, url, cached["evidence_id"], 304)
                return raw
            if attempt or e.code not in (429, 500, 502, 503, 504):
                raise SourceHTTPError(e, url, e.read(15000)) from e
        except (OSError, TimeoutError):
            if attempt:
                raise
        time.sleep(0.5)
