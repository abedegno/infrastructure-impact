"""Bounded HTTPS retrieval with per-plugin official-domain policy."""

import time
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..source_policy import allowed
from ..storage.repository import evidence
from .errors import SourceHTTPError, check_access_response


def _read_with_budget(response, limit, budget):
    """Read at most limit bytes without exceeding the operation's allowance.

    Only an empty read proves EOF: a short chunk may precede more data or a
    failing read. Exhaustion before that proof fails closed for documents.
    """
    chunks = []
    size = 0
    while size < limit:
        requested = min(64_000, limit - size, budget.remaining_received_bytes)
        if requested == 0:
            raise ValueError("HTTP received body budget exhausted before EOF")
        try:
            chunk = response.read(requested)
        except Exception as error:
            partial = getattr(error, "partial", None)
            # Some readers expose bytes delivered before failure; otherwise the
            # bounded request is the conservative upper bound on that delivery.
            charge = len(partial) if isinstance(partial, (bytes, bytearray)) else requested
            budget.consume_received(charge)
            raise
        budget.consume_received(len(chunk))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def fetch(
    db,
    url,
    vendor,
    *,
    max_bytes=15_000_000,
    allowed_urls: frozenset[str] | None = None,
    budget=None,
    forbid_redirects=False,
):
    """Retrieve an official document, optionally sharing a closed-operation budget.

    Budgets require redirect refusal so urllib cannot dispatch or drain response
    bodies outside this function's bounded accounting.
    """
    if budget is not None and not forbid_redirects:
        raise ValueError("Transport budgets require redirect refusal")
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
            if forbid_redirects:
                raise ValueError("HTTP redirects forbidden for this operation")
            if allowed_urls is not None and newurl not in allowed_urls:
                raise ValueError("redirect outside exact retrieval allowlist")
            if not allowed(newurl, vendor):
                raise ValueError("Cross-domain redirect outside vendor allowlist")
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)

    opener = build_opener(Redirects())
    for attempt in range(2):
        if budget is not None:
            if budget.remaining_received_bytes == 0:
                raise ValueError("HTTP received body budget exhausted")
            budget.start_attempt()
        try:
            with opener.open(Request(url, headers=headers), timeout=25) as response:
                raw = (
                    response.read(max_bytes + 1)
                    if budget is None
                    else _read_with_budget(response, max_bytes + 1, budget)
                )
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
            error_body = None
            if budget is not None:
                try:
                    error_body = _read_with_budget(e, 15000, budget)
                except (OSError, HTTPException):
                    if attempt or e.code not in (429, 500, 502, 503, 504):
                        raise
                    # The read already charged known or conservative partial
                    # delivery. Preserve the original HTTP status's retry rule.
                finally:
                    e.close()
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
                raise SourceHTTPError(
                    e, url, e.read(15000) if budget is None else error_body
                ) from e
        except (OSError, TimeoutError):
            if attempt:
                raise
        time.sleep(0.5)
