"""Production WSGI reader. It can access publications, never the evidence vault."""

import json
import logging
import mimetypes
import re
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qs

from .exports import assessment_export, csv_export, select

LOG = logging.getLogger(__name__)
CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")


class BadRequest(ValueError):
    """Invalid client query, distinct from a damaged publication."""


class PublicationStore:
    def __init__(self, root):
        self.root = Path(root)
        self._lock = Lock()
        self._generation = None
        self._data = None

    def read(self):
        generation = (self.root / "current").resolve(strict=True)
        if not generation.is_relative_to((self.root / "generations").resolve()):
            raise ValueError("Invalid publication pointer")
        with self._lock:
            if generation != self._generation:
                self._data = json.loads((generation / "snapshot.json").read_text())
                self._generation = generation
            return generation, self._data


class Application:
    def __init__(self, root, stale_after=129600):
        self.store = PublicationStore(root)
        self.stale_after = stale_after

    def __call__(self, environ, start_response):
        try:
            status, content_type, body = self.route(environ)
        except BadRequest:
            status, content_type, body = 400, "application/json", b'{"error":"Invalid request"}'
        except Exception:
            LOG.exception("Publication request failed")
            status, content_type, body = (
                503,
                "application/json",
                b'{"error":"Publication temporarily unavailable"}',
            )
        statuses = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            405: "Method Not Allowed",
            503: "Service Unavailable",
        }
        headers = [
            ("Content-Type", content_type + "; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            (
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            ),
        ]
        if status == 405:
            headers.append(("Allow", "GET, HEAD"))
        start_response(f"{status} {statuses[status]}", headers)
        return [b"" if environ.get("REQUEST_METHOD") == "HEAD" else body]

    def route(self, environ):
        if environ.get("REQUEST_METHOD") not in ("GET", "HEAD"):
            return 405, "application/json", b'{"error":"Read-only service"}'
        path = environ.get("PATH_INFO", "/")
        if path == "/health/live":
            return self.json({"status": "ok"})
        try:
            generation, data = self.store.read()
        except FileNotFoundError:
            return 503, "application/json", b'{"error":"Awaiting first successful publication"}'
        if path in ("/health/ready", "/api/v1/health"):
            published = datetime.fromisoformat(data["generated_at"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - published).total_seconds()
            stale = age > self.stale_after
            receipt_path = self.store.root / "collection-status.json"
            receipt = (
                json.loads(receipt_path.read_text())
                if receipt_path.exists()
                else (data.get("collector", {}).get("last_run"))
            )
            return self.json(
                {
                    "status": "stale" if stale else "ready",
                    "stale": stale,
                    "publication": data["publication"],
                    "generated_at": data["generated_at"],
                    "collector": data.get("collector"),
                    "latest_collection": receipt,
                    "source_errors": receipt["failures"] if receipt else None,
                    "historical_source_error_urls": sum(
                        h["outcome"] == "error" for h in data["health"]
                    ),
                },
                status=503 if stale else 200,
            )
        if path == "/api/v1/catalogue":
            return self.json(data.get("catalogue", {}))
        query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        ids = None
        if "cves" in query or "cve" in query:
            ids = sorted(set(",".join(query.get("cves", query.get("cve", []))).upper().split(",")))
            if len(ids) > 200 or not all(CVE.fullmatch(cid) for cid in ids):
                raise BadRequest("Invalid CVE cohort")
        if path in (
            "/api/state",
            "/api/export.json",
            "/api/export.csv",
            "/api/assessments",
            "/api/v1/advisories",
            "/api/v1/assessments",
        ):
            selected = select(data, ids)
            if path == "/api/state":
                return self.json(selected)
            selected = assessment_export(selected)
            if path.endswith(".csv"):
                return 200, "text/csv", csv_export(selected).encode()
            if path == "/api/export.json":
                return self.json(selected)
            records = selected["records"]
            if query.get("vendor"):
                vendor = query["vendor"][0]
                if vendor not in data["vendors"]:
                    raise BadRequest("Unknown vendor")
                records = [r for r in records if r["vendor"] == vendor]
            if path == "/api/assessments":
                return self.json(records)
            items = (
                records
                if path.endswith("advisories")
                else [
                    {
                        **a,
                        "vendor": r["vendor"],
                        "advisory_id": r["advisory_id"],
                        "source_url": r["source_url"],
                        "sha256": r["sha256"],
                    }
                    for r in records
                    for a in r["assessments"]
                ]
            )
            try:
                limit = int(query.get("limit", ["100"])[0])
                offset = int(query.get("offset", ["0"])[0])
            except ValueError as exc:
                raise BadRequest("Invalid pagination") from exc
            if not 1 <= limit <= 500 or offset < 0:
                raise BadRequest("Invalid pagination")
            return self.json(
                {
                    "schema_version": 2,
                    "publication": data["publication"],
                    "total": len(items),
                    "offset": offset,
                    "limit": limit,
                    "items": items[offset : offset + limit],
                }
            )
        if re.fullmatch(r"/api/(evidence|changes)/\d+", path):
            path = path.replace("/api/", "/") + ".json"
        allowed = path in (
            "/",
            "/index.html",
            "/app.js",
            "/style.css",
            "/snapshot.js",
            "/snapshot.json",
            "/catalogue.json",
            "/benchmark.json",
            "/release-assets.json",
            "/impact.csv",
            "/manifest.json",
            "/schemas/advisory-v2.json",
            "/schemas/release-asset-v1.json",
            "/openapi.json",
            "/research/cohort-report.txt",
            "/research/hpe-timing-investigation.txt",
        ) or re.fullmatch(r"/(evidence|changes)/\d+\.json", path)
        if not allowed:
            return 404, "application/json", b'{"error":"Not found"}'
        target = generation / ("index.html" if path == "/" else path.lstrip("/"))
        if not target.is_file() or not target.resolve().is_relative_to(generation):
            return 404, "application/json", b'{"error":"Not found"}'
        return (
            200,
            mimetypes.guess_type(target)[0] or "application/octet-stream",
            target.read_bytes(),
        )

    @staticmethod
    def json(data, status=200):
        return status, "application/json", json.dumps(data).encode()
