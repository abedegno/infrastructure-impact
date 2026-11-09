"""Production WSGI reader. It can access publications, never the evidence vault."""

import json
import logging
import mimetypes
import re
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qs

from .application.kev import KevUnavailable
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

    def open(self):
        generation = (self.root / "current").resolve(strict=True)
        if not generation.is_relative_to((self.root / "generations").resolve()):
            raise ValueError("Invalid publication pointer")
        with self._lock:
            if generation != self._generation:
                index_path = generation / "data/index.json"
                from .publication_codec import strict_loads

                if index_path.is_file():
                    with index_path.open("rb") as stream:
                        index = strict_loads(stream.read(2_000_001), max_bytes=2_000_000)
                else:
                    index = {}
                if type(index.get("schema_version")) is int and index["schema_version"] == 2:
                    from .application.publication_reader import PublicationReader

                    candidate = PublicationReader(generation)
                else:
                    candidate = json.loads((generation / "snapshot.json").read_text())
                    self._validate_candidate(generation, candidate)
                self._data = candidate
                self._generation = generation
            return generation, self._data

    def read(self):
        return self.open()

    @staticmethod
    def _validate_candidate(generation, candidate):
        from .application.current_evidence import unavailable_report, validate_report
        from .application.current_views import validate_partition

        publication = candidate["publication"]
        manifest_path = generation / "manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
        if manifest and manifest.get("generation") != publication["id"]:
            raise ValueError("Mixed publication manifest")
        index_path = generation / "data/index.json"
        if "data/index.json" in manifest.get("sha256", {}) and not index_path.is_file():
            raise ValueError("Missing declared publication index")
        index = json.loads(index_path.read_text()) if index_path.exists() else {}
        if index and (
            index.get("publication") != publication
            or index.get("generated_at") != candidate["generated_at"]
        ):
            raise ValueError("Mixed publication index")
        new_generation = (
            "retained_advisories" in candidate
            or "retained_cves" in candidate
            or "current_evidence_version" in candidate
            or "current_evidence" in index
            or "current-evidence.json" in manifest.get("sha256", {})
            or "schemas/current-evidence-v1.json" in manifest.get("sha256", {})
            or (generation / "current-evidence.json").exists()
        )
        if "current_evidence" not in candidate and not new_generation and index.get("bootstrap"):
            path = index["bootstrap"]["path"]
            if not re.fullmatch(r"data/[a-f0-9]{64}\.json", path):
                raise ValueError("Invalid bootstrap path")
            bootstrap = json.loads((generation / path).read_text())
            new_generation = "current_evidence_version" in bootstrap["data"]
        if "current_evidence" in candidate:
            # Validate the archived decision graph as published. No registry hook,
            # current policy execution or evidence database belongs in a reader.
            validate_partition(candidate, require_targets=True)
            counts = candidate.get("counts", {})
            expected = candidate["current_evidence"]["counts"]
            for key, value in {"advisories": expected["current"], **expected}.items():
                if type(counts.get(key)) is not int or counts[key] != value:
                    raise ValueError("Inconsistent published current-evidence counts")
            report_path = generation / "current-evidence.json"
            if "current-evidence.json" in manifest.get("sha256", {}) and not report_path.is_file():
                raise ValueError("Missing declared current-evidence report")
            if report_path.exists():
                report = json.loads(report_path.read_text())
                validate_report(
                    report, publication=publication, generated_at=candidate["generated_at"]
                )
                if report != candidate["current_evidence"]:
                    raise ValueError("Mixed current-evidence assets")
        elif new_generation:
            raise ValueError("Missing current-evidence report")
        else:
            candidate["current_evidence"] = unavailable_report(
                publication=publication, generated_at=candidate["generated_at"]
            )
            candidate["retained_advisories"] = []


class Application:
    def __init__(self, root, stale_after=129600):
        self.store = PublicationStore(root)
        self.stale_after = stale_after

    def __call__(self, environ, start_response):
        try:
            status, content_type, body = self.route(environ)
        except KevUnavailable:
            status, content_type, body = 503, "application/json", b'{"error":"kev_unavailable"}'
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
            *([("Content-Length", str(len(body)))] if isinstance(body, bytes) else []),
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
        if environ.get("REQUEST_METHOD") == "HEAD":
            if hasattr(body, "close"):
                body.close()
            return [b""]
        return [body] if isinstance(body, bytes) else body

    def route(self, environ, *, _opened=None, _reader=None):
        if environ.get("REQUEST_METHOD") not in ("GET", "HEAD"):
            return 405, "application/json", b'{"error":"Read-only service"}'

        def respond(data, status=200):
            return self.json(
                data, status, max_bytes=_reader.limits["selected"] if _reader else None
            )

        path = environ.get("PATH_INFO", "/")
        if path == "/health/live":
            return respond({"status": "ok"})
        try:
            generation, data = _opened if _opened is not None else self.store.open()
            from .application.publication_reader import PublicationReader

            if isinstance(data, PublicationReader):
                return self._route_v2(environ, generation, data)
        except FileNotFoundError:
            return 503, "application/json", b'{"error":"Awaiting first successful publication"}'
        if path == "/api/v1/bootstrap":
            return respond(
                {
                    key: data[key]
                    for key in (
                        "publication",
                        "generated_at",
                        "benchmark_cohort",
                        "switching_validation",
                        "switching_review_packet",
                        "switching_reviewed_source_scopes",
                    )
                    if key in data
                }
            )
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
            return respond(
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
        if path in {
            "/api/v1/family-completeness",
            "/api/v1/comparison-readiness",
            "/api/v1/fix-leads",
            "/api/v1/component-studies",
            "/api/v1/product-cohorts",
            "/api/v1/disclosure-review",
        }:
            key = path.rsplit("/", 1)[-1].replace("-", "_")
            if key not in data:
                return respond({"error": "Report unavailable for this generation"}, status=404)
            return respond(
                {
                    **data[key],
                    "publication": data["publication"],
                    "generated_at": data["generated_at"],
                }
            )
        if path == "/api/v1/vendor-gaps":
            report = data["vendor_gaps"]
            values = parse_qs(environ.get("QUERY_STRING", "")).get("vendor", [])
            if values:
                if len(values) != 1 or values[0] not in data["vendors"]:
                    raise BadRequest("Unknown or repeated vendor")
                report = {
                    **report,
                    "vendors": [v for v in report["vendors"] if v["vendor"] == values[0]],
                }
            return respond(
                {**report, "publication": data["publication"], "generated_at": data["generated_at"]}
            )
        if path == "/api/v1/source-audit":
            return respond(data.get("source_audit", {}))
        if path == "/api/v1/catalogue":
            return respond(data.get("catalogue", {}))
        if path in (
            "/api/v1/extraction-validation",
            "/api/v1/switching-validation",
            "/api/v1/switching-review-packet",
            "/api/v1/review-packet",
            "/api/v1/publisher-history",
        ):
            key = path.rsplit("/", 1)[-1].replace("-", "_")
            if key not in data:
                return respond({"error": "Report unavailable for this generation"}, status=404)
            return respond(
                {
                    **data.get(key, {}),
                    "publication": data["publication"],
                    "generated_at": data["generated_at"],
                }
            )
        query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        if path == "/api/v1/switching-comparison":
            from .application.switching_comparison import day, query_options, select_report, summary
            from .exports import switching_csv

            try:
                options, output = query_options(
                    query,
                    data.get("switching_comparison", {}).get(
                        "observation_end", day(data["generated_at"])
                    ),
                )
            except ValueError as error:
                raise BadRequest("Invalid study query") from error
            asset = generation / "switching-comparison.json"
            if not asset.exists():
                return respond({"error": "switching_unavailable"}, status=503)
            from .application.switching_evidence import validate_comparison

            complete = json.loads(asset.read_text())
            validate_comparison(
                complete, publication=data["publication"], generated_at=data["generated_at"]
            )
            report = select_report(complete, **options)
            if report["availability"] == "unavailable":
                return respond({"error": "switching_unavailable"}, status=503)
            if output == "csv":
                return 200, "text/csv", switching_csv(report).encode()
            return respond(summary(report))
        ids = None
        if "cves" in query or "cve" in query:
            ids = sorted(set(",".join(query.get("cves", query.get("cve", []))).upper().split(",")))
            if len(ids) > 200 or not all(CVE.fullmatch(cid) for cid in ids):
                raise BadRequest("Invalid CVE cohort")
        if path == "/api/v1/current-evidence":
            from .application.current_evidence import unavailable_report

            return respond(
                data.get("current_evidence")
                or unavailable_report(
                    publication=data.get("publication"), generated_at=data["generated_at"]
                )
            )
        if path == "/api/v1/retained-advisories":
            from .application.current_evidence import unavailable_report
            from .exports import retained_assessment_export

            values = query.get("vendor", [])
            if values and (len(values) != 1 or values[0] not in data["vendors"]):
                raise BadRequest("Unknown or repeated vendor")
            formats = query.get("format", [])
            if formats and formats not in (["json"], ["csv"]):
                raise BadRequest("Invalid retained format")
            items = [
                w
                for w in data.get("retained_advisories", [])
                if (ids is None or set(ids).intersection(w["record"]["cves"]))
                and (not values or w["record"]["vendor"] == values[0])
            ]
            if formats:
                # Validate the complete envelope first; filters never fabricate a partition.
                exported = retained_assessment_export(data)
                keys = {w["decision_id"] for w in items}
                exported["records"] = [r for r in exported["records"] if r["decision_id"] in keys]
                if ids is not None:
                    exported["records"] = [
                        {**r, "assessments": [a for a in r["assessments"] if a["cve_id"] in ids]}
                        for r in exported["records"]
                    ]
                if formats == ["json"]:
                    return respond(exported)
                from .exports import FIELDS, RETAINED_FIELDS

                csv_data = {
                    **exported,
                    "kev": data.get("kev"),
                    "comparison": {
                        "cohort": ids
                        if ids is not None
                        else sorted({c for r in exported["records"] for c in r["cves"]})
                    },
                }
                return (
                    200,
                    "text/csv",
                    csv_export(csv_data, _fields=FIELDS + RETAINED_FIELDS).encode(),
                )
            try:
                if any(len(query.get(k, [])) > 1 for k in ("limit", "offset")):
                    raise ValueError("Repeated pagination")
                limit = int(query.get("limit", ["100"])[0])
                offset = int(query.get("offset", ["0"])[0])
                if not 1 <= limit <= 500 or offset < 0:
                    raise ValueError("Pagination out of bounds")
            except ValueError as error:
                raise BadRequest("Invalid pagination") from error
            return respond(
                {
                    "schema_version": 1,
                    "publication": data.get("publication"),
                    "generated_at": data["generated_at"],
                    "record_scope": "retained_latest_excluded",
                    "current_evidence": data.get("current_evidence")
                    or unavailable_report(
                        publication=data.get("publication"), generated_at=data["generated_at"]
                    ),
                    "total": len(items),
                    "offset": offset,
                    "limit": limit,
                    "items": items[offset : offset + limit],
                }
            )
        if path == "/api/v1/research-dossiers":
            from .application.research_dossiers import select_research_dossiers

            values = query.get("vendor", [])
            if values and (len(values) != 1 or values[0] not in data["vendors"]):
                raise BadRequest("Unknown or repeated vendor")
            if "research_dossiers" not in data:
                return respond({"error": "Report unavailable for this generation"}, status=404)
            report = data["research_dossiers"]
            cohort = ids if ids is not None else [d["cve_id"] for d in report["dossiers"]]
            return respond(
                {
                    **select_research_dossiers(report, cohort, values[0] if values else None),
                    "publication": data["publication"],
                    "generated_at": data["generated_at"],
                }
            )
        if path in (
            "/api/state",
            "/api/v1/kev",
            "/api/export.json",
            "/api/export.csv",
            "/api/assessments",
            "/api/v1/scorecards",
            "/api/v1/comparison-eligibility",
            "/api/v1/product-groups",
            "/api/v1/casefiles",
            "/api/v1/timeline",
            "/api/v1/advisories",
            "/api/v1/assessments",
        ):
            try:
                kev_values = query.get("kev", [])
                if kev_values and kev_values != ["listed"]:
                    raise ValueError("Invalid KEV control")
                values = query.get("vendor", [])
                if values and (len(values) != 1 or values[0] not in data["vendors"]):
                    raise ValueError("Unknown or repeated vendor")
                for key in ("start", "end", "products", "group"):
                    if key in query and len(query[key]) != 1:
                        raise ValueError("Duplicate comparison control")
                products = json.loads(query["products"][0]) if "products" in query else None
                selected = select(
                    data,
                    (
                        ids
                        if ids is not None
                        else (
                            data.get("kev", {}).get("selection", {}).get("requested_cve_ids")
                            if path == "/api/v1/kev"
                            else None
                        )
                    ),
                    start=query.get("start", [None])[0],
                    end=query.get("end", [None])[0],
                    products=products,
                    group=query.get("group", [None])[0],
                    vendor=values[0] if values else None,
                    kev_only=kev_values == ["listed"],
                )
            except KevUnavailable:
                raise
            except (ValueError, TypeError) as error:
                raise BadRequest("Invalid comparison selection") from error
            if path == "/api/v1/kev":
                return respond(selected["kev"])
            if path == "/api/state":
                if _reader is not None:
                    keys = (
                        "kev",
                        "comparison",
                        "comparison_eligibility",
                        "scorecards",
                        "timeline",
                        "casefiles",
                        "coverage",
                        "delays",
                        "research_dossiers",
                    )
                    return (
                        200,
                        "application/json",
                        _reader.stream_document({k: selected[k] for k in keys if k in selected}),
                    )
                return respond(selected)
            if path in (
                "/api/v1/scorecards",
                "/api/v1/timeline",
                "/api/v1/casefiles",
                "/api/v1/comparison-eligibility",
                "/api/v1/product-groups",
            ):
                key = path.rsplit("/", 1)[-1].replace("-", "_")
                result = selected[key]
                if query.get("vendor"):
                    vendor = query["vendor"][0]
                    if vendor not in data["vendors"]:
                        raise BadRequest("Unknown vendor")
                    if key in ("scorecards", "comparison_eligibility", "product_groups"):
                        result = {
                            **result,
                            "vendors": [
                                r for r in result.get("vendors", []) if r["vendor"] == vendor
                            ],
                        }
                    elif key == "casefiles":
                        result = {
                            **result,
                            "cases": [c for c in result.get("cases", []) if c["vendor"] == vendor],
                        }
                    else:
                        result = {
                            **result,
                            "events": [
                                e for e in result.get("events", []) if e["vendor"] == vendor
                            ],
                        }
                return respond(
                    {
                        **result,
                        "publication": data["publication"],
                        "generated_at": data["generated_at"],
                    }
                )
            selected = assessment_export(selected)
            if path.endswith(".csv"):
                return (
                    200,
                    "text/csv",
                    csv_export(
                        selected, max_bytes=_reader.limits["selected"] if _reader else None
                    ).encode(),
                )
            if path == "/api/export.json":
                if _reader is not None:
                    keys = (
                        "records",
                        "research",
                        "kev",
                        "comparison",
                        "comparison_eligibility",
                        "scorecards",
                        "timeline",
                        "casefiles",
                        "coverage",
                        "delays",
                        "research_dossiers",
                    )
                    return (
                        200,
                        "application/json",
                        _reader.stream_document(
                            {k: selected[k] for k in keys if k in selected},
                            exclude={"retained_advisories"},
                        ),
                    )
                return respond(selected)
            records = selected["records"]
            if query.get("vendor"):
                vendor = query["vendor"][0]
                if vendor not in data["vendors"]:
                    raise BadRequest("Unknown vendor")
                records = [r for r in records if r["vendor"] == vendor]
            if path == "/api/assessments":
                return respond(records)
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
            return respond(
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
            "/current-evidence.json",
            "/current-evidence.js",
            "/lossless-json.js",
            "/research-dossiers.js",
            "/kev.js",
            "/switching-contracts.js",
            "/switching.js",
            "/switching-view.js",
            "/switching-evidence.json",
            "/switching-comparison.json",
            "/switching-study.json",
            "/schemas/switching-study-v1.json",
            "/schemas/switching-evidence-v1.json",
            "/schemas/switching-comparison-v1.json",
            "/schemas/switching-summary-v1.json",
            "/schemas/switching-inputs-v1.json",
            "/kev.json",
            "/schemas/kev-v1.json",
            "/style.css",
            "/snapshot.js",
            "/delivery.js",
            "/snapshot.json",
            "/snapshot.json.gz",
            "/catalogue.json",
            "/benchmark.json",
            "/scorecards.json",
            "/source-audit.json",
            "/vendor-gaps.json",
            "/family-completeness.json",
            "/comparison-readiness.json",
            "/fix-leads.json",
            "/component-studies.json",
            "/product-cohorts.json",
            "/disclosure-review.json",
            "/research-dossiers.json",
            "/comparison-eligibility.json",
            "/comparison-eligibility-summary.json",
            "/product-groups.json",
            "/extraction-validation.json",
            "/switching-validation.json",
            "/switching-review-packet.json",
            "/review-packet.json",
            "/publisher-history.json",
            "/casefiles.json",
            "/timeline.json",
            "/release-assets.json",
            "/impact.csv",
            "/manifest.json",
            "/schemas/current-evidence-v1.json",
            "/schemas/advisory-v2.json",
            "/schemas/release-asset-v1.json",
            "/schemas/comparison-eligibility-v1.json",
            "/schemas/comparison-eligibility-summary-v1.json",
            "/schemas/product-groups-v1.json",
            "/schemas/publisher-history-v1.json",
            "/schemas/extraction-review-v1.json",
            "/schemas/review-submission-v1.json",
            "/schemas/static-index-v1.json",
            "/schemas/vendor-gaps-v1.json",
            "/schemas/family-completeness-v1.json",
            "/schemas/comparison-readiness-v1.json",
            "/schemas/fix-leads-v1.json",
            "/schemas/component-studies-v1.json",
            "/schemas/product-cohort-definition-v1.json",
            "/schemas/product-cohorts-v1.json",
            "/schemas/disclosure-review-v1.json",
            "/schemas/research-dossiers-v1.json",
            "/schemas/research-dossier-definition-v1.json",
            "/schemas/source-selection-v1.json",
            "/schemas/component-inventory-v1.json",
            "/schemas/build-inventory-submission-v1.json",
            "/openapi.json",
            "/research/cohort-report.txt",
            "/research/hpe-timing-investigation.txt",
            "/research/fortiproxy-curl-investigation.txt",
            "/research/aruba-cx-investigation.txt",
            "/research/juniper-security-rebuilds.txt",
        ) or re.fullmatch(r"/(evidence|changes)/\d+\.json", path)
        allowed = (
            allowed
            or path == "/data/index.json"
            or re.fullmatch(r"/data/[a-f0-9]{64}\.json", path)
            or re.fullmatch(r"/assets/[a-f0-9]{64}\.(?:js|css)", path)
        )
        if not allowed:
            return 404, "application/json", b'{"error":"Not found"}'
        target = generation / ("index.html" if path == "/" else path.lstrip("/"))
        if not target.is_file() or not target.resolve().is_relative_to(generation):
            return 404, "application/json", b'{"error":"Not found"}'
        return (
            200,
            "application/gzip"
            if path == "/snapshot.json.gz"
            else mimetypes.guess_type(target)[0] or "application/octet-stream",
            target.read_bytes(),
        )

    def _route_v2(self, environ, generation, reader):
        path = environ.get("PATH_INFO", "/")
        name = path.lstrip("/")
        if name in reader.catalog["roots"] and name != "runtime-snapshot":
            return 200, "application/json", reader.stream_root(name, serialization="ascii")
        # Static access is independent of runtime materialization.
        if not path.startswith("/api/") and not path.startswith("/health/"):
            allowed = (
                name
                in {
                    "publication-v2.json",
                    "publication-v2.js",
                    "snapshot-v2.json",
                    "snapshot-v2.json.gz",
                }
                or re.fullmatch(r"data/v2/[a-f0-9]{64}\.json", name)
                or name
                in {
                    "schemas/publication-v2.json",
                    "schemas/static-index-v2.json",
                    "schemas/switching-overview-v2.json",
                }
            )
            if allowed:
                target = generation / name
                if not target.is_file() or not target.resolve().is_relative_to(generation):
                    return 404, "application/json", b'{"error":"Not found"}'

                def chunks():
                    with target.open("rb") as stream:
                        while chunk := stream.read(65536):
                            yield chunk

                return 200, mimetypes.guess_type(target)[0] or "application/octet-stream", chunks()
            return self.route(environ, _opened=(generation, reader.metadata()))
        query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        if path == "/api/v1/switching-comparison":
            from .application.switching_comparison import query_options
            from .exports import switching_csv

            try:
                overview = reader.switching_overview()
                options, output = query_options(query, overview["observation_end"])
            except ValueError as exc:
                raise BadRequest("Invalid study query") from exc
            report = reader.switching_selection(
                options, evaluated_at=datetime.now(timezone.utc).isoformat()
            )
            if output == "csv":
                return (
                    200,
                    "text/csv",
                    switching_csv(report, max_bytes=reader.limits["selected"]).encode(),
                )
            return self.json(report, max_bytes=reader.limits["selected"])
        bootstrap = reader.fetch(reader.index["bootstrap"], ordinary=True)
        if path in ("/health/ready", "/api/v1/health", "/api/v1/bootstrap"):
            return self.route(environ, _opened=(generation, bootstrap), _reader=reader)
        ids = None
        if "cves" in query or "cve" in query:
            ids = sorted(set(",".join(query.get("cves", query.get("cve", []))).upper().split(",")))
            if len(ids) > 200 or not all(CVE.fullmatch(c) for c in ids):
                raise BadRequest("Invalid CVE cohort")
        selection_paths = {
            "/api/state",
            "/api/export.json",
            "/api/export.csv",
            "/api/assessments",
            "/api/v1/scorecards",
            "/api/v1/comparison-eligibility",
            "/api/v1/product-groups",
            "/api/v1/casefiles",
            "/api/v1/timeline",
            "/api/v1/advisories",
            "/api/v1/assessments",
        }
        if path in selection_paths:
            data = reader.runtime_snapshot(cohort=ids if ids is not None else bootstrap["all_cves"])
        else:
            data = bootstrap
            data["current_evidence"] = reader.fetch(
                reader.index["current_evidence"]["report"], ordinary=True
            )
            if path == "/api/v1/retained-advisories":
                values = query.get("vendor", [])
                formats = query.get("format", [])
                if values and (len(values) != 1 or values[0] not in data["vendors"]):
                    raise BadRequest("Unknown or repeated vendor")
                if formats and formats not in (["json"], ["csv"]):
                    raise BadRequest("Invalid retained format")
                try:
                    if any(len(query.get(k, [])) > 1 for k in ("limit", "offset")):
                        raise ValueError("Repeated pagination")
                    limit = int(query.get("limit", ["100"])[0])
                    offset = int(query.get("offset", ["0"])[0])
                    if not 1 <= limit <= 500 or offset < 0:
                        raise ValueError("Pagination out of bounds")
                except ValueError as error:
                    raise BadRequest("Invalid pagination") from error
                result = reader.retained_selection(
                    bootstrap,
                    cves=ids,
                    vendor=values[0] if values else None,
                    offset=offset,
                    limit=limit,
                    export=bool(formats),
                )
                if formats == ["csv"]:
                    from .exports import FIELDS, RETAINED_FIELDS

                    csv_data = {
                        **result,
                        "kev": data.get("kev"),
                        "comparison": {
                            "cohort": ids
                            if ids is not None
                            else sorted({c for r in result["records"] for c in r["cves"]})
                        },
                    }
                    return (
                        200,
                        "text/csv",
                        csv_export(
                            csv_data,
                            _fields=FIELDS + RETAINED_FIELDS,
                            max_bytes=reader.limits["selected"],
                        ).encode(),
                    )
                return self.json(result, max_bytes=reader.limits["selected"])
        return self.route(environ, _opened=(generation, data), _reader=reader)

    @staticmethod
    def json(data, status=200, *, max_bytes=None):
        if max_bytes is not None:
            from .publication_codec import Budget, charge_value

            charge_value(data, Budget(max_bytes), spaced=True)
        return status, "application/json", json.dumps(data).encode()
