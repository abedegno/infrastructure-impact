"""Immutable collection projections from explicit, read-only SQLite snapshots.

Publisher hyperlinks are references, never fetched-source aliases. No adapters,
network clients, migrations, raw bodies, configuration payloads or free-text
collection errors are used by this exporter.
"""

import hashlib
import json
import os
import re
import sqlite3
from collections import Counter
from contextlib import closing
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from jsonschema import Draft202012Validator

from ..application.families import definition, matches
from ..collection.config import validate_config
from ..collection.errors import CiscoAccessError
from ..plugins.registry import default_registry
from ..references.registry import allowed as reference_allowed
from ..settings import PACKAGE
from ..source_policy import allowed
from ..storage.repository import connect, now

# Exact current table definitions after migrations 1..15, normalized for whitespace.
# A different schema requires an explicit reader review, never a migration here.
_SCHEMA_SHA256 = "c20eeff5c13ab8a85b72b401105999a38843c1b8e17600dad0e0459880442add"
_FORMAT = "infrastructure-impact-collection-baseline"
_FAMILIES = {"cisco-iosxe", "aruba-aoscx", "arista-eos"}
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_OUTCOMES = {"ok", "error", "partial", "not_applicable", "reprocessed", "unchanged", "imported"}
_ERRORS = CiscoAccessError.CODES | {
    "network_error",
    "source_missing",
    "redirect_target_missing",
    "http_error",
    "access_denied",
    "edge_access_denied",
    "rate_limited",
    "access_verification_required",
    "auth_not_configured",
    "auth_rejected",
    "service_unavailable",
    "request_state_unresolved",
    "publisher_scope_unavailable",
    "retained_source_missing",
    "unsupported_or_invalid_document",
    "collection_error",
}


class BaselineError(ValueError):
    """Stable source-free failure, safe for command-line reporting."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _identity(data):
    return _sha(
        _canonical({k: v for k, v in data.items() if k not in {"observed_at", "fingerprint"}})
    )


def _route(value, vendor=None):
    """Closed reviewed routes; preserve semantic queries and reject all others.

    No query/fragment is silently stripped, and no vendor canonicalizer is used:
    only an evidence-backed selection may bind two different fetched URLs.
    """
    if isinstance(value, str) and vendor in (None, "upstream") and reference_allowed(value):
        return value
    if not isinstance(value, str) or any(ord(c) < 33 for c in value) or "%" in value:
        return None
    try:
        u = urlsplit(value)
        if (
            u.scheme != "https"
            or u.username
            or u.password
            or u.port not in (None, 443)
            or u.fragment
            or "\\" in value
            or ".." in u.path.split("/")
        ):
            return None
        host, path = u.hostname, u.path
        query = parse_qsl(u.query, keep_blank_values=True, strict_parsing=True)
        q = dict(query)
        if len(q) != len(query):
            return None
        owners = set()
        permitted = False
        if host == "cveawg.mitre.org" and re.fullmatch(r"/api/cve/CVE-[0-9]{4}-[0-9]{4,}", path):
            owners = {"cisco", "hpe", "juniper", "checkpoint", "upstream"}
            permitted = not q
        elif host in {"sec.cloudapps.cisco.com", "tools.cisco.com"} and not path.startswith(
            "/.well-known/csaf/"
        ):
            owners = {"cisco"}
            permitted = not q and bool(
                re.fullmatch(
                    r"/security/center/(?:content/CiscoSecurityAdvisory/cisco-sa-[A-Za-z0-9-]+"
                    r"|contentjson/CiscoSecurityAdvisory/cisco-sa-[A-Za-z0-9-]+/csaf/cisco-sa-[A-Za-z0-9-]+\.json"
                    r"|psirtrss20/CiscoSecurityAdvisory\.xml|publicationListing\.x)",
                    path,
                )
            )
        elif host in {"sec.cloudapps.cisco.com", "www.cisco.com"} and path.startswith(
            "/.well-known/csaf/"
        ):
            owners = {"cisco"}
            permitted = not q and bool(
                re.fullmatch(
                    r"/\.well-known/csaf/(?:20[0-9]{2}/)?[A-Za-z0-9_-]+\.(?:json|txt)", path
                )
            )
        elif host == "apix.cisco.com":
            owners = {"cisco"}
            permitted = bool(
                re.fullmatch(
                    r"/security/advisories/v2/(?:all|year/20[0-9]{2}|all/firstpublished)", path
                )
            )
            permitted &= not (set(q) - {"pageIndex", "pageSize", "startDate", "endDate"})
            permitted &= all(
                re.fullmatch(r"[1-9][0-9]*", q[k]) is not None and int(q[k]) <= 100
                for k in ("pageIndex", "pageSize")
                if k in q
            )
            permitted &= all(
                re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", q[k]) is not None
                for k in ("startDate", "endDate")
                if k in q
            )
        elif host in {"csaf.arubanetworking.hpe.com", "csaf.arubanetworks.com"}:
            owners = {"aruba"}
            permitted = not q and bool(
                re.fullmatch(
                    r"/(?:index\.txt|20[0-9]{2}/|(?:20[0-9]{2}/)?[A-Za-z0-9_-]+\.(?:json|txt))",
                    path,
                )
            )
        elif host == "www.arista.com":
            owners = {"arista"}
            if path in {
                "/en/support/advisories-notices",
                "/en/support/advisories-notices/securityadvisory",
            }:
                permitted = not q or (
                    set(q) == {"start"} and re.fullmatch(r"[0-9]+", q["start"]) is not None
                )
            else:
                permitted = not q and bool(
                    re.fullmatch(
                        r"/en/support/advisories-notices/security-advisory/[0-9]+-security-advisory-[0-9]+",
                        path,
                    )
                )
        elif host == "support.hpe.com":
            owners = {"hpe", "aruba"}
            permitted = (
                path == "/hpesc/public/docDisplay"
                and set(q) == {"docId"}
                and re.fullmatch(r"[A-Za-z0-9_-]+", q["docId"]) is not None
            ) or (
                not q
                and re.fullmatch(r"/hpesc/public/api/document/[A-Za-z0-9_-]+", path) is not None
            )
        if not permitted or (vendor is not None and vendor not in owners):
            return None
        if vendor not in (None, "cisco") or host != "apix.cisco.com":
            if vendor is not None and not allowed(value, vendor):
                return None
        return urlunsplit(("https", host, path, urlencode(sorted(q.items())), ""))
    except (ValueError, TypeError):
        return None


def _check_paths(database, config_path, output):
    try:
        inputs = [Path(database), Path(config_path)]
        if not all(p.is_file() for p in inputs):
            raise BaselineError("invalid_input")
        output = Path(output)
        protected = {p.resolve() for p in inputs}
        for p in inputs:
            for original in (p.absolute(), p.resolve()):
                protected.update(
                    Path(str(original) + suffix) for suffix in ("-wal", "-shm", "-journal")
                )
        if (
            output.is_symlink()
            or output.resolve() in protected
            or any(
                output.exists() and p.exists() and os.path.samefile(output, p) for p in protected
            )
        ):
            raise BaselineError("unsafe_output_path")
        # Exclusive creation also rejects unrelated existing files and avoids overwrites.
        if output.exists():
            raise BaselineError("unsafe_output_path")
        return inputs[0], inputs[1], output
    except (OSError, TypeError, ValueError) as error:
        if isinstance(error, BaselineError):
            raise
        raise BaselineError("invalid_input") from None


def _check_schema(db):
    tables = [
        (r[0], " ".join(r[1].split()))
        for r in db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    if _sha(_canonical(tables)) != _SCHEMA_SHA256:
        raise BaselineError("unsupported_schema")
    versions = list(db.execute("SELECT version,checksum FROM schema_migrations ORDER BY version"))
    paths = sorted((PACKAGE / "migrations").glob("*.sql"))
    if [r[0] for r in versions] != list(range(1, 16)):
        raise BaselineError("unsupported_schema")
    if len(paths) != 15 or any(
        r[1] not in (None, _sha(p.read_bytes())) for r, p in zip(versions, paths)
    ):
        raise BaselineError("unsupported_schema")


def _project(db, config):
    diagnostics = Counter(omitted_urls=0, omitted_error_details=0, omitted_selection_reasons=0)

    def url(value, vendor=None):
        safe = _route(value, vendor)
        if value is not None and safe is None:
            diagnostics["omitted_urls"] += 1
        return safe

    def code(value):
        return value if value in _ERRORS else "collection_error" if value else None

    families = [f for f in definition()["families"] if f["id"] in _FAMILIES]
    known_vendors = set(default_registry().names())
    revisions = []
    latest = {r[0] for r in db.execute("SELECT max(id) FROM revisions GROUP BY vendor,advisory_id")}
    for row in db.execute("SELECT * FROM revisions ORDER BY id"):
        normalized = json.loads(row["normalized"])
        if normalized.get("schema_version") != 2 or row["vendor"] not in known_vendors:
            raise BaselineError("unsupported_normalized_record")
        if (
            normalized.get("vendor") != row["vendor"]
            or normalized.get("advisory_id") != row["advisory_id"]
        ):
            raise BaselineError("invalid_collection_data")
        cves = sorted(set(normalized["cves"]))
        if any(not isinstance(c, str) or not _CVE.fullmatch(c) for c in cves):
            raise BaselineError("invalid_collection_data")
        assessments = []
        for index, a in enumerate(normalized["assessments"]):
            if a["cve_id"] not in cves:
                raise BaselineError("invalid_collection_data")
            assessments.append(
                dict(
                    index=index,
                    **{k: a[k] for k in ("cve_id", "product_id", "product", "status", "scope")},
                    product_family=a.get("product_family"),
                    families=sorted(
                        f["id"] for f in families if f["vendor"] == row["vendor"] and matches(f, a)
                    ),
                )
            )
        revisions.append(
            dict(
                revision_id=row["id"],
                evidence_id=row["evidence_id"],
                vendor=row["vendor"],
                advisory_id=row["advisory_id"],
                source_url=url(row["source_url"], row["vendor"]),
                normalized_source_url=url(normalized.get("source_url"), row["vendor"]),
                advisory_url=url(normalized.get("advisory_url"), row["vendor"]),
                observed_at=row["observed_at"],
                latest=row["id"] in latest,
                published_at=normalized.get("published_at"),
                updated_at=normalized.get("updated_at"),
                document_status=normalized.get("document_status", "unknown"),
                cves=cves,
                assessments=assessments,
            )
        )
    retained = [
        dict(
            evidence_id=r["id"],
            source_url=url(r["source_url"]),
            sha256=r["sha256"],
            observed_at=r["observed_at"],
        )
        for r in db.execute("SELECT id,source_url,sha256,observed_at FROM evidence ORDER BY id")
    ]
    checks = []
    for r in db.execute(
        "SELECT * FROM collection_runs WHERE id IN "
        "(SELECT max(id) FROM collection_runs GROUP BY vendor,source_url) ORDER BY id"
    ):
        diagnostics["omitted_error_details"] += bool(r["details"])
        checks.append(
            dict(
                check_id=r["id"],
                vendor=r["vendor"],
                source_url=url(r["source_url"], r["vendor"]),
                checked_at=r["checked_at"],
                outcome=r["outcome"] if r["outcome"] in _OUTCOMES else "unknown",
                error_code=code(r["error_code"]),
            )
        )
    configured = []
    for section in ("vendors", "pinned", "archives", "release_documents", "switching_sources"):
        for entry in config.get(section, []):
            configured.append(
                dict(
                    section=section,
                    vendor=entry["vendor"],
                    source_url=url(entry["url"], entry["vendor"]),
                    kind=entry.get("kind", "document" if section == "pinned" else "release_notes"),
                )
            )
    # Reference configuration is state too; its reviewed source ID is enough.
    for entry in config.get("reference_sources", []):
        configured.append(
            dict(
                section="reference_sources",
                vendor="upstream",
                source_url=url(entry["url"], "upstream"),
                kind=entry["source_id"],
                enabled=entry.get("enabled", True),
            )
        )
    archives = [
        dict(
            source_id=r["id"],
            vendor=r["vendor"],
            source_url=url(r["source_url"], r["vendor"]),
            kind=r["kind"],
            started_at=r["started_at"],
            checked_at=r["checked_at"],
        )
        for r in db.execute("SELECT * FROM archive_sources ORDER BY id")
    ]
    queue = []
    for r in db.execute(
        "SELECT i.*,s.vendor FROM archive_items i JOIN archive_sources s ON s.id=i.source_id ORDER BY i.id"
    ):
        queue.append(
            dict(
                item_id=r["id"],
                source_id=r["source_id"],
                vendor=r["vendor"],
                kind=r["kind"],
                requested_url=url(r["url"], r["vendor"]),
                resolved_url=url(r["resolved_url"], r["vendor"]),
                state=r["state"],
                evidence_id=r["evidence_id"],
                attempts=r["attempts"],
                discovered_at=r["discovered_at"],
                checked_at=r["checked_at"],
                error_code=code(r["error_code"]),
                page_evidence_ids=[
                    e[0]
                    for e in db.execute(
                        "SELECT page_evidence_id FROM archive_links WHERE item_id=? ORDER BY page_evidence_id",
                        (r["id"],),
                    )
                ],
            )
        )
    selections = []
    latest_selections = {
        r[0]
        for r in db.execute("SELECT max(id) FROM source_selections GROUP BY vendor,requested_url")
    }
    for r in db.execute("SELECT * FROM source_selections ORDER BY id"):
        diagnostics["omitted_selection_reasons"] += bool(r["reason"])
        selections.append(
            dict(
                selection_id=r["id"],
                vendor=r["vendor"],
                requested_url=url(r["requested_url"], r["vendor"]),
                observed_at=r["observed_at"],
                latest=r["id"] in latest_selections,
                selected_evidence_id=r["selected_evidence_id"],
                views=[
                    dict(evidence_id=v[0], selected=v[0] == r["selected_evidence_id"])
                    for v in db.execute(
                        "SELECT evidence_id FROM source_selection_views WHERE selection_id=? ORDER BY id",
                        (r["id"],),
                    )
                ],
                unavailable=[
                    dict(source_url=url(v[0], r["vendor"]), error_code=code(v[1]))
                    for v in db.execute(
                        "SELECT source_url,error_code FROM source_selection_issues WHERE selection_id=? ORDER BY id",
                        (r["id"],),
                    )
                ],
            )
        )
    cache = [
        dict(source_url=url(r[0]), evidence_id=r[1])
        for r in db.execute("SELECT url,evidence_id FROM http_cache ORDER BY url")
    ]
    observations = [
        dict(
            observation_id=r["id"],
            vendor=r["vendor"],
            source_url=url(r["source_url"], r["vendor"]),
            checked_at=r["checked_at"],
            evidence_id=r["evidence_id"],
            http_status=r["http_status"],
        )
        for r in db.execute(
            "SELECT * FROM source_observations WHERE id IN "
            "(SELECT max(id) FROM source_observations GROUP BY vendor,source_url) ORDER BY id"
        )
    ]
    return dict(
        revisions=revisions,
        evidence=retained,
        source_checks=checks,
        configured_sources=configured,
        archive_sources=archives,
        queue=queue,
        source_selections=selections,
        cache=cache,
        source_observations=observations,
        diagnostics=dict(diagnostics),
    )


def _obj(properties):
    return dict(
        type="object", properties=properties, required=list(properties), additionalProperties=False
    )


def _array(item):
    return dict(type="array", items=item)


_TEXT = {"type": "string"}
_NULL_TEXT = {"type": ["string", "null"]}
_INT = {"type": "integer", "minimum": 1}
_NULL_INT = {"type": ["integer", "null"], "minimum": 1}
_BOOL = {"type": "boolean"}
_VENDOR = {"enum": [*default_registry().names(), "upstream"]}
_URL = {"type": ["string", "null"]}
_DIGEST = {"type": "string", "pattern": "^[0-9a-f]{64}$"}


def _schema():
    # Closed objects prevent unknown payloads from being loaded as trusted state.
    assessment = _obj(
        dict(
            index={"type": "integer", "minimum": 0},
            cve_id=_TEXT,
            product_id=_TEXT,
            product=_TEXT,
            status=_TEXT,
            scope=_TEXT,
            product_family=_NULL_TEXT,
            families=_array({"enum": sorted(_FAMILIES)}),
        )
    )
    configured = _obj(dict(section=_TEXT, vendor=_VENDOR, source_url=_URL, kind=_TEXT))
    configured["properties"]["enabled"] = _BOOL
    return _obj(
        dict(
            format={"const": _FORMAT},
            format_version={"const": 1},
            observed_at=_TEXT,
            generation={"type": "null"},
            config_sha256=_DIGEST,
            fingerprint=_DIGEST,
            revisions=_array(
                _obj(
                    dict(
                        revision_id=_INT,
                        evidence_id=_INT,
                        vendor=_VENDOR,
                        advisory_id=_TEXT,
                        source_url=_URL,
                        normalized_source_url=_URL,
                        advisory_url=_URL,
                        observed_at=_TEXT,
                        latest=_BOOL,
                        published_at=_NULL_TEXT,
                        updated_at=_NULL_TEXT,
                        document_status=_TEXT,
                        cves=_array({"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"}),
                        assessments=_array(assessment),
                    )
                )
            ),
            evidence=_array(
                _obj(dict(evidence_id=_INT, source_url=_URL, sha256=_DIGEST, observed_at=_TEXT))
            ),
            source_checks=_array(
                _obj(
                    dict(
                        check_id=_INT,
                        vendor=_VENDOR,
                        source_url=_URL,
                        checked_at=_TEXT,
                        outcome={"enum": sorted(_OUTCOMES | {"unknown"})},
                        error_code={"enum": sorted(_ERRORS) + [None]},
                    )
                )
            ),
            configured_sources=_array(configured),
            archive_sources=_array(
                _obj(
                    dict(
                        source_id=_INT,
                        vendor=_VENDOR,
                        source_url=_URL,
                        kind=_TEXT,
                        started_at=_TEXT,
                        checked_at=_NULL_TEXT,
                    )
                )
            ),
            queue=_array(
                _obj(
                    dict(
                        item_id=_INT,
                        source_id=_INT,
                        vendor=_VENDOR,
                        kind={"enum": ["page", "document"]},
                        requested_url=_URL,
                        resolved_url=_URL,
                        state={"enum": ["pending", "done", "error", "not_applicable"]},
                        evidence_id=_NULL_INT,
                        attempts={"type": "integer", "minimum": 0},
                        discovered_at=_TEXT,
                        checked_at=_NULL_TEXT,
                        error_code={"enum": sorted(_ERRORS) + [None]},
                        page_evidence_ids=_array(_INT),
                    )
                )
            ),
            source_selections=_array(
                _obj(
                    dict(
                        selection_id=_INT,
                        vendor=_VENDOR,
                        requested_url=_URL,
                        observed_at=_TEXT,
                        latest=_BOOL,
                        selected_evidence_id=_INT,
                        views=_array(_obj(dict(evidence_id=_INT, selected=_BOOL))),
                        unavailable=_array(
                            _obj(
                                dict(source_url=_URL, error_code={"enum": sorted(_ERRORS) + [None]})
                            )
                        ),
                    )
                )
            ),
            cache=_array(_obj(dict(source_url=_URL, evidence_id=_NULL_INT))),
            source_observations=_array(
                _obj(
                    dict(
                        observation_id=_INT,
                        vendor=_VENDOR,
                        source_url=_URL,
                        checked_at=_TEXT,
                        evidence_id=_INT,
                        http_status={"type": "integer", "minimum": 200, "maximum": 304},
                    )
                )
            ),
            diagnostics=_obj(
                {
                    k: {"type": "integer", "minimum": 0}
                    for k in ("omitted_urls", "omitted_error_details", "omitted_selection_reasons")
                }
            ),
        )
    )


def _validate(data):
    if not Draft202012Validator(_schema()).is_valid(data) or data["fingerprint"] != _identity(data):
        raise BaselineError("invalid_baseline")
    evidence_ids = {e["evidence_id"] for e in data["evidence"]}
    evidence_urls = {e["evidence_id"]: e["source_url"] for e in data["evidence"]}
    for key, id_field in [
        ("evidence", "evidence_id"),
        ("revisions", "revision_id"),
        ("source_selections", "selection_id"),
        ("queue", "item_id"),
        ("archive_sources", "source_id"),
        ("source_checks", "check_id"),
        ("source_observations", "observation_id"),
    ]:
        ids = [r[id_field] for r in data[key]]
        if len(ids) != len(set(ids)):
            raise BaselineError("invalid_baseline")
    for r in data["revisions"]:
        if (
            r["evidence_id"] not in evidence_ids
            or len(r["cves"]) != len(set(r["cves"]))
            or any(a["cve_id"] not in r["cves"] for a in r["assessments"])
        ):
            raise BaselineError("invalid_baseline")
        if (
            r["source_url"] is not None
            and evidence_urls[r["evidence_id"]] is not None
            and r["source_url"] != evidence_urls[r["evidence_id"]]
        ):
            raise BaselineError("invalid_baseline")
        for a in r["assessments"]:
            if any(not f.startswith(r["vendor"] + "-") for f in a["families"]):
                raise BaselineError("invalid_baseline")
    for section in ("queue", "cache", "source_observations"):
        for r in data[section]:
            if r["evidence_id"] is not None and r["evidence_id"] not in evidence_ids:
                raise BaselineError("invalid_baseline")
    sources = {r["source_id"]: r for r in data["archive_sources"]}
    for r in data["queue"]:
        source = sources.get(r["source_id"])
        if (
            source is None
            or r["vendor"] != source["vendor"]
            or not set(r["page_evidence_ids"]) <= evidence_ids
        ):
            raise BaselineError("invalid_baseline")
    for s in data["source_selections"]:
        views = {v["evidence_id"] for v in s["views"]}
        if (
            s["selected_evidence_id"] not in views
            or not views <= evidence_ids
            or any(
                v["selected"] != (v["evidence_id"] == s["selected_evidence_id"]) for v in s["views"]
            )
        ):
            raise BaselineError("invalid_baseline")
        for view_id in views:
            source_url = evidence_urls[view_id]
            if source_url is not None and _route(source_url, s["vendor"]) is None:
                raise BaselineError("invalid_baseline")
        for issue in s["unavailable"]:
            if (
                issue["source_url"] is not None
                and _route(issue["source_url"], s["vendor"]) != issue["source_url"]
            ):
                raise BaselineError("invalid_baseline")
    for section in (
        "evidence",
        "revisions",
        "source_checks",
        "configured_sources",
        "archive_sources",
        "queue",
        "source_selections",
        "cache",
        "source_observations",
    ):
        for r in data[section]:
            for field in (
                "source_url",
                "normalized_source_url",
                "advisory_url",
                "requested_url",
                "resolved_url",
            ):
                if r.get(field) is not None and _route(r[field], r.get("vendor")) != r[field]:
                    raise BaselineError("invalid_baseline")


def export_baseline(*, database: Path, config_path: Path, output: Path) -> dict:
    """Export one consistent snapshot without modifying either supplied input.

    An output is always a new file. Baseline identity excludes only this export's
    observation timestamp, not persisted source/revision/check timestamps.
    """
    database, config_path, output = _check_paths(database, config_path, output)
    try:
        config_raw = config_path.read_bytes()
        try:
            config = validate_config(json.loads(config_raw))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise BaselineError("invalid_config") from None
        with closing(connect(database, read_only=True)) as db:
            db.execute("BEGIN")
            try:
                _check_schema(db)  # First read pins the WAL snapshot.
                projection = _project(db, config)
            finally:
                db.rollback()
        data = dict(
            format=_FORMAT,
            format_version=1,
            observed_at=now(),
            generation=None,
            config_sha256=_sha(config_raw),
            **projection,
        )
        data["fingerprint"] = _identity(data)
        _validate(data)
        payload = _canonical(data) + b"\n"
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        return data
    except BaselineError:
        raise
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, AttributeError):
        raise BaselineError("invalid_collection_data") from None


def load_baseline(path: Path) -> dict:
    """Validate a closed projection and recompute its canonical identity."""

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BaselineError("invalid_baseline")
            result[key] = value
        return result

    try:
        data = json.loads(Path(path).read_bytes(), object_pairs_hook=unique)
        _validate(data)
        return data
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise BaselineError("invalid_baseline") from None
