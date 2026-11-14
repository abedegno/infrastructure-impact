"""Explicit optional IOS XE firstFixed enrichment using the existing transport.

The documented endpoint and firstFixed array do not establish per-CVE/product
ownership. Until that contract is verified, retain closed advisory observations;
no common source fact or verified remediation is manufactured from a query.
"""

import hashlib
import re
from urllib.parse import urlencode

from ..application.software_versions import release_train, version_key
from ..storage import cisco_first_fixed as work
from ..storage.switching import SERVICE
from .cisco_openvuln import MAX_BYTES, CiscoOpenVuln, _has_private_content, _strict_json
from .errors import CiscoAccessError

PARSER_REVISION = "cisco-first-fixed-api-2"
ENDPOINT = "https://apix.cisco.com/security/advisories/v2/OSType/iosxe"
_RELEASE = re.compile(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}[a-z]?")
_ADVISORY = re.compile(r"cisco-sa-[A-Za-z0-9_-]{1,180}")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,12}")


def _releases(releases):
    if (
        not isinstance(releases, list)
        or len(releases) > 1000
        or any(not isinstance(v, str) or not _RELEASE.fullmatch(v) for v in releases)
    ):
        raise ValueError("Invalid release selection")
    return list(dict.fromkeys(releases))


def parse_response(raw: bytes, *, query_release: str) -> dict:
    """Bounded, pure, closed diagnostics; deliberately no inferred row ownership."""
    _releases([query_release])
    result = {"first_fixed": [], "advisory_context": [], "issues": []}
    issues = result["issues"]
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        issues.append("response_too_large")
        return result
    try:
        data = _strict_json(raw)
    except CiscoAccessError:
        issues.append("invalid_json")
        return result
    if _has_private_content(data, ()):
        issues.append("credential_response_rejected")
        return result
    if not isinstance(data, dict) or not isinstance(data.get("advisories"), list):
        issues.append("unsupported_response")
        return result
    rows = data["advisories"]
    if len(rows) > 1000:
        issues.append("response_too_large")
        return result
    if not rows:
        issues.append("empty_response")
    seen = set()
    for i, row in enumerate(rows):
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("advisoryId"), str)
            or not _ADVISORY.fullmatch(row["advisoryId"])
        ):
            issues.append("advisory_identity_unresolved")
            continue
        aid = row["advisoryId"]
        if aid in seen:
            issues.append("duplicate_advisory_identity")
        seen.add(aid)
        refs = row.get("cves")
        valid_refs = (
            isinstance(refs, list)
            and len(refs) <= 1000
            and all(isinstance(v, str) and _CVE.fullmatch(v) for v in refs)
            and len(set(refs)) == len(refs)
        )
        if not valid_refs:
            issues.append("cve_identity_unresolved")
        values = row.get("firstFixed")
        if "firstFixed" not in row:
            state, literals = "missing", []
            issues.append("missing_first_fixed")
        elif (
            not isinstance(values, list)
            or len(values) > 100
            or not all(
                isinstance(v, str) and 1 <= len(v) <= 128 and not any(ord(c) < 32 for c in v)
                for v in values
            )
        ):
            state, literals = "malformed", []
            issues.append("malformed_first_fixed")
        else:
            literals = values.copy()
            state = "present" if values else "empty"
            if not values:
                issues.append("empty_first_fixed")
            if len(set(literals)) != len(literals):
                issues.append("duplicate_first_fixed_literal")
            if any(version_key("cisco", v) is None for v in literals):
                issues.append("unsupported_ordering_literal")
            query_train = release_train("cisco", query_release)
            if any(release_train("cisco", v) not in (None, query_train) for v in literals):
                issues.append("other_train_alternative")
        issues.append("ownership_unresolved")
        result["advisory_context"].append(
            {
                "advisory_id": aid,
                "source_locator": f"/advisories/{i}/firstFixed",
                "source_first_fixed": literals,
                "first_fixed_state": state,
                "cve_refs": refs if valid_refs else [],
                "ownership_state": "ownership_unresolved",
            }
        )
    result["issues"] = list(dict.fromkeys(issues))
    return result


def plan(db, releases: list[str]) -> dict:
    values = _releases(releases)
    work.enqueue(db, [(ENDPOINT + "?" + urlencode({"version": v}), v) for v in values])
    return status(db)


def status(db) -> dict:
    rows = work.queries(db)
    counts = {}
    for row in rows:
        counts[row["state"]] = counts.get(row["state"], 0) + 1
    return {
        "counts": counts,
        "queries": [
            {
                key: row[key]
                for key in (
                    "url",
                    "os_type",
                    "query_release",
                    "state",
                    "error_code",
                    "retry_at",
                    "evidence_id",
                    "parser_revision",
                )
            }
            for row in rows
        ],
    }


def results(db) -> list[dict]:
    return work.results(db)


def _accept(db, row, capture):
    parsed = parse_response(capture["raw"], query_release=row["query_release"])
    if any(
        code in parsed["issues"]
        for code in (
            "invalid_json",
            "unsupported_response",
            "credential_response_rejected",
            "response_too_large",
        )
    ):
        work.outcome(db, row["url"], row["attempt"], "error", error_code="unsupported_response")
        return
    work.accepted(db, row["url"], row["attempt"], capture["id"], PARSER_REVISION, parsed)


def run(db, *, releases: list[str], max_releases: int = 10, client=None) -> dict:
    values = _releases(releases)
    if type(max_releases) is not int or not 1 <= max_releases <= 100:
        raise ValueError("Invalid release budget")
    plan(db, values)
    attempted = 0
    before = db.execute("SELECT coalesce(max(id),0) FROM switching_requests").fetchone()[0]
    for row in work.queries(db):
        if (values and row["query_release"] not in values) or row["state"] == "success":
            continue
        if attempted >= max_releases:
            break
        if row["started"]:
            capture = work.receipt(db, row["url"], row["attempt"])
            if capture:
                _accept(db, row, capture)
                attempted += 1
            else:
                work.unknown(db, row["url"], row["attempt"])
            continue
        attempt = work.start(db, row["url"])
        if attempt is None:
            continue
        row = {**row, "attempt": attempt}
        attempted += 1
        # Constructing the client is itself explicit-run-only. No config file.
        code, retry_at, raw = None, None, None
        try:
            if client is None:
                client = CiscoOpenVuln(db)
            raw = client.get_json(row["url"])
        except CiscoAccessError as error:
            code = error.code if error.code in CiscoAccessError.CODES else "collection_error"
            # Even injected client errors cannot export an arbitrary retry string.
            if isinstance(error.retry_at, str) and re.fullmatch(
                r"[0-9T:+.Z-]{10,40}", error.retry_at
            ):
                retry_at = error.retry_at
        except Exception:
            code = "collection_error"
        # Never persist upstream exceptions, messages, reprs or traceback context.
        if code:
            state = (
                "auth_not_configured"
                if code == "auth_not_configured"
                else "deferred"
                if code
                in {
                    "rate_limited",
                    "service_unavailable",
                    "network_error",
                    "request_state_unresolved",
                }
                else "error"
            )
            work.outcome(db, row["url"], attempt, state, error_code=code, retry_at=retry_at)
            if state in {"deferred", "auth_not_configured"}:
                break
            continue
        capture = (
            work.capture(db, row["url"], hashlib.sha256(raw).hexdigest())
            if isinstance(raw, bytes)
            else None
        )
        if capture is None:
            work.outcome(db, row["url"], attempt, "error", error_code="retained_response_missing")
        elif work.acknowledge(db, row["url"], attempt, capture["id"]):
            _accept(db, row, capture)
    receipt = status(db)
    receipt["release_queries_attempted"] = attempted
    receipt["http_requests_reserved"] = db.execute(
        "SELECT count(*) FROM switching_requests WHERE service=? AND id>?", (SERVICE, before)
    ).fetchone()[0]
    return receipt
