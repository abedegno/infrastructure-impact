"""Preview-bound exact-target maintenance, without publication or ambient startup."""

import json
import re
from contextlib import closing
from hashlib import sha256
from pathlib import Path

from ..collection.maintenance_profiles import MaintenanceProfile
from ..collection.maintenance_profiles import profile as registered_profile
from ..plugins.registry import default_registry
from ..storage.repository import connect, latest, now
from .evidence_identity import canonical_json, record_key


class MaintenanceBaselineChanged(ValueError):
    """The operator's accepted latest inventory or selection facts have changed."""


def _digest(value):
    return sha256(canonical_json(value)).hexdigest()


def _binding(db, selected):
    inventory = sha256()
    for record in latest(db):
        inventory.update(
            canonical_json({"record_key": record_key(record), "payload_sha256": _digest(record)})
        )
        inventory.update(b"\n")
    # Bind only the latest relevant selection graph, including issues and exact
    # capture identities, never loading raw frames or exporting selection prose.
    urls = tuple(sorted(selected.allowed_urls))
    marks = ",".join("?" for _ in urls)
    for row in db.execute(
        "SELECT * FROM source_selections WHERE vendor=? AND requested_url IN (" + marks + ") "
        "AND id IN (SELECT MAX(id) FROM source_selections WHERE vendor=? AND requested_url IN ("
        + marks
        + ") GROUP BY requested_url) ORDER BY requested_url",
        (selected.vendor, *urls, selected.vendor, *urls),
    ):
        facts = dict(row)
        facts["views"] = [
            dict(v)
            for v in db.execute(
                "SELECT v.*,e.source_url,e.sha256,e.observed_at FROM source_selection_views v "
                "JOIN evidence e ON e.id=v.evidence_id WHERE selection_id=? ORDER BY v.id",
                (row["id"],),
            )
        ]
        facts["issues"] = [
            dict(v)
            for v in db.execute(
                "SELECT * FROM source_selection_issues WHERE selection_id=? ORDER BY id",
                (row["id"],),
            )
        ]
        inventory.update(canonical_json(facts))
        inventory.update(b"\n")
    baseline = inventory.hexdigest()
    identities = {
        "baseline_fingerprint": baseline,
        "profile_fingerprint": selected.fingerprint,
        "policy_fingerprint": selected.policy_fingerprint,
        "normalizer_fingerprint": default_registry().fingerprint(selected.vendor),
    }
    return {**identities, "fingerprint": _digest(identities)}


def _preview(db, selected):
    records = latest(db)
    from ..adapters.arista_reconciliation import CSAF103, CSAF103_ID
    from ..plugins.arista_current_evidence import REVIEWED_SHA256

    targets = []
    issues = []
    for target in selected.metadata()["targets"]:
        found = [
            r
            for r in records
            if r["vendor"] == selected.vendor and r["advisory_id"] == target["advisory_id"]
        ]
        targets.append({**target, "before_keys": [record_key(r) for r in found]})
        if not found:
            issues.append({"code": "missing_primary_record", "source_url": target["source_url"]})
    if not any(
        r["vendor"] == selected.vendor
        and r["advisory_id"] == CSAF103_ID
        and r["source_url"] == CSAF103
        and r["sha256"] == REVIEWED_SHA256
        for r in records
    ):
        issues.append({"code": "missing_reviewed_legacy_record", "source_url": CSAF103})
    return {
        "format": "impact-maintenance-preview",
        "schema_version": 1,
        "profile_id": selected.profile_id,
        "profile_version": selected.version,
        **_binding(db, selected),
        "targets": targets,
        "issues": issues,
        "observed_at": now(),
    }


def preview(database: Path, profile_id: str) -> dict:
    """Preview a stable checkpointed input without opening source SQLite.

    WAL or rollback-journal data requires an operator-provided consistent backup.
    Never checkpoint a live input or open it with SQLite just to preview it.
    """
    from ..storage.checkpoint_copy import stable_checkpoint

    selected = registered_profile(profile_id)  # Validate before opening any database.
    with stable_checkpoint(
        database, error_prefix="maintenance", changed_error=MaintenanceBaselineChanged
    ) as copy:
        with closing(connect(copy, read_only=True)) as db:
            db.execute("BEGIN")
            receipt = _preview(db, selected)
            preview_bytes(receipt)
            return receipt


def validate_preview(value, selected):
    fields = {
        "format",
        "schema_version",
        "profile_id",
        "profile_version",
        "fingerprint",
        "baseline_fingerprint",
        "profile_fingerprint",
        "policy_fingerprint",
        "normalizer_fingerprint",
        "targets",
        "issues",
        "observed_at",
    }
    if (
        type(value) is not dict
        or set(value) != fields
        or value["format"] != "impact-maintenance-preview"
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["profile_id"] != selected.profile_id
        or value["profile_version"] != selected.version
    ):
        raise ValueError("invalid_maintenance_preview")
    for key in ("fingerprint", "baseline_fingerprint", "profile_fingerprint", "policy_fingerprint"):
        if type(value[key]) is not str or not re.fullmatch("[0-9a-f]{64}", value[key]):
            raise ValueError("invalid_maintenance_preview")
    if (
        value["profile_fingerprint"] != selected.fingerprint
        or value["policy_fingerprint"] != selected.policy_fingerprint
        or value["normalizer_fingerprint"] != default_registry().fingerprint(selected.vendor)
    ):
        raise MaintenanceBaselineChanged("maintenance_baseline_changed")
    identities = {
        k: value[k]
        for k in (
            "baseline_fingerprint",
            "profile_fingerprint",
            "policy_fingerprint",
            "normalizer_fingerprint",
        )
    }
    if value["fingerprint"] != _digest(identities):
        raise ValueError("invalid_maintenance_preview")
    expected = selected.metadata()["targets"]
    if type(value["targets"]) is not list or len(value["targets"]) != len(expected):
        raise ValueError("invalid_maintenance_preview")
    for target, want in zip(value["targets"], expected):
        if (
            type(target) is not dict
            or set(target) != set(want) | {"before_keys"}
            or any(target[k] != v for k, v in want.items())
            or type(target["before_keys"]) is not list
            or len(target["before_keys"]) > 1
            or any(
                type(k) is not str or not re.fullmatch("[0-9a-f]{64}", k)
                for k in target["before_keys"]
            )
        ):
            raise ValueError("invalid_maintenance_preview")
    from datetime import datetime

    try:
        if not datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00")).tzinfo:
            raise ValueError()
    except (AttributeError, TypeError, ValueError):
        raise ValueError("invalid_maintenance_preview") from None
    allowed_issues = {
        "missing_primary_record": set(selected.primary_urls),
        "missing_reviewed_legacy_record": selected.allowed_urls - set(selected.primary_urls),
    }
    if type(value["issues"]) is not list or len(value["issues"]) > 3:
        raise ValueError("invalid_maintenance_preview")
    seen = set()
    for issue in value["issues"]:
        if (
            type(issue) is not dict
            or set(issue) != {"code", "source_url"}
            or type(issue["code"]) is not str
            or type(issue["source_url"]) is not str
            or issue["source_url"] not in allowed_issues.get(issue["code"], ())
            or (issue["code"], issue["source_url"]) in seen
        ):
            raise ValueError("invalid_maintenance_preview")
        seen.add((issue["code"], issue["source_url"]))
    return value


def preview_bytes(receipt):
    """Closed preview wire encoder with the same inclusive 2 MB receipt limit."""
    if type(receipt) is not dict or type(receipt.get("profile_id")) is not str:
        raise ValueError("invalid_maintenance_preview")
    validate_preview(receipt, registered_profile(receipt["profile_id"]))
    raw = canonical_json(receipt) + b"\n"
    if len(raw) > 2_000_000:
        raise ValueError("maintenance_receipt_limit")
    return raw


def load_preview(path, selected):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("invalid_maintenance_preview")
            result[key] = value
        return result

    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError()
        return validate_preview(json.loads(raw, object_pairs_hook=unique), selected)
    except MaintenanceBaselineChanged:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise ValueError("invalid_maintenance_preview") from None


def apply_profile(
    db, profile: MaintenanceProfile, expected_preview_fingerprint: str, *, fetcher=None
) -> dict:
    """Append reviewed primaries; caller owns the shared writer lock.

    Capture/failure observations and independently committed revisions can survive
    failure. Only completed receipts establish the intended current-scope cleanup.
    """
    import sqlite3

    from ..adapters.arista_reconciliation import CSAF103
    from ..collection.errors import failure_code
    from ..collection.service import resolve_document, retain_resolution
    from ..collection.transport import fetch
    from ..plugins.arista_current_evidence import _alternate_proves_conflict
    from ..storage.repository import collection_result, evidence, ingest
    from .current_evidence import collect_policy_input, partition, report_bytes

    selected = registered_profile(profile.profile_id)
    if profile != selected:
        raise ValueError("unregistered_maintenance_profile")
    if type(expected_preview_fingerprint) is not str or not re.fullmatch(
        "[0-9a-f]{64}", expected_preview_fingerprint
    ):
        raise ValueError("invalid_maintenance_preview")
    before = _preview(db, selected)
    if before["fingerprint"] != expected_preview_fingerprint:
        raise MaintenanceBaselineChanged("maintenance_baseline_changed")
    receipt = {
        "format": "impact-maintenance-apply",
        "schema_version": 1,
        "profile_id": selected.profile_id,
        "profile_version": selected.version,
        "observed_at": now(),
        "preview_fingerprint": expected_preview_fingerprint,
        "baseline_fingerprint": before["baseline_fingerprint"],
        "profile_fingerprint": selected.fingerprint,
        "policy_fingerprint": selected.policy_fingerprint,
        "normalizer_fingerprint": before["normalizer_fingerprint"],
        "outcome": "failed_primary_validation",
        "primary_outcomes": [],
        "alternate_outcomes": [{"source_url": CSAF103, "outcome": "not_attempted"}],
        "imported": 0,
        "unchanged": 0,
        "before_keys": sorted(record_key(r) for r in latest(db)),
        "after_keys": [],
        "decisions": [],
        "proof_fingerprints": [],
        "issues": [],
    }
    cache = {}
    failures = {}
    retrieve = fetcher or fetch

    def bounded_fetch(connection, url, vendor):
        if url not in selected.allowed_urls or vendor != selected.vendor:
            raise ValueError("maintenance_url_rejected")
        if url in failures:
            raise failures[url]
        if url not in cache:
            try:
                raw = retrieve(
                    connection,
                    url,
                    vendor,
                    max_bytes=selected.max_bytes,
                    allowed_urls=selected.allowed_urls,
                )
                if type(raw) is not bytes or len(raw) > selected.max_bytes:
                    raise ValueError("maintenance_document_limit")
                with db:
                    evidence(db, raw, url)
                cache[url] = raw
            except sqlite3.Error as error:
                failures[url] = error
                raise
            except Exception as error:
                failures[url] = error
                collection_result(
                    db, vendor, url, "error", "Targeted retrieval failed", failure_code(error)
                )
                raise
        return cache[url]

    def finish(outcome):
        receipt["outcome"] = outcome
        receipt["after_keys"] = sorted(record_key(r) for r in latest(db))
        receipt_bytes(receipt)
        return receipt

    registry = default_registry()
    candidates = []
    try:
        # Every primary must validate before any normalized writer is reached.
        for url, advisory_id, cves in selected.expected_primaries:
            try:
                resolved = resolve_document(db, url, selected.vendor, fetcher=bounded_fetch)
                actual_url, raw = resolved
                parsed = registry.normalize(raw, actual_url, selected.vendor)
                if (
                    actual_url != url
                    or parsed["advisory_id"] != advisory_id
                    or parsed["cves"] != list(cves)
                ):
                    raise ValueError("maintenance_primary_identity_changed")
                candidates.append((url, resolved, parsed))
                receipt["primary_outcomes"].append({"source_url": url, "outcome": "validated"})
            except sqlite3.Error:
                raise
            except Exception as error:
                receipt["primary_outcomes"].append(
                    {"source_url": url, "outcome": "failed", "error_code": failure_code(error)}
                )
        if len(candidates) != len(selected.primary_urls):
            return finish("failed_primary_validation")
        # The resolver intentionally treats all alternate exceptions as unavailable.
        # Revalidate THIS attempt's exact alternate, not its retained policy proof.
        try:
            alternate = bounded_fetch(db, CSAF103, selected.vendor)
            if not _alternate_proves_conflict(alternate):
                raise ValueError("maintenance_alternate_scope_changed")
            receipt["alternate_outcomes"] = [
                {"source_url": CSAF103, "outcome": "expected_scope_conflict"}
            ]
        except sqlite3.Error:
            raise
        except Exception as error:
            receipt["alternate_outcomes"] = [
                {"source_url": CSAF103, "outcome": "failed", "error_code": failure_code(error)}
            ]
            return finish("failed_alternate_validation")
        for index, (url, resolved, parsed) in enumerate(candidates):
            changed = ingest(db, resolved[1], url, lambda *_: parsed, selected.vendor)
            receipt["imported" if changed else "unchanged"] += 1
            receipt["primary_outcomes"][index]["outcome"] = "imported" if changed else "unchanged"
            retain_resolution(db, selected.vendor, url, resolved)
        records = latest(db)
        context = collect_policy_input(db, records, registry=registry)
        result = partition(
            records,
            context,
            registry=registry,
            publication=None,
            generated_at=receipt["observed_at"],
        )
        report = result["current_evidence"]
        report_bytes(report)
        receipt["decisions"] = report["decisions"]
        receipt["issues"] = report["issues"]
        receipt["proof_fingerprints"] = sorted(
            {_digest(proof) for d in report["decisions"] for proof in d["proofs"]}
        )
        intended = [
            d
            for d in report["decisions"]
            if d["vendor"] == selected.vendor
            and d["policy_fingerprint"] == selected.policy_fingerprint
        ]
        if not intended or report["issues"]:
            return finish("failed_cleanup_proof")
        return finish("completed")
    except sqlite3.Error:
        db.rollback()
        return finish("failed_storage")
    except (ValueError, KeyError, TypeError):
        return finish("failed_cleanup_proof")


def validate_receipt(receipt):
    """Validate a closed public receipt against the installed reviewed profile.

    This validates structure and consistency, not authentication of saved files.
    """
    from jsonschema import Draft202012Validator, FormatChecker

    from .current_evidence import policy_metadata, validate_report

    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    keys = {"type": "array", "items": digest, "uniqueItems": True}
    failure = {
        "enum": [
            "source_missing",
            "redirect_target_missing",
            "http_error",
            "access_denied",
            "edge_access_denied",
            "rate_limited",
            "network_error",
            "collection_error",
            "access_verification_required",
            "unsupported_or_invalid_document",
        ]
    }

    def closed(properties):
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        }

    outcome = closed(
        {
            "source_url": {"type": "string"},
            "outcome": {
                "enum": [
                    "validated",
                    "imported",
                    "unchanged",
                    "expected_scope_conflict",
                    "not_attempted",
                ]
            },
        }
    )
    failed = closed(
        {"source_url": {"type": "string"}, "outcome": {"const": "failed"}, "error_code": failure}
    )
    schema = closed(
        {
            "format": {"const": "impact-maintenance-apply"},
            "schema_version": {"type": "integer", "const": 1},
            "profile_id": {"type": "string"},
            "profile_version": {"type": "string"},
            "observed_at": {"type": "string", "format": "date-time"},
            **{
                k: digest
                for k in (
                    "preview_fingerprint",
                    "baseline_fingerprint",
                    "profile_fingerprint",
                    "policy_fingerprint",
                )
            },
            "normalizer_fingerprint": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
            "outcome": {
                "enum": [
                    "completed",
                    "failed_primary_validation",
                    "failed_alternate_validation",
                    "failed_cleanup_proof",
                    "failed_storage",
                ]
            },
            "primary_outcomes": {
                "type": "array",
                "maxItems": 2,
                "items": {"anyOf": [outcome, failed]},
            },
            "alternate_outcomes": {
                "type": "array",
                "maxItems": 1,
                "items": {"anyOf": [outcome, failed]},
            },
            "imported": {"type": "integer", "minimum": 0, "maximum": 2},
            "unchanged": {"type": "integer", "minimum": 0, "maximum": 2},
            "before_keys": keys,
            "after_keys": keys,
            "proof_fingerprints": keys,
            "decisions": {"type": "array", "maxItems": 1000},
            "issues": {"type": "array", "maxItems": 1000},
        }
    )
    try:
        if not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(receipt):
            raise ValueError()
        selected = registered_profile(receipt["profile_id"])
        if (
            receipt["profile_version"] != selected.version
            or receipt["profile_fingerprint"] != selected.fingerprint
            or receipt["policy_fingerprint"] != selected.policy_fingerprint
            or receipt["normalizer_fingerprint"] != default_registry().fingerprint(selected.vendor)
            or receipt["preview_fingerprint"]
            != _digest(
                {
                    k: receipt[k]
                    for k in (
                        "baseline_fingerprint",
                        "profile_fingerprint",
                        "policy_fingerprint",
                        "normalizer_fingerprint",
                    )
                }
            )
        ):
            raise ValueError()
        for name in ("before_keys", "after_keys", "proof_fingerprints"):
            if receipt[name] != sorted(receipt[name]):
                raise ValueError()
        primary = receipt["primary_outcomes"]
        if any(
            r["source_url"] != selected.primary_urls[i]
            or r["outcome"] not in ("validated", "imported", "unchanged", "failed")
            for i, r in enumerate(primary)
        ):
            raise ValueError()
        alternate = receipt["alternate_outcomes"]
        alternate_urls = selected.allowed_urls - set(selected.primary_urls)
        if any(
            r["source_url"] not in alternate_urls
            or r["outcome"] not in ("expected_scope_conflict", "failed", "not_attempted")
            for r in alternate
        ):
            raise ValueError()
        policy = policy_metadata(default_registry().get(selected.vendor))
        decisions = receipt["decisions"]
        validate_report(
            {
                "schema_version": 1,
                "availability": "available",
                "publication": None,
                "generated_at": receipt["observed_at"],
                "policies": [policy],
                "decisions": decisions,
                "issues": receipt["issues"],
                "counts": {
                    "current": len(receipt["after_keys"]) - len(decisions),
                    "retained_total": len(receipt["after_keys"]),
                    "excluded": len(decisions),
                },
            }
        )
        hook = default_registry().get(selected.vendor).current_evidence_policy
        for decision in decisions:
            if decision["target_key"] not in receipt["after_keys"]:
                raise ValueError()
            if any(
                p["source_url"] not in hook.proof_sources or p["locator"] not in hook.proof_locators
                for p in decision["proofs"]
            ):
                raise ValueError()
        if receipt["proof_fingerprints"] != sorted(
            {_digest(p) for d in decisions for p in d["proofs"]}
        ):
            raise ValueError()
        if any(
            receipt[k] != sum(r["outcome"] == k for r in primary) for k in ("imported", "unchanged")
        ):
            raise ValueError()
        if receipt["imported"] + receipt["unchanged"] > 2:
            raise ValueError()
        if receipt["outcome"] == "completed" and (
            receipt["imported"] + receipt["unchanged"] != 2
            or len(primary) != 2
            or any(r["outcome"] not in ("imported", "unchanged") for r in primary)
            or len(alternate) != 1
            or alternate[0]["outcome"] != "expected_scope_conflict"
            or not decisions
            or receipt["issues"]
        ):
            raise ValueError()
    except (ValueError, TypeError, KeyError, IndexError):
        raise ValueError("invalid_maintenance_receipt") from None
    return receipt


def receipt_bytes(receipt):
    """Strict compact UTF-8 wire encoding, one newline, inclusive 2 MB limit."""
    validate_receipt(receipt)
    raw = canonical_json(receipt) + b"\n"
    if len(raw) > 2_000_000:
        raise ValueError("maintenance_receipt_limit")
    return raw
