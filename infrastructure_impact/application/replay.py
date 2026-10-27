"""Offline re-normalization from retained evidence, never invented source changes."""

import json
from contextlib import closing, nullcontext

from ..plugins.registry import default_registry
from ..storage.locking import writer_lock
from ..storage.repository import connect, ingest, latest, semantic_diff
from .cohort import COHORT


class ReparseIdentityError(ValueError):
    """A retained identity cannot be reproduced safely by the current parser."""


class MissingNormalizerError(ValueError):
    """A retained vendor's trusted parser is no longer installed."""


def normalized_record(registry, record, raw):
    vendor, url = record["vendor"], record["source_url"]
    plugin = registry.get(vendor)
    if record["source_format"] in ("RSS discovery metadata", "Check Point public advisory JSON"):
        if plugin.parse_feed is None:
            raise ValueError("Retained feed parser is unavailable")
        batch = plugin.parse_feed(raw, url, 100000, frozenset(COHORT))
        documents = [r for r in batch.records if r["advisory_id"] == record["advisory_id"]]
        if len(documents) != 1:
            raise ReparseIdentityError("Retained feed identity is missing or ambiguous")
        document = registry.finalize(documents[0], url, vendor)
    else:
        document = registry.normalize(raw, url, vendor)
    if (document["vendor"], document["advisory_id"], document["source_url"]) != (
        vendor,
        record["advisory_id"],
        url,
    ):
        raise ReparseIdentityError("Reparse changed a stable record identity; review required")
    return document


def replay_report(*, dry_run=False, vendor=None, limit=1000, force=False, db_path=None):
    """Bounded latest-record maintenance; unsupported sources remain retained.

    Preview uses a read-only connection and never takes a writer lock. Apply
    shares collection's process lock. There are no retrieval or health updates.
    """
    registry = default_registry()
    if vendor is not None:
        registry.get(vendor)
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError("Reparse limit must be an integer between 1 and 10000")
    report = dict(
        schema_version=1,
        dry_run=bool(dry_run),
        outcome="ok",
        vendor=vendor,
        limit=limit,
        selected_records=0,
        already_current=0,
        candidates=0,
        attempted=0,
        would_reparse=0,
        reparsed_revisions=0,
        semantic_changes=0,
        unchanged=0,
        failed=0,
        remaining_candidates=0,
        examples=[],
        examples_truncated=False,
        failures=[],
        failures_truncated=False,
        network_requests=0,
        retrieval_observations_added=0,
        method="Latest retained representations only. Differences can include provenance and scope context, not new security exposure or publisher changes. First capture times remain intact; failed records are preserved for review.",
    )
    lock = nullcontext(True) if dry_run else writer_lock()
    with lock as acquired:
        if not acquired:
            report["outcome"] = "skipped_writer_lock"
            return report
        with closing(connect(db_path, read_only=dry_run)) as db:
            records = [r for r in latest(db) if vendor is None or r["vendor"] == vendor]
            fingerprints = {
                v: registry.fingerprint(v)
                for v in {r["vendor"] for r in records}
                if v in registry.names()
            }
            candidates = [
                r for r in records if force or r["adapter_version"] != fingerprints.get(r["vendor"])
            ]
            report.update(
                selected_records=len(records),
                candidates=len(candidates),
                already_current=sum(
                    r["adapter_version"] == fingerprints.get(r["vendor"]) for r in records
                ),
                remaining_candidates=max(0, len(candidates) - limit),
            )
            for record in candidates[:limit]:
                report["attempted"] += 1
                # SQL failures are fatal; do not disguise database corruption as
                # a publisher layout gap or continue writes after a storage error.
                row = db.execute(
                    "SELECT raw FROM evidence WHERE id=?", (record["evidence_id"],)
                ).fetchone()
                previous = json.loads(
                    db.execute(
                        "SELECT normalized FROM revisions WHERE id=?", (record["revision_id"],)
                    ).fetchone()[0]
                )
                item = {
                    k: record[k]
                    for k in ("vendor", "advisory_id", "revision_id", "sha256", "adapter_version")
                }
                # Count bounds alone do not bound job logs if a publisher uses
                # an unexpectedly long identifier. The stored identity is intact.
                if len(item["advisory_id"]) > 240:
                    item["advisory_id"] = item["advisory_id"][:240]
                    item["identity_label_truncated"] = True
                item["current_normalizer_fingerprint"] = fingerprints.get(record["vendor"])
                try:
                    if record["vendor"] not in fingerprints:
                        raise MissingNormalizerError("Vendor normalizer is unavailable")
                    if row is None:
                        raise ValueError("Retained source evidence is unavailable")
                    document = normalized_record(registry, record, row["raw"])
                except Exception as error:
                    # Installed parsers are trusted code, but one failed record
                    # must not prevent independent valid records from being checked.
                    # Do not echo raw exception values/source text into job logs.
                    report["failed"] += 1
                    code = (
                        "vendor_plugin_unavailable"
                        if isinstance(error, MissingNormalizerError)
                        else "stable_identity_requires_review"
                        if isinstance(error, ReparseIdentityError)
                        else "unsupported_or_invalid_document"
                        if isinstance(error, (ValueError, KeyError, TypeError, IndexError))
                        else "normalizer_runtime_error"
                    )
                    item.update(outcome="failed", error_code=code, error_type=type(error).__name__)
                    if len(report["failures"]) < 20:
                        report["failures"].append(item)
                    else:
                        report["failures_truncated"] = True
                else:
                    if previous == document:
                        report["unchanged"] += 1
                        item["outcome"] = "unchanged"
                    else:
                        report["would_reparse"] += 1
                        if semantic_diff(previous, document):
                            report["semantic_changes"] += 1
                        if not dry_run:
                            # Ingest failures remain fatal. Evidence capture is
                            # deduplicated; same-byte changes are reinterpretations.
                            report["reparsed_revisions"] += bool(
                                ingest(
                                    db,
                                    row["raw"],
                                    record["source_url"],
                                    lambda *args, document=document: document,
                                    record["vendor"],
                                )
                            )
                        item["outcome"] = "would_reparse" if dry_run else "reparsed"
                if len(report["examples"]) < 20:
                    report["examples"].append(item)
                else:
                    report["examples_truncated"] = True
            report["outcome"] = (
                "partial" if report["failed"] or report["remaining_candidates"] else "ok"
            )
    return report


def replay():
    """Compatibility API: strict full replay returning the revision count."""
    registry = default_registry()
    changed = 0
    with writer_lock() as acquired:
        if not acquired:
            raise RuntimeError("Another writer holds the collection lock")
        with closing(connect()) as db:
            for record in latest(db):
                raw = db.execute(
                    "SELECT raw FROM evidence WHERE id=?", (record["evidence_id"],)
                ).fetchone()[0]
                document = normalized_record(registry, record, raw)
                changed += ingest(
                    db,
                    raw,
                    record["source_url"],
                    lambda *args, document=document: document,
                    record["vendor"],
                )
    return changed
