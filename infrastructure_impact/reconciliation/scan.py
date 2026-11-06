"""Bounded offline snapshot scanning; no fetch, clone, advisory or baseline I/O."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from . import state
from .selectors import load_selectors, select_record, selector_hash
from .snapshot import MAX_RECORD_BYTES, SnapshotError, open_snapshot

SCANNER_VERSION = "1"
MAX_INVOCATION_RECORDS = 5000
MAX_INVOCATION_BYTES = 250_000_000


def scan_snapshot(
    *,
    repository: Path,
    commit: str,
    receipt_path: Path,
    workspace: Path,
    start_date: str,
    end_date: str,
    record_limit: int = 5000,
    byte_limit: int = 250_000_000,
) -> dict:
    """Return cumulative progress plus this invocation's actual read counts/bytes."""
    for value, ceiling in (
        (record_limit, MAX_INVOCATION_RECORDS),
        (byte_limit, MAX_INVOCATION_BYTES),
    ):
        if type(value) is not int or not 0 <= value <= ceiling:
            raise ValueError("invalid_scan_limit")
    try:
        if (
            date.fromisoformat(start_date).isoformat() != start_date
            or date.fromisoformat(end_date).isoformat() != end_date
            or start_date > end_date
        ):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("invalid_date_window") from None
    repository, receipt_path = Path(repository), Path(receipt_path)
    workspace = state.validate_paths(Path(workspace), repository, receipt_path)
    snapshot = open_snapshot(repository, commit, receipt_path)
    entries = tuple(snapshot.iter_entries())
    rules = load_selectors()
    identity = dict(
        format_version=2,
        receipt_sha256=snapshot.receipt_sha256,
        commit=snapshot.commit,
        tree=snapshot.tree,
        selector_hash=selector_hash(rules),
        selector_version=rules["selector_version"],
        scanner_version=SCANNER_VERSION,
        start_date=start_date,
        end_date=end_date,
        total=len(entries),
        inventory_entries=snapshot.inventory_entries,
        inventory_bytes=snapshot.inventory_bytes,
    )
    attempted = consumed = 0
    with state.writable_workspace(workspace, identity, entries) as view:
        reason = "complete"
        with snapshot.blob_reader() as reader:
            for entry in entries[view.cursor :]:
                if attempted >= record_limit:
                    reason = "record_limit"
                    break
                raw = None
                result = dict(
                    outcome="oversized",
                    source_sha256=None,
                    findings=[],
                    diagnostic_codes=["record_byte_limit"],
                )
                if entry.size <= MAX_RECORD_BYTES:
                    if consumed + entry.size > byte_limit:
                        reason = "byte_limit"
                        break
                    attempted += 1
                    try:
                        raw = reader.read_blob(entry, max_bytes=MAX_RECORD_BYTES)
                    except SnapshotError as error:
                        if error.code != "git_object_unavailable":
                            raise
                        result = dict(
                            outcome="missing_object",
                            source_sha256=None,
                            findings=[],
                            diagnostic_codes=["git_object_unavailable"],
                        )
                    else:
                        consumed += len(raw)
                        result = select_record(
                            raw,
                            entry=entry,
                            snapshot=snapshot,
                            rules=rules,
                            start_date=start_date,
                            end_date=end_date,
                        )
                else:
                    attempted += 1
                try:
                    stage = view.stage(result)
                    view.commit_record(entry, result, raw, stage)
                except state.StorageLimit as error:
                    reason = error.code
                    break
        receipt = view.receipt(reason)
        receipt.update(invocation_attempted=attempted, invocation_consumed_bytes=consumed)
        return receipt
