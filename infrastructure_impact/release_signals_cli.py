"""Explicit-path commands for the standalone, opt-in release-signal dataset."""

import argparse
import fcntl
import hashlib
import json
import math
import os
import sys
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.error import URLError

from .application.release_signals import (
    add_document,
    build_report,
    new_dataset,
    to_csv,
    validate_dataset,
    validate_report,
)
from .collection.errors import failure_code
from .collection.release_signals import (
    ARISTA_URL,
    ARUBA_URL,
    CISCO_URL,
    MAX_DOCUMENT_BYTES,
    fetch_arista,
    parse_arista_releases,
    parse_aruba_history,
    parse_cisco_caveats,
)

_COHORT_START = "2024-01-01"
_MAX_JSON_BYTES = 64 * 1024 * 1024
_SOURCE_READERS = {
    "arista-rss": (ARISTA_URL, "arista", "4.33", parse_arista_releases),
    "cisco-caveats": (CISCO_URL, "cisco", "17.12", parse_cisco_caveats),
    "aruba-history": (ARUBA_URL, "aruba", "10.13", parse_aruba_history),
}
_GAPS = {
    "arista": "Public release RSS covers a rolling sample. Download details and history are unresolved.",
    "aruba": "Offline version-history reading only. The sampled anonymous origin route returned 403.",
    "cisco": "Offline caveat reading only. The sampled anonymous origin route returned 403.",
}


def _bounded_read(path, limit):
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"Input exceeds {limit} bytes")
    return raw


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _finite_number(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("nonfinite number")
    return parsed


def _read_json(path):
    raw = _bounded_read(path, _MAX_JSON_BYTES)
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_finite_number,
            parse_constant=_finite_number,
        )
    except (ValueError, RecursionError) as error:
        raise ValueError(f"Invalid JSON in {path.name}: {error}") from None


def _json_bytes(data):
    return (json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()


@contextmanager
def _dataset_lock(path):
    # Lock the existing directory inode so replacing the dataset does not invalidate the lock.
    handle = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        os.close(handle)


@contextmanager
def _staged_file(path, data):
    with NamedTemporaryFile(dir=path.parent, prefix=".release-signals-", delete=False) as handle:
        staged = Path(handle.name)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            yield staged
        finally:
            staged.unlink(missing_ok=True)


def _save_dataset(path, dataset):
    validate_dataset(dataset)
    data = _json_bytes(dataset)
    if len(data) > _MAX_JSON_BYTES:
        raise ValueError("Dataset exceeds CLI JSON size limit")
    with _staged_file(path, data) as staged:
        staged.replace(path)


def _set_coverage(dataset, vendor, train, start, end, status, reason):
    row = {
        "vendor": vendor,
        "train": train,
        "start": min(start, end),
        "end": end,
        "status": status,
        "expected_releases": None,
        "reason": reason,
    }
    rows = dataset["coverage"]
    identity = ("vendor", "train", "start", "end", "status")
    rows[:] = [
        previous
        for previous in rows
        if not (
            all(previous[key] == row[key] for key in identity)
            or (
                status == "partial"
                and (previous["vendor"], previous["train"], previous["start"])
                == (vendor, train, _COHORT_START)
                and previous["status"] == "not_collected"
                and previous["reason"] == _GAPS[vendor]
            )
        )
    ]
    rows.append(row)


def _mark_partial(dataset, vendor, train):
    _set_coverage(
        dataset,
        vendor,
        train,
        _COHORT_START,
        dataset["generated_at"][:10],
        "partial",
        _GAPS[vendor],
    )


def _init(args):
    if args.dataset.exists():
        raise ValueError("Dataset already exists")
    dataset = new_dataset(args.generated_at)
    for _, vendor, train, _ in _SOURCE_READERS.values():
        _set_coverage(
            dataset,
            vendor,
            train,
            _COHORT_START,
            args.generated_at[:10],
            "not_collected",
            _GAPS[vendor],
        )
    _save_dataset(args.dataset, dataset)
    return 0


def _import(args, dataset):
    url, vendor, train, parser = _SOURCE_READERS[args.parser]
    if args.source_url != url:
        raise ValueError("Source URL does not identify the reviewed parser route")
    if args.parser == "aruba-history" and args.capture_method != "rendered_capture":
        raise ValueError(
            "Aruba history requires an explicit rendered HTML capture of the reviewed source"
        )
    raw = _bounded_read(args.input, MAX_DOCUMENT_BYTES)
    events = parser(raw)
    add_document(dataset, raw, url, args.retrieved_at, events, capture_method=args.capture_method)
    _mark_partial(dataset, vendor, train)
    _save_dataset(args.dataset, dataset)
    return 0


def _cache_path(directory):
    resolved = directory.resolve()
    if any((ancestor / ".git").exists() for ancestor in [resolved, *resolved.parents]):
        raise ValueError("Raw responses must be cached outside Git workspaces")
    if resolved.exists() and not resolved.is_dir():
        raise ValueError("Raw cache path must be a directory")
    return resolved


def _collect(args, dataset):
    cache = _cache_path(args.cache_dir)
    try:
        raw = fetch_arista()
        events = parse_arista_releases(raw)
    except (ValueError, URLError, OSError) as error:
        now = datetime.now(UTC)
        code = "network_error" if isinstance(error, URLError) else failure_code(error)
        _set_coverage(
            dataset,
            "arista",
            "4.33",
            now.date().isoformat(),
            now.date().isoformat(),
            "blocked",
            f"Public release feed collection failed ({code}).",
        )
        dataset["generated_at"] = max(
            now, datetime.fromisoformat(dataset["generated_at"])
        ).isoformat()
        _save_dataset(args.dataset, dataset)
        print(f"Arista collection failed ({code})", file=sys.stderr)
        return 1

    retrieved_at = datetime.now(UTC).isoformat()
    add_document(dataset, raw, ARISTA_URL, retrieved_at, events)
    _mark_partial(dataset, "arista", "4.33")
    cache.mkdir(parents=True, exist_ok=True)
    raw_path = cache / f"{hashlib.sha256(raw).hexdigest()}.xml"
    if raw_path.is_symlink():
        raise ValueError("Cached response path must not be a symlink")
    if raw_path.exists():
        if _bounded_read(raw_path, MAX_DOCUMENT_BYTES) != raw:
            raise ValueError("Cached response does not match its fingerprint")
    else:
        with _staged_file(raw_path, raw) as staged:
            staged.replace(raw_path)
    _save_dataset(args.dataset, dataset)
    return 0


def _report(args, dataset):
    outputs = [args.json_output.resolve(), args.csv_output.resolve()]
    inputs = [args.dataset] + ([args.upgrades.resolve()] if args.upgrades else [])
    paths = inputs + outputs
    if len(paths) != len(set(paths)) or any(
        path.exists() and other.exists() and path.samefile(other)
        for index, path in enumerate(paths)
        for other in paths[index + 1 :]
    ):
        raise ValueError("Report inputs and outputs must be separate files")
    if any(not path.parent.is_dir() or (path.exists() and not path.is_file()) for path in outputs):
        raise ValueError("Report outputs must identify regular files in existing directories")
    upgrades = _read_json(args.upgrades) if args.upgrades else None
    report = build_report(dataset, start=args.start, end=args.end, upgrades=upgrades)
    validate_report(report)
    with ExitStack() as stack:
        json_file = stack.enter_context(_staged_file(outputs[0], _json_bytes(report)))
        csv_file = stack.enter_context(_staged_file(outputs[1], to_csv(report).encode()))
        backup = None
        if outputs[0].exists():
            backup = stack.enter_context(_staged_file(outputs[0], b""))
            backup.unlink()
            os.link(outputs[0], backup)
        json_file.replace(outputs[0])
        try:
            csv_file.replace(outputs[1])
        except OSError:
            if backup is None:
                outputs[0].unlink()
            else:
                backup.replace(outputs[0])
            raise
    return 0


def _arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a new standalone dataset with coverage gaps")
    init.add_argument("--generated-at", required=True)
    import_document = commands.add_parser("import-document", help="Import retained source bytes")
    import_document.add_argument("--parser", choices=_SOURCE_READERS, required=True)
    import_document.add_argument("--source-url", required=True)
    import_document.add_argument("--input", required=True, type=Path)
    import_document.add_argument("--retrieved-at", required=True)
    import_document.add_argument(
        "--capture-method", choices=("http_response", "rendered_capture"), default="http_response"
    )
    collect = commands.add_parser("collect-arista", help="Fetch the public Arista software RSS")
    collect.add_argument("--cache-dir", required=True, type=Path)
    report = commands.add_parser("report", help="Write local JSON and CSV reports")
    for flag in ("--start", "--end"):
        report.add_argument(flag, required=True)
    for flag in ("--json-output", "--csv-output"):
        report.add_argument(flag, required=True, type=Path)
    report.add_argument("--upgrades", type=Path)
    for command in (init, import_document, collect, report):
        command.add_argument("--dataset", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv=None):
    args = _arguments(argv)
    try:
        args.dataset = args.dataset.resolve()
        with _dataset_lock(args.dataset):
            if args.command == "init":
                return _init(args)
            dataset = _read_json(args.dataset)
            validate_dataset(dataset)
            if args.command == "import-document":
                return _import(args, dataset)
            if args.command == "collect-arista":
                return _collect(args, dataset)
            return _report(args, dataset)
    except (ValueError, OSError, RecursionError) as error:
        print(f"Release signals: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
