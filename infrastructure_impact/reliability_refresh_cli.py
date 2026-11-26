"""Prepare independently reviewed release reliability evidence through explicit local paths."""

import argparse
import sys
from contextlib import ExitStack
from itertools import combinations
from pathlib import Path
from tempfile import TemporaryDirectory

from .application.reliability_refresh import prepare
from .collection.reliability_refresh import (
    SOURCES,
    SUCCESS,
    RefreshCache,
    collect,
    read_capture,
    regular_path,
)
from .release_catalogue_cli import MAX_BYTES, read_json
from .release_signals_cli import _dataset_lock, _json_bytes, _staged_file
from .settings import PACKAGE

_BASELINE = PACKAGE / "resources/release-catalogue.json"


def _arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    importer = commands.add_parser("import-capture", help="Import explicit original source bytes")
    collector = commands.add_parser("collect", help="Check a policy-gated Cisco source")
    preparer = commands.add_parser(
        "prepare", help="Validate a separate candidate and review report"
    )
    for command in (importer, collector, preparer):
        command.add_argument("--cache-dir", type=Path, required=True)
    for command in (importer, collector):
        command.add_argument("--source", choices=SOURCES, required=True)
    importer.add_argument("--input", type=Path, required=True)
    importer.add_argument("--retrieved-at", required=True)
    collector.add_argument("--policy-receipt", type=Path, required=True)
    preparer.add_argument("--catalogue", type=Path, default=_BASELINE)
    preparer.add_argument("--output", type=Path, required=True)
    preparer.add_argument("--report", type=Path, required=True)
    return parser, parser.parse_args(argv)


def _entry_identity(path):
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    return info.st_dev, info.st_ino


def _same_entry(first, second):
    if first == second:
        return True
    first_id, second_id = map(_entry_identity, (first, second))
    if first_id is not None or second_id is not None:
        return first_id == second_id
    parent_id = _entry_identity(first.parent)
    if parent_id is None or parent_id != _entry_identity(second.parent):
        return False
    # Ask the output filesystem how it compares two missing sibling names.
    with TemporaryDirectory(prefix=".refresh-path-check-", dir=first.parent) as directory:
        probe = Path(directory)
        (probe / first.name).touch(exist_ok=False)
        return (probe / second.name).exists()


def _check_destinations(baseline, output, report, cache_dir):
    protected = {_entry_identity(PACKAGE), _entry_identity(cache_dir)} - {None}
    if any(
        _entry_identity(parent) in protected for path in (output, report) for parent in path.parents
    ):
        raise ValueError("Candidate and report require separate paths outside cache and package")
    if any(_same_entry(cache_dir, path) for path in (output, report)) or any(
        _same_entry(first, second) for first, second in combinations((baseline, output, report), 2)
    ):
        raise ValueError("Candidate and report require separate paths outside cache and package")


def _prepare(args, cache):
    baseline, output, report = map(regular_path, (args.catalogue, args.output, args.report))
    _check_destinations(baseline, output, report, cache.directory)
    candidate, review = prepare(cache, read_json(baseline))
    contents = [_json_bytes(value) for value in (candidate, review)]
    if any(len(data) > MAX_BYTES for data in contents):
        raise ValueError("Candidate or report exceeds JSON size limit")
    directories = {_entry_identity(path.parent): path.parent for path in (output, report)}
    if None in directories:
        raise ValueError("Output parent directories must exist")
    with ExitStack() as stack:
        for identity in sorted(directories):
            stack.enter_context(_dataset_lock(directories[identity] / "refresh-output"))
        for path in (baseline, output, report):
            regular_path(path)
        _check_destinations(baseline, output, report, cache.directory)
        staged_candidate = stack.enter_context(_staged_file(output, contents[0]))
        staged_review = stack.enter_context(_staged_file(report, contents[1]))
        previous_review = None
        if report.exists():
            with report.open("rb") as handle:
                previous_bytes = handle.read(MAX_BYTES + 1)
            if len(previous_bytes) > MAX_BYTES:
                raise ValueError("Existing review report exceeds JSON size limit")
            previous_review = stack.enter_context(_staged_file(report, previous_bytes))

        staged_review.replace(report)
        try:
            staged_candidate.replace(output)
        except OSError:
            if previous_review is None:
                report.unlink()
            else:
                previous_review.replace(report)
            raise


def main(argv=None):
    parser, args = _arguments(argv)
    try:
        cache = RefreshCache(args.cache_dir)
        if args.command == "prepare":
            _prepare(args, cache)
            return 0
        if args.command == "import-capture":
            status = cache.import_capture(args.source, read_capture(args.input), args.retrieved_at)
        else:
            status = collect(cache, args.source, args.policy_receipt)
        print(f"{args.source}: {status}", file=sys.stderr)
        return 0 if status in SUCCESS else 1
    except (ValueError, OSError, TypeError, RecursionError) as error:
        parser.exit(1, f"Reliability refresh failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
