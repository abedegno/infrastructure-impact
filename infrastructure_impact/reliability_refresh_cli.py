"""Prepare independently reviewed release reliability evidence through explicit local paths."""

import argparse
import sys
from contextlib import ExitStack
from pathlib import Path

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


def _prepare(args, cache):
    baseline = regular_path(args.catalogue)
    output, report = map(regular_path, (args.output, args.report))

    def comparison_path(path):
        return Path(str(path).casefold()) if sys.platform == "darwin" else path

    if len({comparison_path(path) for path in (baseline, output, report)}) != 3 or any(
        comparison_path(path).is_relative_to(comparison_path(protected))
        for path in (output, report)
        for protected in (cache.directory, PACKAGE)
    ):
        raise ValueError("Candidate and report require separate paths outside cache and package")
    candidate, review = prepare(cache, read_json(baseline))
    contents = [_json_bytes(value) for value in (candidate, review)]
    if any(len(data) > MAX_BYTES for data in contents):
        raise ValueError("Candidate or report exceeds JSON size limit")
    with ExitStack() as stack:
        for directory in sorted({output.parent, report.parent}):
            stack.enter_context(_dataset_lock(directory / "refresh-output"))
        for path in (output, report):
            regular_path(path)
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
