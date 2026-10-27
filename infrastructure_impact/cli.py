"""Supported command-line interface for operators and plugin authors."""

import argparse
import json
import logging
import sys
from contextlib import closing
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="impact", description="Infrastructure CVE evidence collection and serving"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plugins", help="List installed vendor plugins and capabilities")
    sub.add_parser("migrate", help="Apply additive database migrations")
    audit_parser = sub.add_parser(
        "audit", help="Verify database, normalized records and retained source hashes"
    )
    audit_parser.add_argument(
        "--storage",
        action="store_true",
        help="Read-only aggregate storage accounting without returning source content",
    )
    reparse = sub.add_parser(
        "reparse", help="Replay retained evidence through current schema-validated plugins"
    )
    reparse.add_argument("--dry-run", action="store_true")
    reparse.add_argument("--vendor")
    reparse.add_argument("--limit", type=int, default=1000)
    reparse.add_argument(
        "--force", action="store_true", help="Also check records using current code identities"
    )
    check = sub.add_parser("validate", help="Validate a normalized advisory JSON file")
    check.add_argument("file", type=Path)
    check.add_argument("--schema", choices=("advisory", "component-inventory"), default="advisory")
    snap = sub.add_parser(
        "snapshot", help="Publish a validated generation and export static assets"
    )
    snap.add_argument("--output", type=Path)
    collect = sub.add_parser("collect", help="Collect evidence and publish new data")
    collect.add_argument("--dry-run", action="store_true")
    collect.add_argument("--watch", action="store_true")
    collect.add_argument("--at", default="08:15")
    collect.add_argument("--timezone", default="Europe/London")
    sync = sub.add_parser("sync", help="Collect configured feeds and pinned sources")
    sync.add_argument("--config", type=Path)
    sync.add_argument("--limit", type=int, default=4)
    sync.add_argument("--upstream-limit", type=int, default=0)
    archive = sub.add_parser("backfill", help="Resume bounded historical document collection")
    archive.add_argument("--config", type=Path)
    archive.add_argument("--vendor")
    archive.add_argument("--page-limit", type=int)
    archive.add_argument("--document-limit", type=int)
    archive.add_argument("--refresh-pages", action="store_true")
    archive.add_argument("--retry-errors", action="store_true")
    triage = sub.add_parser(
        "triage", help="Group a bounded pending/error archive sample by layout and parser outcome"
    )
    triage.add_argument("--vendor")
    triage.add_argument("--limit", type=int, default=32)
    triage.add_argument(
        "--fetch",
        action="store_true",
        help="Retrieve and retain official sources without ingesting or changing queue state",
    )
    triage.add_argument("--output", type=Path)
    bench = sub.add_parser("benchmark", help="Refresh the declared benchmark")
    bench.add_argument("--aruba-limit", type=int, default=200)
    evaluation = sub.add_parser(
        "evaluate", help="Evaluate primary-source-reviewed benchmark expectations"
    )
    evaluation.add_argument("--fail-on-disagreement", action="store_true")
    validation = sub.add_parser(
        "validation",
        help="Evaluate pinned source-led checks or emit a blind independent-review packet",
    )
    validation_modes = validation.add_mutually_exclusive_group()
    validation_modes.add_argument("--packet", action="store_true")
    validation_modes.add_argument("--submission", type=Path)
    validation_modes.add_argument("--submission-template", action="store_true")
    validation.add_argument("--packet-file", type=Path)
    validation.add_argument("--fail-on-disagreement", action="store_true")
    sub.add_parser(
        "source-audit", help="Audit retained source scope without making network requests"
    )
    sub.add_parser("report", help="Regenerate coverage reports")
    research = sub.add_parser("research", help="Release evidence and correction review workflow")
    research.add_argument("arguments", nargs=argparse.REMAINDER)
    serve = sub.add_parser("serve", help="Serve public generations with Waitress; no vault access")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--publications", type=Path)
    backup = sub.add_parser("backup", help="Create an online, consistent SQLite vault backup")
    backup.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    from .plugins.registry import default_registry
    from .settings import Paths
    from .storage.repository import connect

    if args.command == "plugins":
        print(
            json.dumps(
                [
                    {
                        "id": p.id,
                        "name": p.name,
                        "domains": p.domains,
                        "version": p.version,
                        "capabilities": p.capabilities,
                        "normalizer_fingerprint_scheme": default_registry().fingerprint_scheme(
                            p.id
                        ),
                        "current_normalizer_fingerprint": default_registry().fingerprint(p.id),
                    }
                    for p in default_registry().all()
                ],
                indent=2,
            )
        )
    elif args.command == "validation":
        from .application.extraction_validation import definition as review_definition
        from .application.extraction_validation import review_packet, validation_report
        from .application.review_submission import audit_submission, submission_template
        from .application.source_scope import retained_scopes
        from .storage.repository import latest

        def read_review_file(path):
            with path.open("rb") as stream:
                raw = stream.read(262145)
            if len(raw) > 262144:
                raise ValueError("Review file exceeds 256 KiB")
            return json.loads(raw)

        if args.packet_file and not args.submission:
            parser.error("--packet-file requires --submission")
        try:
            if args.submission and args.packet_file:
                result = audit_submission(
                    read_review_file(args.submission), read_review_file(args.packet_file)
                )
            else:
                with closing(connect(read_only=True)) as db:
                    records = latest(db)
                    packet = review_packet(records)
                    result = (
                        audit_submission(read_review_file(args.submission), packet)
                        if args.submission
                        else submission_template(packet)
                        if args.submission_template
                        else packet
                        if args.packet
                        else validation_report(
                            records, scopes=retained_scopes(db, records, review_definition())
                        )
                    )
        except ValueError as error:
            parser.error(str(error))
        print(json.dumps(result, indent=2))
        if (
            args.fail_on_disagreement
            and not (args.packet or args.submission or args.submission_template)
            and any(
                c["outcome"] in ("disagreement", "product_scope_missing") for c in result["cases"]
            )
        ):
            raise SystemExit(1)
    elif args.command == "migrate":
        with closing(connect()) as db:
            print(json.dumps([dict(row) for row in db.execute("SELECT * FROM schema_migrations")]))
    elif args.command == "reparse":
        from .application.replay import replay_report

        try:
            result = replay_report(
                dry_run=args.dry_run, vendor=args.vendor, limit=args.limit, force=args.force
            )
        except ValueError as error:
            parser.error(str(error))
        print(json.dumps(result))
        if result["outcome"] != "ok":
            raise SystemExit(1)
    elif args.command == "audit":
        from .storage.audit import audit

        if args.storage:
            from .storage.profiling import storage_profile

            with closing(connect(read_only=True)) as db:
                print(json.dumps(storage_profile(db)))
        else:
            print(json.dumps(audit()))
    elif args.command == "validate":
        from .domain import validate_advisory, validate_component_inventory

        document = json.loads(args.file.read_text())
        if args.schema == "component-inventory":
            validate_component_inventory(document)
            print("Normalized component reference is valid")
        else:
            validate_advisory(document)
            print("Normalized advisory is valid")
    elif args.command == "snapshot":
        from .application.publication import build

        build(args.output)
    elif args.command == "collect":
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "home": str(Paths.from_env().home),
                        "steps": ["collect", "benchmark", "validate", "publish"],
                        "hosted_auto_publication": False,
                    }
                )
            )
            return
        from .worker import collect_once, watch

        if args.watch:
            import signal
            import threading
            from zoneinfo import ZoneInfo

            try:
                hour, minute = map(int, args.at.split(":"))
                if not 0 <= hour < 24 or not 0 <= minute < 60:
                    raise ValueError
                ZoneInfo(args.timezone)
            except (ValueError, KeyError) as exc:
                parser.error(f"Invalid schedule: {exc}")
            stop = threading.Event()
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: stop.set())
            watch(hour, minute, args.timezone, stop)
        else:
            collect_once()
    elif args.command == "sync":
        from .collection.config import load_config
        from .collection.service import run

        if args.limit < 0 or args.upstream_limit < 0:
            parser.error("Limits must be nonnegative")
        print(run(load_config(args.config), args.limit, upstream_limit=args.upstream_limit))
    elif args.command == "backfill":
        from .collection.archive import run as backfill
        from .collection.config import load_config
        from .worker import writer_lock

        with writer_lock() as acquired:
            if not acquired:
                parser.error("Another collector holds the writer lock")
            try:
                result = backfill(
                    load_config(args.config),
                    vendor=args.vendor,
                    page_limit=args.page_limit,
                    document_limit=args.document_limit,
                    refresh_pages=args.refresh_pages,
                    retry_errors=args.retry_errors,
                )
            except ValueError as error:
                parser.error(str(error))
        print(json.dumps(dict(imported=result[0], failed=result[1])))
        if result[1]:
            raise SystemExit(1)
    elif args.command == "triage":
        from .collection.triage import review_batch
        from .worker import writer_lock

        with writer_lock() as acquired:
            if not acquired:
                parser.error("Another collector holds the writer lock")
            with closing(connect()) as db:
                result = review_batch(db, vendor=args.vendor, limit=args.limit, retrieve=args.fetch)
        raw = json.dumps(result, indent=2) + "\n"
        if args.output:
            args.output.write_text(raw)
            print(
                json.dumps(
                    dict(
                        selected=result["selected"],
                        dispositions=result["dispositions"],
                        output=str(args.output),
                    )
                )
            )
        else:
            print(raw)
    elif args.command == "benchmark":
        from .application.benchmark import run

        print(run(args.aruba_limit))
    elif args.command == "evaluate":
        from .application.evaluation import evaluate
        from .storage.repository import latest

        with closing(connect(read_only=True)) as db:
            result = evaluate(latest(db))
        print(json.dumps(result, indent=2))
        if args.fail_on_disagreement and result["passed"] != result["total"]:
            raise SystemExit(1)
    elif args.command == "source-audit":
        from .application.source_audit import source_audit
        from .storage.repository import latest

        with closing(connect(read_only=True)) as db:
            print(json.dumps(source_audit(db, latest(db)), indent=2))
    elif args.command == "report":
        from .application.reporting import report

        report()
    elif args.command == "research":
        from .research_cli import main as research_main

        research_main(args.arguments)
    elif args.command == "serve":
        from waitress import serve

        from .http import Application

        serve(
            Application(args.publications or Paths.from_env().publications),
            host=args.host,
            port=args.port,
            threads=4,
            expose_tracebacks=False,
            max_request_body_size=0,
            max_request_header_size=16384,
            connection_limit=100,
            channel_timeout=30,
        )
    elif args.command == "backup":
        import sqlite3

        if args.destination.exists():
            parser.error("Backup destination already exists; no file overwritten")
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        with (
            closing(connect(read_only=True)) as source,
            closing(sqlite3.connect(args.destination)) as target,
        ):
            source.backup(target)
        print(args.destination)


if __name__ == "__main__":
    main(sys.argv[1:])
