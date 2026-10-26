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
    sub.add_parser("audit", help="Verify database, normalized records and retained source hashes")
    sub.add_parser(
        "reparse", help="Replay retained evidence through current schema-validated plugins"
    )
    check = sub.add_parser("validate", help="Validate a normalized advisory JSON file")
    check.add_argument("file", type=Path)
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
    bench = sub.add_parser("benchmark", help="Refresh the declared benchmark")
    bench.add_argument("--aruba-limit", type=int, default=200)
    evaluation = sub.add_parser(
        "evaluate", help="Evaluate primary-source-reviewed benchmark expectations"
    )
    evaluation.add_argument("--fail-on-disagreement", action="store_true")
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
                    }
                    for p in default_registry().all()
                ],
                indent=2,
            )
        )
    elif args.command == "migrate":
        with closing(connect()) as db:
            print(json.dumps([dict(row) for row in db.execute("SELECT * FROM schema_migrations")]))
    elif args.command == "reparse":
        from .application.replay import replay

        print(json.dumps({"reparsed_revisions": replay()}))
    elif args.command == "audit":
        from .storage.audit import audit

        print(json.dumps(audit()))
    elif args.command == "validate":
        from .domain import validate_advisory

        validate_advisory(json.loads(args.file.read_text()))
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
