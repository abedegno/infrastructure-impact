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
    snap.add_argument(
        "--include-switching-analysis",
        action="store_true",
        help="Include optional source-owned switching analysis in this local export",
    )
    snap.add_argument(
        "--switching-analysis-input",
        type=Path,
        help="Explicit local JSON source frame for optional analysis",
    )
    snap.add_argument("--publication-format", choices=("v1", "v2"), default="v1")
    export = sub.add_parser(
        "publication-export", help="Stream a complete logical v2 root to a new local file"
    )
    export.add_argument("--publication", type=Path, required=True)
    export.add_argument("--root", required=True)
    export.add_argument("--output", type=Path, required=True)
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
    switching = sub.add_parser(
        "switching-backfill", help="Resume staging switching discovery without publication"
    )
    switching.add_argument("--config", type=Path, required=True)
    switching.add_argument("--vendor", choices=("cisco", "aruba", "arista"))
    switching.add_argument("--start-date", required=True)
    switching.add_argument("--end-date", required=True)
    switching.add_argument("--page-limit", type=int, default=2)
    switching.add_argument("--document-limit", type=int, default=8)
    switching.add_argument("--score-limit", type=int, default=0)
    first_fixed = sub.add_parser(
        "cisco-first-fixed", help="Explicit optional local IOS XE first-fixed queries"
    )
    first_fixed.add_argument("operation", choices=("plan", "run", "status"))
    first_fixed.add_argument("--release", action="append", default=[])
    first_fixed.add_argument("--max-releases", type=int, default=10)
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
    gaps = sub.add_parser(
        "coverage-gaps", help="Read-only explicit-vault source coverage inventory"
    )
    gaps.add_argument("--database", type=Path, required=True)
    gaps.add_argument("--config", type=Path, required=True)
    gaps.add_argument("--vendor")
    gaps.add_argument("--limit", type=int, default=32)
    gaps.add_argument("--output", type=Path)
    bench = sub.add_parser("benchmark", help="Refresh the declared benchmark")
    bench.add_argument("--aruba-limit", type=int, default=200)
    evaluation = sub.add_parser(
        "evaluate", help="Evaluate primary-source-reviewed benchmark expectations"
    )
    evaluation.add_argument("--fail-on-disagreement", action="store_true")
    switching_validation = sub.add_parser(
        "switching-validation", help="Separate switching source review and blind packet"
    )
    switching_validation.add_argument("--packet", action="store_true")
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
    reconcile = sub.add_parser("cve-reconcile", help="Local, offline official CVE reconciliation")
    modes = reconcile.add_subparsers(dest="reconcile_mode", required=True)
    for mode, arguments in {
        "verify": ("repository", "commit", "receipt"),
        "scan": ("repository", "commit", "receipt", "workspace", "start-date", "end-date"),
        "baseline": ("database", "config", "output"),
        "report": ("workspace", "baseline", "json-output", "csv-output"),
    }.items():
        command = modes.add_parser(mode)
        for argument in arguments:
            command.add_argument(
                "--" + argument,
                required=True,
                type=str if argument in {"commit", "start-date", "end-date"} else Path,
            )
        if mode == "scan":
            command.add_argument("--record-limit", type=int, default=5000)
            command.add_argument("--byte-limit", type=int, default=250000000)
    maintenance = sub.add_parser("maintenance", help="Preview-bound reviewed target refresh")
    maintenance_modes = maintenance.add_subparsers(dest="maintenance_mode", required=True)
    for mode in ("preview", "apply"):
        command = maintenance_modes.add_parser(mode)
        command.add_argument("--database", type=Path, required=True)
        command.add_argument("--profile", required=True)
        command.add_argument("--output", type=Path, required=True)
        if mode == "apply":
            command.add_argument("--preview", type=Path, required=True)
    target_import = sub.add_parser(
        "target-import", help="Preview exact imports against an explicit vault"
    )
    target_modes = target_import.add_subparsers(dest="target_import_mode", required=True)
    for mode in ("preview", "stage"):
        command = target_modes.add_parser(mode)
        command.add_argument("--database", type=Path, required=True)
        command.add_argument("--profile", required=True)
        command.add_argument("--output", type=Path, required=True)
        if mode == "stage":
            command.add_argument("--preview", type=Path, required=True)
            command.add_argument("--home", type=Path, required=True)
            command.add_argument("--capture-cache", type=Path)
            command.add_argument("--base-path", default="/")
            command.add_argument("--publication-format", choices=("v1", "v2"), default="v1")
    args = parser.parse_args(argv)
    if args.command == "publication-export":
        from .application.publication_reader import export_root

        export_root(args.publication, args.root, args.output)
        return 0
    if args.command == "target-import":
        return _target_import(args, parser)
    if args.command == "maintenance":
        return _maintenance(args, parser)
    if args.command == "cve-reconcile":
        return _reconcile(args, parser)
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
    elif args.command == "switching-validation":
        from .application import switching_validation
        from .application.source_scope import retained_scopes
        from .storage.repository import latest
        from .storage.source_selections import latest as source_selections

        with closing(connect(read_only=True)) as db:
            records = latest(db)
            from .application.query import current_partition

            if not args.packet:
                current, _ = current_partition(db, records)
            result = (
                switching_validation.packet(records)
                if args.packet
                else switching_validation.report(
                    current["records"],
                    retained_scopes(db, records, switching_validation.definition()),
                    retained_advisories=current["retained_advisories"],
                    source_selections=source_selections(db),
                )
            )
        print(json.dumps(result, indent=2))
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
                    from .application.query import current_partition

                    if not (args.packet or args.submission or args.submission_template):
                        current, _ = current_partition(db, records)
                    packet = review_packet(records)
                    result = (
                        audit_submission(read_review_file(args.submission), packet)
                        if args.submission
                        else submission_template(packet)
                        if args.submission_template
                        else packet
                        if args.packet
                        else validation_report(
                            current["records"],
                            scopes=retained_scopes(db, records, review_definition()),
                            retained_advisories=current["retained_advisories"],
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

        if args.switching_analysis_input is not None and not args.include_switching_analysis:
            parser.error("--switching-analysis-input requires --include-switching-analysis")
        analysis_input = {}
        if args.switching_analysis_input is not None:
            from .publication_codec import MAX_SELECTED, strict_loads

            if args.switching_analysis_input.stat().st_size > MAX_SELECTED:
                raise ValueError("Analysis input exceeds selected byte bound")
            analysis_input["switching_analysis_input"] = strict_loads(
                args.switching_analysis_input.read_bytes(), max_bytes=MAX_SELECTED
            )

        build(
            args.output,
            **({"publication_format": "v2"} if args.publication_format == "v2" else {}),
            **({"include_switching_analysis": True} if args.include_switching_analysis else {}),
            **analysis_input,
        )
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
    elif args.command == "switching-backfill":
        import os

        from .collection.config import load_config
        from .collection.switching_backfill import run as switching_run
        from .storage.locking import writer_lock

        if not os.environ.get("IMPACT_DATABASE"):
            parser.error("Set IMPACT_DATABASE to an explicit staging vault")
        config = load_config(args.config)
        with writer_lock() as acquired:
            if not acquired:
                parser.error("Another collector holds the writer lock")
            with closing(connect()) as db:
                try:
                    receipt = switching_run(
                        db,
                        config,
                        vendor=args.vendor,
                        start_date=args.start_date,
                        end_date=args.end_date,
                        page_limit=args.page_limit,
                        document_limit=args.document_limit,
                        score_limit=args.score_limit,
                    )
                except ValueError:
                    parser.error("Invalid switching source, date or budget")
        print(json.dumps(receipt, indent=2))
    elif args.command == "cisco-first-fixed":
        import os

        from .collection import cisco_first_fixed

        if not os.environ.get("IMPACT_DATABASE"):
            parser.error("Set IMPACT_DATABASE to an explicit staging database")
        with closing(connect()) as db:
            try:
                receipt = (
                    cisco_first_fixed.plan(db, args.release)
                    if args.operation == "plan"
                    else cisco_first_fixed.status(db)
                    if args.operation == "status"
                    else cisco_first_fixed.run(
                        db, releases=args.release, max_releases=args.max_releases
                    )
                )
            except ValueError:
                parser.error("Invalid Cisco first-fixed release selection or budget")
        print(json.dumps(receipt, indent=2))
    elif args.command == "coverage-gaps":
        import sqlite3

        from jsonschema import ValidationError

        from .application.coverage_gaps import report as coverage_report
        from .collection.config import load_config

        try:
            if not args.database.is_file() or not args.config.is_file():
                raise ValueError("Missing explicit input")
            protected = [args.database, args.config]
            for database in (args.database.absolute(), args.database.resolve()):
                protected.extend(
                    database.with_name(database.name + suffix)
                    for suffix in ("-wal", "-shm", "-journal")
                )
            if args.output and any(
                args.output.resolve() == source.resolve()
                or (args.output.exists() and source.exists() and args.output.samefile(source))
                for source in protected
            ):
                raise ValueError("Output aliases an input")
            config = load_config(args.config)
            with closing(connect(args.database, read_only=True)) as db:
                result = coverage_report(db, config, vendor=args.vendor, limit=args.limit)
            raw = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                args.output.write_text(raw, encoding="utf-8")
            else:
                print(raw, end="")
        except (OSError, ValueError, TypeError, sqlite3.Error, ValidationError):
            parser.error(
                "Coverage inventory failed: check explicit inputs, output, vendor and limit"
            )
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
        from .application.query import current_partition

        with closing(connect(read_only=True)) as db:
            current, _ = current_partition(db)
            result = evaluate(
                current["records"], retained_advisories=current["retained_advisories"]
            )
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


def _target_import(args, parser):
    """Dispatch before ambient settings, collector, recovery or configuration startup."""
    import os
    import sqlite3

    from .application import target_import
    from .application.target_import_contracts import load_preview, preview_bytes, result_bytes
    from .collection.target_import_profiles import profile

    try:
        selected = profile(args.profile)
        if (
            any(path.is_symlink() for path in (args.output, *args.output.parents))
            or args.output.exists()
        ):
            raise ValueError("unsafe_output_path")
        if any(
            args.output.resolve() == Path(str(args.database.resolve()) + suffix)
            for suffix in ("", "-wal", "-shm", "-journal")
        ):
            raise ValueError("unsafe_output_path")
        if args.target_import_mode == "stage":
            from .application.target_import_stage import stage

            accepted = load_preview(args.preview, selected)
            result = stage(
                args.database,
                selected,
                accepted["fingerprint"],
                args.output,
                lock_home=args.home,
                **({"capture_cache": args.capture_cache} if args.capture_cache is not None else {}),
                accepted_preview=accepted,
                base_path=args.base_path,
                **({"publication_format": "v2"} if args.publication_format == "v2" else {}),
            )
            payload = result_bytes(
                result, selected=selected, publication_format=args.publication_format
            )
            if args.output.is_dir():
                receipt_path = args.output / "result.json"
                fd = os.open(
                    receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
            print(payload.decode("utf-8"), end="")
            return 0 if result["outcome"] == "completed" else 1
        result = target_import.preview(args.database, selected.profile_id)
        payload = preview_bytes(result, selected=selected)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
    except (ValueError, OSError, sqlite3.Error) as error:
        codes = {
            "unknown_target_import_profile",
            "unsafe_input_path",
            "unsafe_output_path",
            "target_import_checkpoint_required",
            "target_import_baseline_changed",
            "target_import_input_missing",
            "target_import_receipt_size",
        }
        parser.error(str(error) if str(error) in codes else "target_import_failed")
    print(payload.decode("utf-8"), end="")
    return 0


def _maintenance(args, parser):
    import os

    from .application import maintenance
    from .collection.maintenance_profiles import profile

    try:
        selected = profile(args.profile)
        if any(p.is_symlink() for p in (args.output, *args.output.parents)) or args.output.exists():
            raise ValueError("unsafe_output_path")
        protected = [args.database]
        if args.maintenance_mode == "apply":
            protected.append(args.preview)
        if any(
            args.output.resolve() == Path(str(p.resolve()) + suffix)
            for p in protected
            for suffix in ("", "-wal", "-shm", "-journal")
        ):
            raise ValueError("unsafe_output_path")
        if args.maintenance_mode == "preview":
            result = maintenance.preview(args.database, selected.profile_id)
        else:
            from .storage.locking import writer_lock
            from .storage.repository import connect

            accepted = maintenance.load_preview(args.preview, selected)
            with writer_lock() as acquired:
                if not acquired:
                    result = {"outcome": "skipped_writer_lock", "profile_id": selected.profile_id}
                else:
                    with closing(connect(args.database)) as db:
                        result = maintenance.apply_profile(db, selected, accepted["fingerprint"])
        if args.maintenance_mode == "preview":
            payload = maintenance.preview_bytes(result).decode("utf-8")
        elif result["outcome"] == "skipped_writer_lock":
            payload = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        else:
            payload = maintenance.receipt_bytes(result).decode("utf-8")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
    except (ValueError, OSError) as error:
        codes = {
            "unknown_maintenance_profile",
            "unsafe_output_path",
            "invalid_maintenance_preview",
            "maintenance_baseline_changed",
            "unregistered_maintenance_profile",
            "invalid_maintenance_receipt",
            "maintenance_receipt_limit",
            "maintenance_checkpoint_required",
            "maintenance_input_missing",
        }
        parser.error(str(error) if str(error) in codes else "maintenance_failed")
    print(payload, end="")
    return 0 if args.maintenance_mode == "preview" or result["outcome"] == "completed" else 1


def _reconcile(args, parser):
    """Explicit reconciliation dispatch before any ambient application startup."""
    try:
        if args.reconcile_mode == "verify":
            from .reconciliation.snapshot import verify_snapshot

            result = verify_snapshot(args.repository, args.commit, args.receipt)
        elif args.reconcile_mode == "scan":
            from .reconciliation.scan import scan_snapshot

            result = scan_snapshot(
                repository=args.repository,
                commit=args.commit,
                receipt_path=args.receipt,
                workspace=args.workspace,
                start_date=args.start_date,
                end_date=args.end_date,
                record_limit=args.record_limit,
                byte_limit=args.byte_limit,
            )
        elif args.reconcile_mode == "baseline":
            from .reconciliation.baseline import export_baseline

            exported = export_baseline(
                database=args.database, config_path=args.config, output=args.output
            )
            result = {"fingerprint": exported["fingerprint"]}
        else:
            from .reconciliation.report import build_report, write_report

            report = build_report(workspace=args.workspace, baseline_path=args.baseline)
            write_report(
                report,
                json_path=args.json_output,
                csv_path=args.csv_output,
                workspace=args.workspace,
                baseline_path=args.baseline,
            )
            result = {
                "report_id": report["report_id"],
                "scan_complete": report["scan"]["scan_complete"],
                "coverage_complete": None,
            }
    except (ValueError, OSError) as error:
        parser.error(getattr(error, "code", "reconciliation_failed"))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1:])
