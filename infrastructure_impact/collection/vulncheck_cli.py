"""Private CLI boundary, without configuration or default-vault access."""

import json
import sqlite3

from ..application.strict_json import loads
from .vulncheck_kev import collect, report


def run(args, parser):
    try:
        if args.vc_mode == "collect":
            result = collect(args.state, force=args.force)
            print(json.dumps(result, indent=2))
            return 0 if result["outcome"] in ("ok", "cached") else 1
        scope = args.cve
        if args.scope:
            with args.scope.open("rb") as stream:
                ids = loads(stream.read(4_000_001), budget=4_000_000)
            if not isinstance(ids, list):
                raise ValueError("Scope must be a JSON array")
            scope = scope + ids
        if not scope:
            raise ValueError("Provide --cve or --scope")
        cisa_ids = None
        cisa_source = {"availability": "missing"}
        if args.cisa_report:
            from ..application.kev import select_report, validate_report

            with args.cisa_report.open("rb") as stream:
                supplied = loads(stream.read(16_000_001), budget=16_000_000)
            validate_report(supplied)
            selected = select_report(supplied, scope)
            cisa_source = {**selected["source"], "catalogue": selected["catalogue"]}
            if selected["source"]["availability"] == "available":
                cisa_ids = set(selected["listed_cve_ids"])
        result = report(args.state, scope, cisa_ids=cisa_ids)
        result["cisa_source"] = cisa_source
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, TypeError, sqlite3.Error):
        # No file paths, feed content, credentials or reflected transport details.
        parser.error("Private KEV input rejected; check file bounds, schema and state path")
