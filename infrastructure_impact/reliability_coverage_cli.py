"""Export coverage gaps from a retained public reliability report, without network access."""

import argparse
import json
import os
import tempfile
from pathlib import Path

from .application.reliability_coverage import build_coverage, csv_export
from .release_catalogue_cli import read_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    args = parser.parse_args(argv)
    temporary = None
    try:
        if args.output.resolve() == args.input.resolve() or (
            args.output.exists() and args.output.samefile(args.input)
        ):
            raise ValueError("Coverage output must not overwrite its input")
        value = build_coverage(read_json(args.input))
        body = (
            json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
            if args.format == "json"
            else csv_export(value, max_bytes=16 * 1024 * 1024)
        )
        if len(body.encode("utf-8")) > 16 * 1024 * 1024:
            raise ValueError("Coverage output exceeds 16 MiB")
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=args.output.parent,
            prefix=".reliability-coverage-",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(body)
        os.replace(temporary, args.output)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Coverage failed: {error}\n")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
