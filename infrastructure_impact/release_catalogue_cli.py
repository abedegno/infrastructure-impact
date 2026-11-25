"""Offline catalogue validation and first-delivery summaries. Never reads a vault."""

import argparse
import json
from pathlib import Path

from .application.release_catalogue import catalogue_summary, find_respins, validate_catalogue
from .settings import PACKAGE

MAX_BYTES = 16 * 1024 * 1024


def read_json(path):
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Catalogue JSON exceeds 16 MiB")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = item
        return value

    def reject_constant(_):
        raise ValueError("Nonfinite JSON value")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalogue", type=Path, required=True)
    parser.add_argument(
        "--config", type=Path, default=PACKAGE / "resources/release-catalogue-trains.json"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.resolve() in {args.catalogue.resolve(), args.config.resolve()}:
            raise ValueError("Summary must not overwrite an input")
        catalogue = validate_catalogue(read_json(args.catalogue))
        result = catalogue_summary(catalogue, read_json(args.config))
        result["possible_and_corrective_respins"] = find_respins(catalogue, read_json(args.config))
        args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    except (ValueError, OSError) as error:
        parser.exit(1, f"Catalogue failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
