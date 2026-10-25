"""Standards-based parser available to new vendor plugins."""

import json

from ..adapters.standards import cna, csaf


def structured(raw, url, vendor):
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(
            "Expected CSAF or CVE JSON; vendor HTML requires a reviewed plugin parser"
        ) from exc
    if "document" in data:
        return csaf(raw, url, vendor)
    if "cveMetadata" in data and "containers" in data:
        return cna(raw, url, vendor)
    raise ValueError("Unrecognized structured advisory format")


def is_json(raw):
    return raw.lstrip().startswith(b"{" if isinstance(raw, bytes) else "{")
