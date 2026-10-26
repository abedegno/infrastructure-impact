"""Bounded NVD 2.0 OpenSSH registry mappings; never product affectedness."""

import json
import re
from datetime import datetime
from hashlib import sha256

PARSER_VERSION = "nvd-openssh-products/1"
PREFIX = "cpe:2.3:a:openbsd:openssh:"


def semantic_fingerprint(cve):
    fields = {
        "id": cve["id"],
        "published": cve["published"],
        "descriptions": [d for d in cve["descriptions"] if d.get("lang") == "en"],
        "configurations": cve.get("configurations", []),
        "rejected": cve.get("vulnStatus") == "Rejected",
    }
    return sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def mappings(value):
    """Traverse mappings without flattening AND/OR or negation into exposure."""
    if isinstance(value, dict):
        if isinstance(value.get("criteria"), str) and value["criteria"].startswith(PREFIX):
            yield value
        for child in value.values():
            yield from mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from mappings(child)


def parse_openssh(raw):
    data = json.loads(raw)
    rows = data.get("vulnerabilities")
    if (
        data.get("format") != "NVD_CVE"
        or data.get("version") != "2.0"
        or not isinstance(rows, list)
        or not rows
        or len(rows) > 2000
        or type(data.get("startIndex")) is not int
        or data["startIndex"] != 0
        or type(data.get("totalResults")) is not int
        or type(data.get("resultsPerPage")) is not int
        or data["totalResults"] != len(rows)
        or data["resultsPerPage"] != len(rows)
    ):
        raise ValueError("Expected complete, nonempty, single-page NVD 2.0 response")
    records = []
    seen = set()
    for item in rows:
        cve = item["cve"]
        cid = cve["id"]
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cid) or cid in seen:
            raise ValueError("Invalid or duplicate NVD CVE identity")
        seen.add(cid)
        datetime.fromisoformat(cve["published"].replace("Z", "+00:00"))
        refs = list(mappings(cve.get("configurations", [])))
        if not refs or not any(d.get("lang") == "en" for d in cve["descriptions"]):
            raise ValueError("Missing reviewed product mapping or English description")
        if any(type(m.get("vulnerable")) is not bool for m in refs):
            raise ValueError("Product mapping lacks a Boolean vulnerability flag")
        records.append(
            {
                "cve_id": cid,
                "publisher_published_at": cve["published"],
                "record_semantic_sha256": semantic_fingerprint(cve),
                "rejected": cve.get("vulnStatus") == "Rejected",
                "has_positive_product_mapping": any(m["vulnerable"] for m in refs),
            }
        )
    return {"parser_version": PARSER_VERSION, "records": sorted(records, key=lambda r: r["cve_id"])}
