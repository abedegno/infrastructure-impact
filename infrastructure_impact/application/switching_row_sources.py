"""Private publisher composition for exact published-row Source membership.

This is derived immediately after fresh comparison validation, never accepted as
caller-owned proof. Native certification derives it again from its own facts.
"""

import copy
import json
from hashlib import sha256

from . import switching_evidence as contracts
from .switching_comparison import VENDORS, _selected_sources

ROOT = "switching-row-sources.json"
SCHEMA = "switching-row-sources-v1.json"
MAX_BYTES = 8_000_000


def membership_digest(row, *, budget=None):
    ids = set()

    def retain(identity):
        if type(identity) is not str or not identity.isascii():
            raise ValueError("published row membership must use ASCII claim IDs")
        if identity not in ids:
            if budget is not None:
                from ..publication_codec import charge_value

                charge_value(identity, budget)
                budget.charge(32, 32)
            ids.add(identity)

    for identity in row["claim_ids"]:
        retain(identity)
    for event in row["events"]:
        for identity in event["claim_ids"]:
            retain(identity)
    return sha256(json.dumps(sorted(ids), separators=(",", ":")).encode()).hexdigest()


def published_family(report):
    selection = report["selection"]
    if (
        selection["requested_vendor"] is not None
        or selection["effective_vendors"] != list(VENDORS)
        or selection["scope_level"] != "os_family"
        or selection["requested_window"] != "all"
        or selection["requested_cve_ids"] is not None
        or selection["definition_sha256"] != contracts.definition_sha256(report["definition"])
        or [r["vendor"] for r in report["rows"]] != list(VENDORS)
        or any(
            r["scope_level"] != "os_family"
            or r["window"] != "all"
            or r["row_id"] != f"{r['vendor']}:os_family:all"
            for r in report["rows"]
        )
        or selection["effective_windows"] != [r["row_id"] for r in report["rows"]]
    ):
        raise ValueError("noncanonical published row family")


def derive(report):
    if report["inputs"] is None:
        return None
    published_family(report)
    sources = report["sources"]
    if sources != sorted(sources, key=contracts._json):
        raise ValueError("noncanonical global Sources order")
    ordinals = {}
    for index, source in enumerate(sources):
        if set(source) != set(contracts._SOURCE_FIELDS) or any(
            type(source[k]) is not str for k in contracts._SOURCE_FIELDS
        ):
            raise ValueError("Expected a closed four-string Source")
        key = tuple(source[k] for k in contracts._SOURCE_FIELDS)
        if key in ordinals:
            raise ValueError("duplicate global Source")
        ordinals[key] = index
    rows, union = [], set()
    for index, row in enumerate(report["rows"]):
        selected = _selected_sources(report["inputs"]["evidence"], [row])
        try:
            members = sorted(
                ordinals[tuple(s[k] for k in contracts._SOURCE_FIELDS)] for s in selected
            )
        except KeyError as exc:
            raise ValueError("published row Source missing globally") from exc
        union.update(members)
        rows.append(
            dict(
                row_id=row["row_id"],
                row_ordinal=index,
                claim_membership_sha256=membership_digest(row),
                source_ordinals=members,
            )
        )
    if union != set(range(len(sources))):
        raise ValueError("published row Source union differs from global Sources")
    return dict(sources_count=len(sources), rows=rows)


def finalize(report, membership, ranges):
    if membership is None:
        return None
    return dict(
        schema_version=1,
        representation="switching-row-sources",
        publication=report["publication"],
        generated_at=report["generated_at"],
        definition_sha256=report["selection"]["definition_sha256"],
        observation_end=report["observation_end"],
        scope_level="os_family",
        window="all",
        requested_cve_ids=None,
        sources_range=ranges[("switching_comparison", "sources")],
        sources_count=membership["sources_count"],
        rows=[
            dict(
                **row,
                published_row_sha256=ranges[("switching_comparison", "rows", row["row_ordinal"])][
                    "logical_sha256"
                ],
            )
            for row in membership["rows"]
        ],
    )


def vendor_summary(complete, vendor, sources):
    """Rebuild selection metadata from independently owned complete rows."""
    result = copy.deepcopy({k: v for k, v in complete.items() if k not in ("rows", "sources")})
    result["rows"] = copy.deepcopy(
        [r for r in complete["rows"] if vendor is None or r["vendor"] == vendor]
    )
    result["sources"] = sources
    result["selection"].update(
        requested_vendor=vendor,
        effective_vendors=[vendor] if vendor else list(VENDORS),
        effective_windows=[r["row_id"] for r in result["rows"]],
        effective_cve_ids=sorted({cid for r in result["rows"] for cid in r["cve_ids"]}),
    )
    return result
