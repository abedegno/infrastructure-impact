"""Discover attributed family leads without producing product-impact assessments.

Rules are a closed, reviewed resource. Matching uses literal product-local names,
never provider identity, global CPE context, version arithmetic or model inference.
Container text can supply weaker discovery leads. Reference-only discovery is
disabled until jointly reviewed advisory-route and bounded-family-context rules exist.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date, datetime
from importlib.resources import files

from .snapshot import MAX_RECORD_BYTES, Entry, Snapshot

_ID = re.compile(r"CVE-([0-9]{4})-([0-9]{4,})\Z")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?\Z"
)
_CLASSES = ("explicit_family_row", "ambiguous_family_lead", "reference_only_lead")
_RULE_KEYS = frozenset(
    {
        "format_version",
        "selector_version",
        "supported_data_versions",
        "method_note",
        "unknown_vendor_labels",
        "cpe_rules",
        "reference_rules",
        "families",
    }
)
_FAMILY_KEYS = frozenset(
    {
        "id",
        "vendor_id",
        "trusted_cna_org_ids",
        "product_vendors",
        "product_aliases",
        "text_phrases",
        "provenance",
    }
)


def _validate_rules(rules):
    """Reject stale/domain-only policy and unreviewed reference/CPE activation."""
    if (
        not isinstance(rules, dict)
        or rules.keys() != _RULE_KEYS
        or type(rules["format_version"]) is not int
        or rules["format_version"] != 1
        or rules["selector_version"] != "2026-11-06.2"
        or rules["reference_rules"] != []
        or rules["cpe_rules"] != []
        or not isinstance(rules["families"], list)
        or any(
            not isinstance(family, dict) or family.keys() != _FAMILY_KEYS
            for family in rules["families"]
        )
    ):
        raise ValueError("invalid_selector_rules")


def load_selectors() -> dict:
    """Load a fresh copy of the packaged versioned selector rules, with no I/O to sources."""
    rules = json.loads(
        files("infrastructure_impact")
        .joinpath("resources/cve-reconciliation-selectors.json")
        .read_text(encoding="utf-8")
    )
    _validate_rules(rules)
    return rules


def selector_hash(rules: dict) -> str:
    """SHA-256 of UTF-8 JSON with sorted keys, compact separators, and no ASCII escaping."""
    raw = json.dumps(
        rules, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _constant(value):
    raise ValueError


def _canonical_scalars(value):
    """Check retained JSON scalars without serializing amplified/shared evidence."""
    pending, seen = [value], set()
    while pending:
        item = pending.pop()
        if isinstance(item, float) and not math.isfinite(item):
            return False
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return False
        elif isinstance(item, (dict, list)) and id(item) not in seen:
            seen.add(id(item))
            if isinstance(item, dict):
                pending.extend(item.keys())
                pending.extend(item.values())
            else:
                pending.extend(item)
    return True


def _norm(value):
    return " ".join(value.split()).casefold() if isinstance(value, str) else ""


def _valid_path(entry):
    match = _ID.fullmatch(entry.cve_id)
    if not match:
        return False
    year, number = match.groups()
    if len(number) > 4 and number.startswith("0"):
        return False
    bucket = number[:-3].lstrip("0") or "0"
    return entry.path == f"cves/{year}/{bucket}xxx/{entry.cve_id}.json"


def _objects(value):
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def _valid_container(container):
    """Validate consumed structure, not a claim of whole upstream schema conformance."""
    if not isinstance(container, dict):
        return False
    if not isinstance(container.get("providerMetadata", {}), dict):
        return False
    for field in ("affected", "references", "descriptions"):
        if not _objects(container.get(field, [])):
            return False
    if "title" in container and not isinstance(container["title"], str):
        return False
    for product in container.get("affected", []):
        for field in ("vendor", "product", "defaultStatus"):
            if field in product and not isinstance(product[field], str):
                return False
        if not _objects(product.get("versions", [])):
            return False
        for field in ("platforms", "cpes"):
            items = product.get(field, [])
            if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
                return False
    return True


def _date_window(published, start, end):
    if not isinstance(published, str) or not _TIMESTAMP.fullmatch(published):
        return "unknown"
    try:
        parsed = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        return "unknown"
    # Compare the literal publication calendar day; do not replace it with an update
    # date, identifier year, UTC-normalized day, or vendor advisory publication date.
    return "inside" if start <= parsed.date() <= end else "outside"


def _product_match(product, family, rules):
    name, vendor = _norm(product.get("product")), _norm(product.get("vendor"))
    for alias in family["product_aliases"]:
        if name != _norm(alias["value"]):
            continue
        if not alias["require_vendor"] or vendor in map(_norm, family["product_vendors"]):
            return "explicit_family_row", alias["id"]
        if vendor in rules["unknown_vendor_labels"]:
            return "ambiguous_family_lead", alias["id"]
    return None


def _container_findings(container, kind, index, meta, rules):
    base = "/containers/cna" if kind == "cna" else f"/containers/adp/{index}"
    provider = container.get("providerMetadata", {})
    references = [
        dict(locator=f"{base}/references/{i}", row=row)
        for i, row in enumerate(container.get("references", []))
    ]
    findings = []

    def finding(family, classification, matches, product=None, locator=None):
        return dict(
            family=family["id"],
            vendor_id=family["vendor_id"],
            discovery_class=classification,
            container_type=kind,
            container_index=index,
            container_locator=base,
            provider_identity=provider,
            trusted_vendor_cna=(
                kind == "cna"
                and provider.get("orgId") in family["trusted_cna_org_ids"]
                and provider.get("orgId") == meta.get("assignerOrgId")
            ),
            matching_rules=matches,
            product_locator=locator,
            product=product,
            # These parsed evidence objects belong to this invocation. Share them
            # across rows to avoid multiplying large reference/context lists in RAM.
            references=references,
            container_cpe_applicability=container.get("cpeApplicability", []),
        )

    for family in rules["families"]:
        family_rows = []
        for i, product in enumerate(container.get("affected", [])):
            match = _product_match(product, family, rules)
            if match:
                classification, rule = match
                locator = f"{base}/affected/{i}"
                family_rows.append(
                    finding(
                        family,
                        classification,
                        [dict(rule_id=rule, locator=locator + "/product")],
                        product,
                        locator,
                    )
                )
        if family_rows:
            findings.extend(family_rows)
            continue
        # Text discovery never borrows another container's products or
        # references and never fabricates a product row from a mention.
        texts = [(base + "/title", container.get("title", ""))]
        texts.extend(
            (f"{base}/descriptions/{i}/value", row.get("value", ""))
            for i, row in enumerate(container.get("descriptions", []))
        )
        matches = []
        for phrase_index, phrase in enumerate(family["text_phrases"]):
            pattern = re.compile(r"(?<![\w-])" + re.escape(phrase) + r"(?![\w-])", re.I)
            for locator, text in texts:
                if isinstance(text, str) and pattern.search(text):
                    matches.append(
                        dict(rule_id=f"{family['id']}:text:{phrase_index}", locator=locator)
                    )
        if matches:
            findings.append(finding(family, "ambiguous_family_lead", matches))
        # reference_only_lead remains a reserved class, with no active matcher.
        # A vendor hostname or route alone cannot establish bounded family context.
    return findings


def select_record(
    raw: bytes, *, entry: Entry, snapshot: Snapshot, rules: dict, start_date: str, end_date: str
) -> dict:
    """Return source-bound discovery rows; diagnostic codes never interpolate source data.

    Date limits are inclusive ISO calendar days. An invalid caller window raises a
    stable ValueError; malformed source records instead return an unprocessed result.
    Literal fields/references are retained as evidence, separate from safe diagnostics.
    """
    _validate_rules(rules)
    try:
        start, end = date.fromisoformat(start_date), date.fromisoformat(end_date)
        if start.isoformat() != start_date or end.isoformat() != end_date or start > end:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("invalid_date_window") from None
    result = dict(
        outcome="invalid",
        discovery_class="unprocessed",
        cve_id=entry.cve_id,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_url=entry.source_url(snapshot.commit),
        source_locator=entry.path,
        record_state=None,
        data_version=None,
        assigner_org_id=None,
        dates=dict(dateReserved=None, datePublished=None, dateUpdated=None),
        date_window_state="unknown",
        findings=[],
        diagnostic_codes=[],
    )
    clean_result = result.copy()

    def finish():
        # Only the returned projection must be canonical UTF-8 JSON. Ignored
        # source fields cannot change previously committable classifications.
        if not _canonical_scalars(result):
            return clean_result | dict(diagnostic_codes=["invalid_json_scalar"])
        return result

    def stop(code, outcome="invalid", classification="unprocessed"):
        result.update(outcome=outcome, discovery_class=classification, diagnostic_codes=[code])
        return finish()

    if not _valid_path(entry):
        return stop("record_path_mismatch")
    if len(raw) > MAX_RECORD_BYTES:
        return stop("record_byte_limit")
    try:
        record = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        return stop("invalid_json")
    if not isinstance(record, dict):
        return stop("invalid_record_structure")
    meta = record.get("cveMetadata")
    version = record.get("dataVersion")
    if (
        record.get("dataType") != "CVE_RECORD"
        or not isinstance(meta, dict)
        or not isinstance(version, str)
    ):
        return stop("invalid_record_structure")
    result.update(
        data_version=version,
        record_state=meta.get("state"),
        assigner_org_id=meta.get("assignerOrgId"),
        dates={field: meta.get(field) for field in result["dates"]},
    )
    result["date_window_state"] = _date_window(meta.get("datePublished"), start, end)
    if meta.get("cveId") != entry.cve_id:
        return stop("record_id_mismatch")
    if version not in rules["supported_data_versions"]:
        return stop("unsupported_data_version", "unsupported_version")
    if meta.get("state") == "REJECTED":
        return stop("record_rejected", "rejected_record", "rejected_record")
    if meta.get("state") != "PUBLISHED":
        return stop("unsupported_record_state")
    containers = record.get("containers")
    if (
        not isinstance(containers, dict)
        or not _valid_container(containers.get("cna"))
        or not _objects(containers.get("adp", []))
        or not all(_valid_container(c) for c in containers.get("adp", []))
    ):
        return stop("invalid_record_structure")
    findings, diagnostics = [], set()
    for kind, index, container in [("cna", 0, containers["cna"])] + [
        ("adp", i, c) for i, c in enumerate(containers.get("adp", []))
    ]:
        provider_id = container.get("providerMetadata", {}).get("orgId")
        if not isinstance(provider_id, str) or not re.fullmatch(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", provider_id
        ):
            diagnostics.add("unknown_provider")
        if (
            kind == "cna"
            and isinstance(provider_id, str)
            and isinstance(meta.get("assignerOrgId"), str)
            and provider_id != meta["assignerOrgId"]
        ):
            diagnostics.add("cna_assigner_mismatch")
        findings.extend(_container_findings(container, kind, index, meta, rules))
    if result["date_window_state"] == "unknown":
        diagnostics.add("unknown_publication_date")
    result.update(
        outcome="parsed",
        findings=findings,
        diagnostic_codes=sorted(diagnostics),
        discovery_class=next(
            (c for c in _CLASSES if any(f["discovery_class"] == c for f in findings)), "non_target"
        ),
    )
    return finish()
