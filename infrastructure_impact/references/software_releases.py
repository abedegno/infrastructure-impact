"""Reviewed public release evidence, separate from product affectedness and fixes."""

import hashlib
import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from ..adapters.common import HTML
from ..settings import PACKAGE

MAX_BYTES = 2_000_000
ARUBA_BASE = (
    "https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/6300-6400%20Release%20Notes/"
)
ARUBA_10_14_URL = ARUBA_BASE + "aos-cx-10-14-xx/version-history-4.html"
ARUBA_10_16_URL = ARUBA_BASE + "aos-cx-10-16-xx/version-history.html"
ARUBA_SUPPORT_URL = ARUBA_BASE + "aos-cx-10-14-xx/products-supported-3.html"
CISCO_URL = (
    "https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-dublin-17-12-1/model.html"
)
ARISTA_URL = "https://www.arista.com/en/support/advisories-notices/security-advisory/24535-security-advisory-0148"
URLS = (ARUBA_10_14_URL, ARUBA_10_16_URL, ARUBA_SUPPORT_URL, CISCO_URL, ARISTA_URL)
ARUBA_PLATFORMS = ["6300 Switch Series", "6300L Switch Series", "6400 Switch Series"]


def reviewed_html(raw):
    if not isinstance(raw, (bytes, str)):
        raise ValueError("Release evidence must be HTML bytes or text")
    if len(raw if isinstance(raw, bytes) else raw.encode()) > MAX_BYTES:
        raise ValueError("Release evidence exceeds 2000000-byte limit")
    return HTML(raw).root


def safe_node(node):
    """Reject active or concealed content in the selected evidence, not page chrome."""
    descendants = [node]
    nodes = []
    while descendants:
        child = descendants.pop()
        nodes.append(child)
        descendants.extend(c for c in child.children if not isinstance(c, str))
    ancestor = node.parent
    while ancestor is not None:
        nodes.append(ancestor)
        ancestor = ancestor.parent
    for child in nodes:
        if child.tag in {
            "script",
            "style",
            "iframe",
            "object",
            "embed",
            "img",
            "input",
            "template",
            "svg",
            "math",
        } or any(k.lower().startswith("on") and v for k, v in child.attrs.items()):
            raise ValueError("Active HTML in reviewed release evidence")
        if child.tag == "a" and urlsplit(child.attrs.get("href") or "").scheme not in ("", "https"):
            raise ValueError("Active or insecure link in reviewed release evidence")
        style = re.sub(r"\s+", "", (child.attrs.get("style") or "").lower())
        if (
            "hidden" in child.attrs
            or child.attrs.get("aria-hidden") == "true"
            or "display:none" in style
            or "visibility:hidden" in style
        ):
            raise ValueError("Concealed HTML in reviewed release evidence")
    return node.text()


def heading(tree, tag, expected):
    nodes = list(tree.find({tag}))
    if len(nodes) != 1 or safe_node(nodes[0]) != expected:
        raise ValueError("Reviewed release evidence title or heading missing")


def reviewed_table(tree, columns):
    tables = [t for t in tree.find({"table"}) if [h.text() for h in t.find({"th"})] == columns]
    if len(tables) != 1:
        raise ValueError("Expected exactly one reviewed release evidence table")
    table = tables[0]
    safe_node(table)
    if list(table.find({"table"})):
        raise ValueError("Nested release evidence table")
    rows = []
    for row in table.find({"tr"}):
        cells = list(row.find({"td"}))
        if not cells:
            continue
        if (
            len(cells) != len(columns)
            or list(row.find({"th"}))
            or any(
                c.attrs.get("rowspan", "1") != "1" or c.attrs.get("colspan", "1") != "1"
                for c in cells
            )
        ):
            raise ValueError("Release evidence table row structure changed")
        rows.append(cells)
    if not 1 <= len(rows) <= 1000:
        raise ValueError("Release evidence table has no usable rows or exceeds row bound")
    return rows


def explicit_date(text, fmt):
    try:
        value = datetime.strptime(text, fmt).date().isoformat()
    except ValueError as error:
        raise ValueError("Unreviewed explicit publisher date format") from error
    return value


@lru_cache(maxsize=3)
def fingerprint(adapter):
    paths = [
        Path(__file__),
        PACKAGE / "adapters" / adapter,
        PACKAGE / "adapters/common.py",
        PACKAGE / "schemas/software-release-evidence-v1.json",
    ]
    return hashlib.sha256(b"".join(p.read_bytes() for p in paths)).hexdigest()


def document(vendor, family, product, platforms, url, adapter, **rows):
    value = dict(
        schema_version=1,
        vendor=vendor,
        family=family,
        product=product,
        platforms=platforms,
        source_url=url,
        parser_fingerprint=fingerprint(adapter),
        releases=[],
        bundles=[],
        platform_support=[],
        issues=[],
    )
    value.update(rows)
    return validate_document(value)


@lru_cache(maxsize=1)
def validator():
    schema = json.loads((PACKAGE / "schemas/software-release-evidence-v1.json").read_text())
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_document(value, *, source_id=None):
    try:
        validator().validate(value)
    except ValidationError as error:
        raise ValueError("Invalid software release evidence document: " + error.message) from error
    if value["source_url"] not in URLS:
        raise ValueError("Unreviewed software release evidence route")
    bindings = {
        ARUBA_10_14_URL: (
            "aruba-aos-cx-6300-6400-10-14-history",
            "aruba",
            "aruba-aoscx",
            "AOS-CX",
            ARUBA_PLATFORMS,
            "releases",
            "10.14",
        ),
        ARUBA_10_16_URL: (
            "aruba-aos-cx-6300-6400-10-16-history",
            "aruba",
            "aruba-aoscx",
            "AOS-CX",
            ARUBA_PLATFORMS,
            "releases",
            "10.16",
        ),
        ARUBA_SUPPORT_URL: (
            "aruba-aos-cx-6300-6400-10-14-models",
            "aruba",
            "aruba-aoscx",
            "AOS-CX",
            ARUBA_PLATFORMS,
            "platform_support",
            None,
        ),
        CISCO_URL: (
            "cisco-iosxe-17-12-1-release",
            "cisco",
            "cisco-iosxe",
            "Cisco IOS XE Dublin 17.12.1",
            [],
            "releases",
            "17.12",
        ),
        ARISTA_URL: (
            "arista-eos-advisory-bundle-0148",
            "arista",
            "arista-eos",
            "EOS",
            [],
            "bundles",
            None,
        ),
    }
    identity, vendor, family, product, platforms, kind, branch = bindings[value["source_url"]]
    if source_id is not None and source_id != identity:
        raise ValueError("Software release evidence is bound to a different source")
    if (value["vendor"], value["family"], value["product"], value["platforms"]) != (
        vendor,
        family,
        product,
        platforms,
    ):
        raise ValueError("Software release evidence product or family scope changed")
    if not value[kind] or any(
        value[k] for k in ("releases", "bundles", "platform_support") if k != kind
    ):
        raise ValueError("Missing or conflicting software release evidence rows")
    seen = set()
    for row in value[kind]:
        key = row[
            {"releases": "version", "bundles": "publisher_id", "platform_support": "sku"}[kind]
        ]
        if key in seen:
            raise ValueError("Duplicate or conflicting software release evidence identity")
        seen.add(key)
        if kind == "releases":
            version_pattern = re.escape(branch) + (r"\.\d{4}" if vendor == "aruba" else r"\.1")
            basis = "publisher_release_history" if vendor == "aruba" else "publisher_release_date"
            if (
                row["branch"] != branch
                or not re.fullmatch(version_pattern, row["version"])
                or row["date_basis"] != basis
            ):
                raise ValueError("Release version, branch or date basis changed")
        if kind == "bundles" and (
            row["publisher_id"] != "0148"
            or len(row["member_advisory_ids"]) != 30
            or set(row["member_advisory_ids"]) != {str(identity) for identity in range(149, 179)}
        ):
            raise ValueError("Unreviewed advisory bundle identity or EOS membership")
    return value


def parse_aruba_10_14(raw):
    from ..adapters.aruba_history import consolidated_history

    return consolidated_history(raw, ARUBA_10_14_URL, "10.14")


def parse_aruba_10_16(raw):
    from ..adapters.aruba_history import consolidated_history

    return consolidated_history(raw, ARUBA_10_16_URL, "10.16")


def parse_aruba_support_10_14(raw):
    from ..adapters.aruba_history import consolidated_support

    return consolidated_support(raw, ARUBA_SUPPORT_URL)


def parse_cisco_17_12_1(raw):
    from ..adapters.cisco_history import model_release

    return model_release(raw, CISCO_URL)


def parse_arista_0148(raw):
    from ..adapters.arista_history import advisory_bundle

    return advisory_bundle(raw, ARISTA_URL)


def inputs(db, config):
    """All reviewed sources; retained.document is independent of latest_attempt."""
    from .registry import SOURCES
    from .storage import enrichment_input

    result = []
    for spec in SOURCES.values():
        if spec.purpose != "release_history":
            continue
        value = enrichment_input(db, config, spec.id)
        retained = value["retained"]
        if retained:
            doc = validate_document(retained.pop("catalogue"), source_id=spec.id)
            retained.update(
                document=doc,
                parser_fingerprint=doc["parser_fingerprint"],
                normalized_sha256=hashlib.sha256(
                    json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
            )
        attempt = value["latest_attempt"]
        if attempt:
            # No freeform errors, body fragments, response headers or unknown codes.
            outcomes = {"ok", "error", "partial", "not_applicable"}
            codes = {
                "access_denied",
                "edge_access_denied",
                "rate_limited",
                "http_error",
                "network_error",
                "source_missing",
                "redirect_target_missing",
                "access_verification_required",
                "unsupported_or_invalid_document",
                "collection_error",
            }
            attempt["outcome"] = attempt["outcome"] if attempt["outcome"] in outcomes else "error"
            attempt["error_code"] = (
                attempt["error_code"] if attempt["error_code"] in codes else None
            )
        result.append(dict(source_id=spec.id, source_url=spec.url, purpose=spec.purpose, **value))
    return result
