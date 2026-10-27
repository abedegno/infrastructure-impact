"""Fortinet CSAF and scoped product release notes."""

import json
import re
from urllib.parse import urlsplit

from ..adapters.fortinet import (
    affected_products_advisory,
    document_history,
    fortinet_release,
    investigation_advisory,
)
from ..adapters.fortinet_openssh import CVE, ID, openssh_advisory, reviewed_route
from ..adapters.fortinet_ranges import ROUTES as RANGE_ROUTES
from ..adapters.fortinet_ranges import range_advisory
from ..collection.errors import PublisherScopeUnavailable
from .archive_listings import fortinet as archive_listing
from .contracts import VendorPlugin
from .shared import is_json, resolve_reviewed_advisory, structured


def canonicalize(url):
    parsed = urlsplit(url)
    if (
        parsed.hostname in {"www.fortiguard.com", "fortiguard.fortinet.com"}
        and parsed.path.rstrip("/") == "/psirt/" + ID
        and not parsed.query
    ):
        return "https://www.fortiguard.com/psirt/" + ID
    return url


def parse(raw, url, vendor):
    if "docs.fortinet.com/" in url:
        return fortinet_release(raw, url, vendor)
    if not is_json(raw) and urlsplit(url).path.rsplit("/", 1)[-1] in RANGE_ROUTES:
        return range_advisory(raw, url, vendor)
    if not is_json(raw) and reviewed_route(url):
        return openssh_advisory(raw, url, vendor)
    if not is_json(raw) and url.rstrip("/").endswith("/psirt/FG-IR-23-494"):
        return affected_products_advisory(raw, url, vendor)
    if not is_json(raw):
        return investigation_advisory(raw, url, vendor)
    record = structured(raw, url, vendor)
    if not record["cves"] and not record["assessments"]:
        raise PublisherScopeUnavailable(
            "Retrieved publisher document has no explicit CVE/product scope; no impact inferred"
        )
    return record


def resolve(raw, url, fetch):
    selected = resolve_reviewed_advisory(
        raw,
        url,
        fetch,
        vendor="fortinet",
        advisory_id=ID,
        cve_ids=[CVE],
        primary_url="https://www.fortiguard.com/psirt/" + ID,
        html_route=reviewed_route,
        parse_primary=openssh_advisory,
        reason="Reviewed single-CVE HTML preserves the version table and explicit unaffected/investigation lists. Its structured counterpart remains separate; statement counts do not decide which view is selected or establish equivalent scope.",
    )
    if selected is not None:
        return selected
    if is_json(raw):
        document = json.loads(raw)
        identity = document.get("document", {}).get("tracking", {}).get("id", "")
        if not document.get("vulnerabilities") and re.fullmatch(r"FG-IR-\d{2}-\d+", identity):
            target = "https://www.fortiguard.com/psirt/" + identity
            html = fetch(target)
            # Only a fully reviewed, identity-matching layout can replace the empty envelope.
            try:
                parser = range_advisory if identity in RANGE_ROUTES else investigation_advisory
                parser(html, target, "fortinet")
            except ValueError:
                # Preserve a valid title-scoped structured record with unknown
                # applicability when the optional HTML layout is unsupported.
                # Truly empty envelopes still fail normal schema validation.
                return url, raw
            return target, html
    return url, raw


def plugin():
    return VendorPlugin(
        "fortinet",
        "Fortinet",
        ("fortinet.com", "fortiguard.com"),
        parse,
        canonicalize=canonicalize,
        resolve=resolve,
        parse_document_history=document_history,
        parse_archive=archive_listing,
        normalizer_dependencies=(
            affected_products_advisory,
            fortinet_release,
            investigation_advisory,
            openssh_advisory,
            range_advisory,
            structured,
        ),
        capabilities=("csaf", "release-notes-html", "investigation-html"),
    )
