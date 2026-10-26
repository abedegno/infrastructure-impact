"""Arista reviewed historical and current HTML layouts."""

from ..adapters.arista import arista_aggregate_notice, arista_software
from ..adapters.arista_history import arista_release_history
from ..adapters.arista_scoped import (
    airsnitch_notice,
    grouped_software,
    non_cve_security_notice,
    reviewed_software,
)
from ..adapters.common import HTML
from ..adapters.legacy_html import html_advisory
from .archive_listings import arista as archive_listing
from .contracts import VendorPlugin
from .shared import is_json, structured


def parse(raw, url, vendor):
    if is_json(raw):
        return structured(raw, url, vendor)
    if url.rstrip("/").endswith("/24500-security-advisory-0146"):
        return non_cve_security_notice(raw, url, vendor)
    if url.rstrip("/").endswith("/24515-security-advisory-0147"):
        return grouped_software(raw, url, vendor)
    if url.rstrip("/").endswith(("/24776-security-advisory-0184", "/24535-security-advisory-0148")):
        return arista_aggregate_notice(raw, url, vendor)
    if url.rstrip("/").endswith(
        (
            "/23118-security-advisory-0130",
            "/23119-security-advisory-0131",
            "/23399-security-advisory-0133",
            "/23784-security-advisory-0135",
            "/24004-security-advisory-0136",
            "/24019-security-advisory-0138",
            "/24029-security-advisory-0139",
            "/24074-security-advisory-0140",
        )
    ):
        return reviewed_software(raw, url, vendor)
    if url.rstrip("/").endswith("/24108-security-advisory-0141"):
        return airsnitch_notice(raw, url, vendor)
    if "Affected Software" in HTML(raw).root.text():
        return arista_software(raw, url, vendor)
    return html_advisory(raw, url, vendor)


def plugin():
    return VendorPlugin(
        "arista",
        "Arista",
        ("arista.com",),
        parse,
        parse_archive=archive_listing,
        capabilities=(
            "csaf",
            "html",
            "browser-release-history",
            "reviewed-unlinked-security-notice",
        ),
        retain_unlinked_notice=lambda document: (
            document.get("source_format") == "Arista security notice without CVE"
            and document.get("advisory_id")
            in {"24500-security-advisory-0146", "24108-security-advisory-0141"}
            and document.get("source_url")
            == "https://www.arista.com/en/support/advisories-notices/security-advisory/"
            + document["advisory_id"]
        ),
        parse_release_history=arista_release_history,
    )
