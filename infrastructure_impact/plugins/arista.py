"""Arista reviewed historical and current HTML layouts."""

from ..adapters.arista import arista_aggregate_notice, arista_software
from ..adapters.arista_boundaries import (
    continuation,
    radius,
    restricted_cloud_notice,
    xz_unaffected,
)
from ..adapters.arista_chronology import apply_claim_chronology
from ..adapters.arista_current_scope import (
    NOTICE_FORMAT,
    NOTICE_SLUG,
    PREFIX,
    ROUTES,
    advance_notice,
)
from ..adapters.arista_current_scope import parse as current_scope
from ..adapters.arista_hardware_notice import SLUG as HARDWARE_SLUG
from ..adapters.arista_hardware_notice import parse as hardware_notice
from ..adapters.arista_history import arista_release_history
from ..adapters.arista_legacy_scope import ROUTES as OLDER_ROUTES
from ..adapters.arista_legacy_scope import older_scope
from ..adapters.arista_management_scope import ROUTES as MANAGEMENT_ROUTES
from ..adapters.arista_management_scope import management_scope
from ..adapters.arista_openssh import openssh_scope
from ..adapters.arista_reconciliation import CSAF103
from ..adapters.arista_reconciliation import ROUTES as RECONCILIATION_ROUTES
from ..adapters.arista_reconciliation import parse as reconciliation
from ..adapters.arista_routing_scope import ROUTES as ROUTING_ROUTES
from ..adapters.arista_routing_scope import routing_scope
from ..adapters.arista_sa0137 import CSAF as CSAF137
from ..adapters.arista_sa0137 import URL as URL137
from ..adapters.arista_sa0137 import parse as sa0137
from ..adapters.arista_scoped import (
    airsnitch_notice,
    grouped_software,
    non_cve_security_notice,
    reviewed_software,
)
from ..adapters.common import HTML
from ..adapters.legacy_html import html_advisory
from ..adapters.switching import extract
from .archive_listings import arista as archive_listing
from .arista_current_evidence import decide
from .arista_selection import resolve
from .contracts import VendorPlugin
from .shared import is_json, structured


def parse(raw, url, vendor):
    if url in {CSAF103, CSAF137}:
        raise ValueError("Reviewed Arista CSAF requires HTML source selection")
    if url == URL137:
        return sa0137(raw, url, vendor)
    if url in RECONCILIATION_ROUTES:
        return reconciliation(raw, url, vendor)
    if is_json(raw):
        return structured(raw, url, vendor)
    if url == PREFIX + HARDWARE_SLUG:
        return hardware_notice(raw, url, vendor)
    if any(url == PREFIX + slug for slug, _ in ROUTES.values()):
        return current_scope(raw, url, vendor)
    if url == PREFIX + NOTICE_SLUG:
        return advance_notice(raw, url, vendor)
    if any(url.rstrip("/").endswith("/" + value[0]) for value in OLDER_ROUTES.values()):
        return older_scope(raw, url, vendor)
    if any(url.rstrip("/").endswith("/" + value[0]) for value in ROUTING_ROUTES.values()):
        return routing_scope(raw, url, vendor)
    if any(url.rstrip("/").endswith("/" + value[0]) for value in MANAGEMENT_ROUTES.values()):
        return management_scope(raw, url, vendor)
    for slug, parser in {
        "/19904-security-advisory-0100": openssh_scope,
        "/19905-security-advisory-0101": radius,
        "/19222-security-advisory-0095": xz_unaffected,
        "/19221-security-advisory-0094": continuation,
        "/19025-security-advisory-0092": restricted_cloud_notice,
    }.items():
        if url.rstrip("/").endswith(slug):
            return parser(raw, url, vendor)
    if url.rstrip("/").endswith("/24500-security-advisory-0146"):
        return non_cve_security_notice(raw, url, vendor)
    if url.rstrip("/").endswith("/24515-security-advisory-0147"):
        return grouped_software(raw, url, vendor)
    if url.rstrip("/").endswith(("/24776-security-advisory-0184", "/24535-security-advisory-0148")):
        return arista_aggregate_notice(raw, url, vendor)
    if url.rstrip("/").endswith(
        (
            "/20454-security-advisory-0105",
            "/21316-security-advisory-0116",
            "/22535-security-advisory-0123",
            "/22538-security-advisory-0124",
            "/23117-security-advisory-0129",
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


def research_evidence(raw, url, vendor, document):
    if url in {CSAF103, CSAF137}:
        return dict(
            schema_version=1, claims=[], bundles=[], issues=["reviewed_html_selection_required"]
        )
    return apply_claim_chronology(extract(raw, url, vendor, document), document, raw)


def plugin():
    return VendorPlugin(
        "arista",
        "Arista",
        ("arista.com",),
        parse,
        parse_archive=archive_listing,
        resolve=resolve,
        capabilities=(
            "csaf",
            "html",
            "browser-release-history",
            "reviewed-unlinked-security-notice",
        ),
        non_cve_notice=lambda d: (
            not d["cves"]
            and not d["assessments"]
            and d.get("source_format") == NOTICE_FORMAT
            and d.get("advisory_id") == NOTICE_SLUG
            and d.get("source_url") == PREFIX + NOTICE_SLUG
        ),
        retain_unlinked_notice=lambda document: (
            document.get("source_format") == "Arista security notice without CVE"
            and document.get("advisory_id")
            in {
                "24500-security-advisory-0146",
                "24108-security-advisory-0141",
                "19025-security-advisory-0092",
            }
            and document.get("source_url")
            == "https://www.arista.com/en/support/advisories-notices/security-advisory/"
            + document["advisory_id"]
        ),
        parse_release_history=arista_release_history,
        research_evidence=research_evidence,
        current_evidence_policy=decide,
        normalizer_dependencies=(
            apply_claim_chronology,
            sa0137,
            reconciliation,
            hardware_notice,
            current_scope,
            advance_notice,
            arista_aggregate_notice,
            arista_software,
            openssh_scope,
            radius,
            older_scope,
            routing_scope,
            management_scope,
            grouped_software,
            html_advisory,
            structured,
        ),
    )
