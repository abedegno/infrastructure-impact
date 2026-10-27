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


def select_reviewed_html(raw, url, fetch, vendor, primary, reason):
    """Choose a reviewed HTML scope, keeping its identity-matching CSAF separate.

    The caller decides the source policy. Counts never decide which view wins.
    This function returns metadata; collection writers own persistence.
    """
    from urllib.parse import urljoin

    from ..adapters.common import HTML
    from ..collection.errors import failure_code
    from ..domain import validate_advisory
    from ..source_policy import allowed
    from .contracts import SourceSelection, SourceView, SourceViewIssue
    from .registry import default_registry

    registry = default_registry()
    primary = registry.finalize(primary, url, vendor)
    validate_advisory(primary)
    links = list(
        dict.fromkeys(
            urljoin(url, node.attrs.get("href", ""))
            for node in HTML(raw).root.find({"a"})
            if "csaf" in node.attrs.get("href", "").lower()
            and node.attrs.get("href", "").lower().endswith(".json")
        )
    )
    if len(links) != 1:
        raise ValueError("Reviewed HTML requires one advertised CSAF representation")
    target = links[0]
    if not allowed(target, vendor):
        raise ValueError("Advertised representation outside reviewed vendor routes")
    alternatives, unavailable = (), ()
    try:
        other_raw = fetch(target)
        other = registry.finalize(structured(other_raw, target, vendor), target, vendor)
        validate_advisory(other)
        if other["advisory_id"] != primary["advisory_id"] or other["cves"] != primary["cves"]:
            raise ValueError("Advertised CSAF identity or CVE scope changed")
        alternatives = (
            SourceView(
                target,
                other_raw,
                other["source_format"],
                len(other["assessments"]),
                other["adapter_version"],
            ),
        )
    except Exception as error:
        unavailable = (SourceViewIssue(target, failure_code(error)),)
    return SourceSelection(
        SourceView(
            url,
            raw,
            primary["source_format"],
            len(primary["assessments"]),
            primary["adapter_version"],
        ),
        alternatives,
        reason,
        unavailable,
    )


def resolve_reviewed_advisory(
    raw, url, fetch, *, vendor, advisory_id, cve_ids, primary_url, html_route, parse_primary, reason
):
    """Apply a reviewed policy from either its HTML route or structured identity.

    Direct CSAF collection must not later replace the selected HTML with a
    narrower counterpart. Unknown advisory identities keep normal resolution.
    """
    if is_json(raw):
        data = json.loads(raw)
        document = data.get("document")
        tracking = document.get("tracking") if isinstance(document, dict) else None
        if not isinstance(tracking, dict) or tracking.get("id") != advisory_id:
            return None
        if data.get("vulnerabilities") and structured(raw, url, vendor)["cves"] != cve_ids:
            raise ValueError("Reviewed structured advisory has contradictory CVE scope")
        if url == primary_url:
            raise ValueError("Canonical reviewed HTML route unexpectedly returned structured data")
        selected_url, selected_raw = primary_url, fetch(primary_url)

        def alternate_fetch(target):
            return raw if target == url else fetch(target)
    elif html_route(url):
        selected_url, selected_raw, alternate_fetch = url, raw, fetch
    else:
        return None
    primary = parse_primary(selected_raw, selected_url, vendor)
    if (
        primary is None
        or primary.get("advisory_id") != advisory_id
        or primary.get("cves") != cve_ids
    ):
        raise ValueError("Reviewed primary advisory identity or CVE scope changed")
    return select_reviewed_html(
        selected_raw, selected_url, alternate_fetch, vendor, primary, reason
    )
