"""Reviewed SA-0103/0137 pairs, preserving each publisher identity."""

from hashlib import sha256
from urllib.parse import urljoin

from ..adapters import arista_sa0137 as sa137
from ..adapters.arista_reconciliation import CSAF103, CSAF103_ID, URL103, parse
from ..adapters.common import HTML
from ..collection.errors import failure_code
from ..domain import validate_advisory
from .contracts import SourceSelection, SourceView, SourceViewIssue
from .shared import is_json, structured


def resolve(raw, url, fetch):
    if url not in {URL103, CSAF103, sa137.URL, sa137.CSAF}:
        return url, raw
    primary_url, alternate_url, alternate_id, parser = (
        (sa137.URL, sa137.CSAF, sa137.CSAF_ID, sa137.parse)
        if url in {sa137.URL, sa137.CSAF}
        else (URL103, CSAF103, CSAF103_ID, parse)
    )
    from .registry import default_registry

    registry = default_registry()
    primary_raw = raw if url == primary_url else fetch(primary_url)
    if is_json(primary_raw):
        raise ValueError("Reviewed Arista HTML route returned structured data")
    primary = registry.finalize(parser(primary_raw, primary_url, "arista"), primary_url, "arista")
    validate_advisory(primary)
    # The primary parser has validated one article and its advisory heading.
    # Navigation/footer links cannot establish the reviewed representation pair.
    article = next(
        n
        for n in HTML(primary_raw).root.find({"div"})
        if "item-page" in n.attrs.get("class", "").split()
    )
    heading = next(n for n in article.find({"h2"}) if n.text().startswith("Security Advisory "))
    links = list(
        dict.fromkeys(
            urljoin(primary_url, n.attrs.get("href", ""))
            for n in heading.find({"a"})
            if "csaf" in n.attrs.get("href", "").lower()
            and n.attrs.get("href", "").lower().endswith(".json")
        )
    )
    if links != [alternate_url]:
        raise ValueError("Reviewed Arista advertised representation pairing changed")
    alternatives, unavailable = (), ()
    try:
        other_raw = raw if url == alternate_url else fetch(alternate_url)
        other = registry.finalize(
            structured(other_raw, alternate_url, "arista"), alternate_url, "arista"
        )
        validate_advisory(other)
        if other["advisory_id"] != alternate_id or other["cves"] != primary["cves"]:
            raise ValueError("Reviewed Arista alternate identity or CVE scope changed")
        if alternate_url == sa137.CSAF and (
            sha256(other_raw).hexdigest() != sa137.REVIEWED_SHA256
            or not sa137.draft_shape(other_raw)
        ):
            raise ValueError("SA-0137 alternate requires renewed source review")
        alternatives = (
            SourceView(
                alternate_url,
                other_raw,
                other["source_format"],
                len(other["assessments"]),
                other["adapter_version"],
            ),
        )
    except Exception as error:
        unavailable = (SourceViewIssue(alternate_url, failure_code(error)),)
    return SourceSelection(
        SourceView(
            primary_url,
            primary_raw,
            primary["source_format"],
            len(primary["assessments"]),
            primary["adapter_version"],
        ),
        alternatives,
        (
            "Reviewed SA-0137 HTML owns conditional EOS and platform scope; the exact draft CSAF placeholder is retained for audit only. Changed or unavailable alternates remain visible for renewed review."
            if primary_url == sa137.URL
            else "Reviewed SA-0103 HTML tracking and local EOS scope are primary. The explicitly paired CSAF retains its literal identity and is unavailable for scope comparison if its CVEs or identity disagree; no CVE alias or remediation transfer is inferred."
        ),
        unavailable,
    )
