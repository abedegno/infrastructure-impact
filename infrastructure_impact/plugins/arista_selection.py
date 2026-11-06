"""Reviewed SA-0103 representation pairing, preserving each publisher identity."""

from urllib.parse import urljoin

from ..adapters.arista_reconciliation import CSAF103, CSAF103_ID, URL103, parse
from ..adapters.common import HTML
from ..collection.errors import failure_code
from ..domain import validate_advisory
from .contracts import SourceSelection, SourceView, SourceViewIssue
from .shared import is_json, structured


def resolve(raw, url, fetch):
    if url not in {URL103, CSAF103}:
        return url, raw
    from .registry import default_registry

    registry = default_registry()
    primary_raw = raw if url == URL103 else fetch(URL103)
    if is_json(primary_raw):
        raise ValueError("Reviewed Arista HTML route returned structured data")
    primary = registry.finalize(parse(primary_raw, URL103, "arista"), URL103, "arista")
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
            urljoin(URL103, n.attrs.get("href", ""))
            for n in heading.find({"a"})
            if "csaf" in n.attrs.get("href", "").lower()
            and n.attrs.get("href", "").lower().endswith(".json")
        )
    )
    if links != [CSAF103]:
        raise ValueError("Reviewed Arista advertised representation pairing changed")
    alternatives, unavailable = (), ()
    try:
        other_raw = raw if url == CSAF103 else fetch(CSAF103)
        other = registry.finalize(structured(other_raw, CSAF103, "arista"), CSAF103, "arista")
        validate_advisory(other)
        if other["advisory_id"] != CSAF103_ID or other["cves"] != primary["cves"]:
            raise ValueError("Reviewed Arista alternate identity or CVE scope changed")
        alternatives = (
            SourceView(
                CSAF103,
                other_raw,
                other["source_format"],
                len(other["assessments"]),
                other["adapter_version"],
            ),
        )
    except Exception as error:
        unavailable = (SourceViewIssue(CSAF103, failure_code(error)),)
    return SourceSelection(
        SourceView(
            URL103,
            primary_raw,
            primary["source_format"],
            len(primary["assessments"]),
            primary["adapter_version"],
        ),
        alternatives,
        "Reviewed SA-0103 HTML tracking and local EOS scope are primary. The explicitly paired CSAF retains its literal identity and is unavailable for scope comparison if its CVEs or identity disagree; no CVE alias or remediation transfer is inferred.",
        unavailable,
    )
