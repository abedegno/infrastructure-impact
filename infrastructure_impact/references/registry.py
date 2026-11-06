"""Explicit reference-source registry. Configuration cannot load Python code."""

from dataclasses import dataclass
from typing import Callable

from .kev import parse as parse_kev
from .nvd import parse_openssh

NVD_OPENSSH_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    "virtualMatchString=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A*"
    "&resultsPerPage=2000&startIndex=0"
)

KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
KEV_ATTRIBUTION_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


@dataclass(frozen=True)
class ReferenceSource:
    id: str
    url: str
    parse: Callable
    purpose: str = "component_study"


SOURCES = {
    "nvd-openssh-products": ReferenceSource("nvd-openssh-products", NVD_OPENSSH_URL, parse_openssh),
    "cisa-kev": ReferenceSource("cisa-kev", KEV_URL, parse_kev, purpose="cve_enrichment"),
}


def source(source_id):
    try:
        return SOURCES[source_id]
    except (KeyError, TypeError):
        raise ValueError("Unknown reviewed reference source") from None


def allowed(url):
    return any(url == item.url for item in SOURCES.values())
