"""Explicit reference-source registry. Configuration cannot load Python code."""

from dataclasses import dataclass
from typing import Callable

from .nvd import parse_openssh

NVD_OPENSSH_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    "virtualMatchString=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A*"
    "&resultsPerPage=2000&startIndex=0"
)


@dataclass(frozen=True)
class ReferenceSource:
    id: str
    url: str
    parse: Callable


SOURCES = {
    "nvd-openssh-products": ReferenceSource("nvd-openssh-products", NVD_OPENSSH_URL, parse_openssh)
}


def source(source_id):
    try:
        return SOURCES[source_id]
    except (KeyError, TypeError):
        raise ValueError("Unknown reviewed reference source") from None


def allowed(url):
    return any(url == item.url for item in SOURCES.values())
