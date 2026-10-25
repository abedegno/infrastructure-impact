"""Compatibility exports; new integrations use the vendor registry."""

from .checkpoint import checkpoint_records
from .common import ADAPTER_VERSION, HTML, Node, availability, base, cves, iso_date, pdf_text
from .standards import cna, csaf


def auto(raw, url, vendor):
    from ..plugins.registry import default_registry

    return default_registry().normalize(raw, url, vendor)


__all__ = [
    "ADAPTER_VERSION",
    "HTML",
    "Node",
    "availability",
    "base",
    "cves",
    "iso_date",
    "pdf_text",
    "csaf",
    "cna",
    "checkpoint_records",
    "auto",
]
