"""Curated public F5 article PDFs, with explicit scope-change rejection."""

from ..adapters.f5_pdf import ARTICLE_PREFIX, PDF_PREFIX, PROFILES, advisory
from .contracts import VendorPlugin


def route(url):
    return any(url in (PDF_PREFIX + identity, ARTICLE_PREFIX + identity) for identity in PROFILES)


def plugin():
    return VendorPlugin(
        "f5",
        "F5",
        ("my.f5.com",),
        advisory,
        capabilities=("reviewed-advisory-pdf",),
        url_filter=route,
        normalizer_dependencies=(advisory,),
    )
