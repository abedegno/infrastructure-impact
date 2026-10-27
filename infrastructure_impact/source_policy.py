"""Pure official-source route policy shared by retrieval and evidence validation."""

from urllib.parse import urlsplit

from .plugins.registry import default_registry


def allowed(url, vendor):
    from .references.registry import allowed as reference_allowed

    if vendor == "upstream" and reference_allowed(url):
        return True
    if vendor != "upstream" and vendor not in default_registry().names():
        return False
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    return (
        u.scheme == "https"
        and not u.username
        and not u.password
        and u.port in (None, 443)
        and any(
            host == d or host.endswith("." + d)
            for d in (
                ("mitre.org", "cve.org")
                if vendor == "upstream"
                else default_registry().get(vendor).domains
            )
        )
        and (vendor == "upstream" or default_registry().get(vendor).url_filter(url))
    )
