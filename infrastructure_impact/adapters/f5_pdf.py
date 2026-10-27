"""Exact reviewed F5 PDF scopes; no generic table or appliance-version inference."""

import re
from datetime import datetime, timezone
from hashlib import sha256

from .common import assessment, base, cves, pdf_text

PDF_PREFIX = "https://my.f5.com/manage/MyF5_KnowledgeArticlePDF?article="
ARTICLE_PREFIX = "https://my.f5.com/manage/s/article/"
START = "Security Advisory Description"
END = "Security Advisory Recommended Actions"

# Rows are reviewed literal table facts, bound to the complete evaluated list, description,
# impact, status tables and table footnotes by scope_sha256. Changed scope fails
# closed, even if a title or old version string still appears elsewhere.
PROFILES = {
    "K000163821": {
        "evaluated_sha256": "7cb03fe23b90bd7a28da49d7608a60e4a180a3a97cd97b7cbe2d52d37a35c7f9",
        "title": "PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619",
        "cves": ("CVE-2026-109618", "CVE-2026-109619"),
        "scope_sha256": "30cd5b9e0634a9737eaeca1d0f1fabd2a7098f426bf36bc76802eee7a6d41ef0",
        "unaffected": (
            ("BIG-IP Next CNF", "All"),
            ("BIG-IP Next for Kubernetes", "All"),
            ("BIG-IP eBPF Observability (EOB)", "All"),
            ("BIG-IQ Centralized Management", "All"),
            ("F5 Insight", "All"),
            ("F5 Distributed Cloud", None),
            ("NGINX One Console", None),
            ("F5OS", "All"),
            ("F5OS-A", "All"),
            ("F5OS-C", "All"),
            ("NGINX (all products)", "All"),
            ("F5 AI Gateway", "All"),
            ("F5 API Security Local Edition", "All"),
            ("F5 AI Guardrails", "All"),
            ("F5 AI Red Team", "All"),
        ),
        "affected": tuple(
            (product, branch, versions, fixes, feature, authentication)
            for product, feature, authentication in (
                ("BIG-IP APM", "Data plane: Access profile", "unauthenticated"),
                (
                    "BIG-IP (all modules)",
                    "Control plane: The Configuration utility",
                    "authenticated",
                ),
            )
            for branch, versions, fixes in (
                ("21.x", ("21.1.0",), ("21.1.0.4",)),
                (
                    "17.x",
                    ("17.5.0 - 17.5.1", "17.1.0 - 17.1.3"),
                    (
                        "17.5.1.11",
                        "Hotfix-BIGIP-17.5.1.10.0.37.35-ENG",
                        "17.1.3.7",
                        "Hotfix-BIGIP-17.1.3.6.0.9.20-ENG",
                    ),
                ),
            )
        ),
    },
    "K000140222": {
        "evaluated_sha256": "774d457702e6430fed36705206cf8d001bc0b7fe85e58723c51618396cbd228f",
        "title": "OpenSSH server vulnerability CVE-2024-6387",
        "cves": ("CVE-2024-6387",),
        "scope_sha256": "0b7bd8bdeeb23f923ab07b78f4cfa97a11699d850efe75908bd8580860d39ece",
        "unaffected": (
            ("BIG-IP (all modules)", "All"),
            ("BIG-IQ Centralized Management", "All"),
            ("F5 Distributed Cloud (all services)", None),
            ("F5 Silverline (all services)", None),
            ("F5OS-A", "All"),
            ("F5OS-C", "All"),
            ("NGINX (all products)", "All"),
            ("Traffix SDC", "All"),
        ),
        "affected": (
            (
                "BIG-IP Next (all modules)",
                "20.x",
                ("20.1.0 - 20.2.1",),
                ("Will not fix",),
                "OpenSSH in the base operating system, f5-debug-sidecar container",
                "unauthenticated",
            ),
            (
                "BIG-IP Next Central Manager",
                "20.x",
                ("20.1.0 - 20.2.1",),
                ("Will not fix",),
                "OpenSSH in the base operating system",
                "unauthenticated",
            ),
            (
                "BIG-IP Next SPK",
                "1.x",
                ("1.7.0 - 1.9.2",),
                ("Will not fix",),
                "f5-debug-sidecar container",
                "unauthenticated",
            ),
            (
                "BIG-IP Next CNF",
                "2.x",
                ("2.2.0 - 2.4.0",),
                ("None",),
                "f5-debug-sidecar container",
                "unauthenticated",
            ),
            (
                "BIG-IP Next CNF",
                "1.x",
                ("1.1.0 - 1.4.4",),
                ("None",),
                "f5-debug-sidecar container",
                "unauthenticated",
            ),
        ),
    },
}


def reviewed_scope(text):
    if len(text) > 1_500_000:
        raise ValueError("F5 PDF text exceeds reviewed size budget")
    lines = [" ".join(line.split()) for line in text.splitlines()]
    text = " ".join(" ".join(lines).split())
    if text.count(START) != 1 or text.count(END) != 1 or lines.count("Evaluated products") != 1:
        raise ValueError("F5 PDF article boundaries changed; review required")
    before, tail = text.split(START, 1)
    critical, _ = tail.split(END, 1)
    return before, " ".join(critical.split())


def remediation(value, locator):
    availability = (
        "no_fix_planned"
        if value == "Will not fix"
        else "unknown"
        if value == "None"
        else "vendor_reports_fixed"
    )
    return dict(
        category="publisher_fix_column",
        availability=availability,
        details=value,
        source_locator=locator + " / Fixes introduced in",
    )


def advisory(raw, url, vendor):
    identity = url.removeprefix(PDF_PREFIX)
    if vendor != "f5" or identity not in PROFILES or url != PDF_PREFIX + identity:
        raise ValueError("Unreviewed F5 article PDF route")
    if not isinstance(raw, bytes) or not raw.startswith(b"%PDF") or len(raw) > 3_000_000:
        raise ValueError("Reviewed F5 source must be a PDF within 3 MB")
    profile = PROFILES[identity]
    before, critical = reviewed_scope(pdf_text(raw, layout=True))
    if before.count("Evaluated products") != 1:
        raise ValueError("F5 evaluated-product boundary changed")
    header, evaluated = before.split("Evaluated products", 1)
    header = " ".join(header.split())
    evaluated = " ".join(evaluated.split())
    if sha256(evaluated.encode()).hexdigest() != profile["evaluated_sha256"]:
        raise ValueError("F5 evaluated-product scope changed; review required")
    match = re.fullmatch(
        re.escape(identity + ": " + profile["title"] + " " + ARTICLE_PREFIX + identity)
        + r" Published Date: ([A-Z][a-z]{2} \d{1,2}, \d{4}) UTC Updated Date: ([A-Z][a-z]{2} \d{1,2}, \d{4}) UTC",
        header,
    )
    if not match or tuple(cves(profile["title"])) != profile["cves"]:
        raise ValueError("F5 article identity or publisher date metadata changed")
    if sha256(critical.encode()).hexdigest() != profile["scope_sha256"]:
        raise ValueError("F5 PDF product, impact or table-footnote scope changed; review required")
    dates = [
        datetime.strptime(value, "%b %d, %Y").replace(tzinfo=timezone.utc)
        for value in match.groups()
    ]
    if dates[1] < dates[0]:
        raise ValueError("F5 publisher date claims are contradictory")
    out = base("f5", url, identity, profile["title"], *(date.isoformat() for date in dates))
    out.update(
        advisory_url=ARTICLE_PREFIX + identity,
        cves=list(profile["cves"]),
        document_status="published",
        source_format="F5 reviewed article PDF",
    )
    scope = "bulletin_shared" if len(profile["cves"]) > 1 else "cve_specific"
    rows = [(p, b, "unaffected", (), (), None, None) for p, b in profile["unaffected"]]
    rows += [
        (p, b, "affected", v, f, feature, auth) for p, b, v, f, feature, auth in profile["affected"]
    ]
    for product, branch, status, versions, fixes, feature, auth in rows:
        locator = f"Security Advisory Status / {product}" + (f" / {branch}" if branch else "")
        for cid in profile["cves"]:
            claim = assessment(
                cid,
                product,
                status,
                locator,
                [dict(expression=value) for value in versions],
                [remediation(value, locator) for value in fixes],
                scope=scope,
            )
            claim["product_id"] = (
                re.sub(r"[^a-z0-9]+", "-", product.lower()).strip("-") + ":" + (branch or "service")
            )
            claim["product_context"] = [["product_name", product]] + (
                [["product_version", branch]] if branch else []
            )
            claim["exposure"] = [
                dict(
                    category="publisher_table_scope",
                    details="The table explicitly reports this product branch as vulnerable."
                    if status == "affected"
                    else "The table explicitly reports this product or service as not vulnerable. The evaluated-products list is not an affected-products list.",
                    source_locator=locator,
                )
            ]
            if branch:
                claim["exposure"].append(
                    dict(
                        category="publisher_lifecycle_limit",
                        details="F5 limits evaluated software versions to those before End of Technical Support. Branch All is retained as the table label; it does not certify every historical release.",
                        source_locator="Security Advisory Status / table footnote 1",
                    )
                )
            if feature:
                claim["exposure"].append(
                    dict(
                        category="publisher_prerequisite",
                        details=f"{feature}. The Impact section describes a remote {auth} attacker. No installed configuration or component inventory is inferred.",
                        source_locator=locator + " / Vulnerable component or feature; Impact",
                    )
                )
            out["assessments"].append(claim)
    out["warnings"] = [
        "Only two exact reviewed PDF routes are supported. Complete evaluated list, description, impact, status-table and footnote text is fingerprint-bound; changed scope requires review. RSS discovery and portfolio completeness are not implemented.",
        "Publisher PDF date claims have day precision and are represented at UTC midnight. They do not establish CVE-specific first disclosure, historical download availability or a before/after sequence with other article representations.",
        "The article Final label does not make affected ranges fixed. Fix-column values remain publisher statements, without automatic firmware matching, independent availability verification or download access.",
        "A row can contain several vulnerable ranges and several fix candidates. Candidates are not applied across different minor branches. Engineering hotfixes are distinguished by their literal Hotfix names; the superscript footnote 4 is not part of a version.",
        "Mitigation commands and protection for backend pool members are not normalized as appliance fixes. Background CVE references do not expand the advisory title scope.",
    ]
    return out
