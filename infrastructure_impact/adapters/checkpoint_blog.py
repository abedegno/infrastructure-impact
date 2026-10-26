"""Exact reviewed vendor blog route; product statements only, never IPS inference."""

from urllib.parse import urlsplit

from .common import HTML, assessment, base, cves

REGRESSHION_PATH = (
    "/research/cve-2024-6387-regresshion-remote-code-execution-vulnerability-seen-in-openssh/"
)


def checkpoint_blog(raw, url, vendor):
    u = urlsplit(url)
    if (
        u.scheme != "https"
        or u.hostname != "blog.checkpoint.com"
        or u.path != REGRESSHION_PATH
        or u.query
        or u.fragment
    ):
        raise ValueError("Unreviewed Check Point blog route")
    tree = HTML(raw).root
    titles = [n for n in tree.find({"h1"}) if "entry-title" in (n.attrs.get("class") or "").split()]
    articles = [
        n for n in tree.find({"article"}) if "post--single" in (n.attrs.get("class") or "").split()
    ]
    if len(titles) != 1 or len(articles) != 1 or cves(titles[0].text()) != ["CVE-2024-6387"]:
        raise ValueError("Reviewed vendor article identity/boundary changed")
    article = articles[0]
    paragraphs = [n.text() for n in article.find({"p"})]
    # Require the explicit customer section and exact product propositions. Other
    # paragraphs about attacks, IPS and third-party OpenSSH are not assessments.
    if "Check Point Customers" not in article.text():
        raise ValueError("Customer applicability section missing")
    exclusions = [
        t
        for t in paragraphs
        if t.startswith("Quantum Force & CloudGuard Network are not vulnerable.")
    ]
    affected = [
        t
        for t in paragraphs
        if t.startswith(
            "Quantum Spark does utilize a vulnerable version of OpenSSH in R81.10.x and above"
        )
    ]
    if len(exclusions) != 1 or len(affected) != 1:
        raise ValueError("Reviewed customer product statements changed")
    times = [
        n.attrs.get("datetime")
        for n in tree.find({"time"})
        if n.attrs.get("datetime") and "published" in (n.attrs.get("class") or "").split()
    ]
    out = base(
        vendor,
        url,
        "checkpoint-blog-regresshion",
        "Check Point product response to CVE-2024-6387",
        times[0] if times else None,
    )
    out.update(
        cves=["CVE-2024-6387"],
        document_status="published",
        source_format="Reviewed vendor blog customer statements",
    )
    for product in ["Quantum Force", "CloudGuard Network"]:
        out["assessments"].append(
            assessment(
                "CVE-2024-6387",
                product,
                "unaffected",
                "Check Point Customers / explicit product exclusion",
            )
        )
    for claim in out["assessments"]:
        claim["exposure"] = [
            dict(
                category="publisher_scope",
                details=exclusions[0],
                source_scope="explicit_customer_product_paragraph",
            )
        ]
    claim = assessment(
        "CVE-2024-6387",
        "Quantum Spark R81.10.x and above",
        "affected",
        "Check Point Customers / Quantum Spark",
        [{"expression": "R81.10.x and above (publisher wording)"}],
    )
    claim["exposure"] = [
        dict(
            category="publisher_scope",
            details=affected[0],
            source_scope="explicit_customer_product_paragraph",
        )
    ]
    # "Mitigates" does not establish a complete product-specific fix or build.
    out["assessments"].append(claim)
    out["warnings"] = [
        "Curated vendor blog statements supplement, but do not replace, the detailed SK article. No lower-version exclusion, exact fixed build, historical availability or complete portfolio coverage is inferred. IPS protection and CNAPP detection are not evidence that those products are affected."
    ]
    return out
